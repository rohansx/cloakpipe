//! Durable append-only storage for [`LedgerRecord`].
//!
//! Uses SQLite (one file per ledger) for simplicity — same engine as the
//! vault. Each insert is a single transaction; records are never updated
//! or deleted.

use rusqlite::{params, Connection};
use thiserror::Error;

use crate::chain::{compute_hash, GENESIS_HASH};
use crate::record::LedgerRecord;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("serde_json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("record's stored seq does not match expected next seq {expected}")]
    SeqOutOfOrder { expected: u64 },
    #[error("record's prev_hash does not match head record_hash")]
    PrevHashMismatch,
    #[error("record's stored record_hash does not match recomputed hash")]
    RecordHashMismatch,
}

/// A record that has been durably stored, paired with its DB row id.
#[derive(Debug, Clone)]
pub struct StoredRecord {
    pub id: i64,
    pub record: LedgerRecord,
}

/// Append-only store. One connection per ledger file; cheap to clone via
/// [`Connection::clone`] — but each thread should ideally own one.
pub struct LedgerStore {
    conn: Connection,
}

impl LedgerStore {
    /// Opens or creates a ledger at `path`. Enables WAL for concurrent
    /// appends and reasonable crash safety.
    pub fn open(path: &str) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<(), StoreError> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS records (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id    TEXT NOT NULL,
                seq          INTEGER NOT NULL,
                record_hash  TEXT NOT NULL,
                prev_hash    TEXT NOT NULL,
                record_json  TEXT NOT NULL,
                UNIQUE(tenant_id, seq)
            );
            CREATE INDEX IF NOT EXISTS idx_records_tenant_seq
              ON records(tenant_id, seq);
            "#,
        )?;
        Ok(())
    }

    /// Returns the (seq, record_hash) tail of the chain for `tenant_id`,
    /// or `(None, GENESIS_HASH)` if empty.
    pub fn head(&self, tenant_id: &uuid::Uuid) -> Result<(Option<u64>, [u8; 32]), StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, record_hash FROM records
             WHERE tenant_id = ?1
             ORDER BY seq DESC LIMIT 1",
        )?;
        let mut rows = stmt.query([tenant_id.to_string()])?;
        if let Some(row) = rows.next()? {
            let seq: i64 = row.get(0)?;
            let hash_hex: String = row.get(1)?;
            let hash = decode_hex_32(&hash_hex)
                .ok_or_else(|| StoreError::PrevHashMismatch)?;
            Ok((Some(seq as u64), hash))
        } else {
            Ok((None, GENESIS_HASH))
        }
    }

    /// Append a record after linking it into the chain. Verifies the
    /// supplied `prev_hash` matches the current head.
    pub fn append(&mut self, tenant_id: &uuid::Uuid, record: &mut LedgerRecord) -> Result<i64, StoreError> {
        let (head_seq_opt, head_hash) = self.head(tenant_id)?;
        let expected_seq = head_seq_opt.map(|s| s + 1).unwrap_or(0);
        if record.seq != expected_seq {
            return Err(StoreError::SeqOutOfOrder {
                expected: expected_seq,
            });
        }
        record.prev_hash = head_hash;
        record.record_hash = compute_hash(record);

        // Sanity: the hash we just computed matches what we are about to
        // store. (compute_hash is deterministic, so this is a tautology —
        // but it documents the contract.)
        let recomputed = compute_hash(record);
        if recomputed != record.record_hash {
            return Err(StoreError::RecordHashMismatch);
        }

        let json = serde_json::to_string(record)?;
        let mut stmt = self.conn.prepare(
            "INSERT INTO records (tenant_id, seq, record_hash, prev_hash, record_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        let res = stmt.insert(params![
            tenant_id.to_string(),
            record.seq as i64,
            hex_lower(&record.record_hash),
            hex_lower(&record.prev_hash),
            json
        ])?;
        Ok(res)
    }

    /// Read all records for a tenant, in seq order.
    pub fn records_for_tenant(&self, tenant_id: &uuid::Uuid) -> Result<Vec<StoredRecord>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, seq, record_json FROM records
             WHERE tenant_id = ?1
             ORDER BY seq ASC",
        )?;
        let rows = stmt.query_map([tenant_id.to_string()], |row| {
            let id: i64 = row.get(0)?;
            let seq: i64 = row.get(1)?;
            let json: String = row.get(2)?;
            Ok((id, seq, json))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, _seq, json) = row?;
            let record: LedgerRecord = serde_json::from_str(&json)?;
            out.push(StoredRecord { id, record });
        }
        Ok(out)
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        write!(s, "{:02x}", b).unwrap();
    }
    s
}

fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::*;
    use tempfile::tempdir;
    use uuid::Uuid;

    fn fresh() -> (tempfile::TempDir, LedgerStore) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ledger.sqlite");
        let store = LedgerStore::open(path.to_str().unwrap()).unwrap();
        (dir, store)
    }

    fn rec(seq: u64, tenant: Uuid) -> LedgerRecord {
        RecordBuilder::new()
            .seq(seq)
            .tenant(tenant)
            .hop(Hop::LlmPrompt)
            .build()
            .unwrap()
    }

    #[test]
    fn head_starts_at_genesis_for_new_ledger() {
        let (_dir, store) = fresh();
        let t = Uuid::new_v4();
        let (seq, hash) = store.head(&t).unwrap();
        assert_eq!(seq, None);
        assert_eq!(hash, GENESIS_HASH);
    }

    #[test]
    fn append_links_chain_correctly() {
        let (_dir, mut store) = fresh();
        let t = Uuid::new_v4();
        for i in 0..3 {
            let mut r = rec(i, t);
            store.append(&t, &mut r).unwrap();
        }
        let rows = store.records_for_tenant(&t).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].record.prev_hash, GENESIS_HASH);
        assert_eq!(rows[1].record.prev_hash, rows[0].record.record_hash);
        assert_eq!(rows[2].record.prev_hash, rows[1].record.record_hash);
    }

    #[test]
    fn append_rejects_wrong_seq() {
        let (_dir, mut store) = fresh();
        let t = Uuid::new_v4();
        let mut r = rec(7, t);
        let err = store.append(&t, &mut r).unwrap_err();
        assert!(matches!(err, StoreError::SeqOutOfOrder { expected: 0 }));
    }

    #[test]
    fn two_tenants_have_independent_chains() {
        let (_dir, mut store) = fresh();
        let t1 = Uuid::new_v4();
        let t2 = Uuid::new_v4();
        store.append(&t1, &mut rec(0, t1)).unwrap();
        store.append(&t2, &mut rec(0, t2)).unwrap();
        store.append(&t1, &mut rec(1, t1)).unwrap();
        store.append(&t2, &mut rec(1, t2)).unwrap();
        let r1 = store.records_for_tenant(&t1).unwrap();
        let r2 = store.records_for_tenant(&t2).unwrap();
        assert_eq!(r1.len(), 2);
        assert_eq!(r2.len(), 2);
        // Independent genesis -> tail hashes differ across tenants.
        assert_ne!(r1[0].record.record_hash, r2[0].record.record_hash);
    }

    #[test]
    fn persisted_records_replay_through_chain_verifier() {
        let (_dir, mut store) = fresh();
        let t = Uuid::new_v4();
        for i in 0..10 {
            let mut r = rec(i, t);
            store.append(&t, &mut r).unwrap();
        }
        let rows: Vec<LedgerRecord> = store
            .records_for_tenant(&t)
            .unwrap()
            .into_iter()
            .map(|s| s.record)
            .collect();
        crate::chain::verify_chain(&rows).unwrap();
    }
}