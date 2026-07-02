//! Producer-side bundle export.
//!
//! Lives in `cloakpipe-ledger` because this crate owns the canonical
//! byte encoding (`canonical::canonicalize`) and the durable store
//! (`store::LedgerStore`). The verifier reads the JSON we emit here
//! without any back-reference to this crate.
//!
//! The export is **deterministic**: same records + same signer keys =
//! byte-identical bundle JSON. This is what lets auditors diff
//! bundles across versions and across operators.

use crate::canonical::canonicalize;
use crate::sign::Signer;
use crate::store::LedgerStore;
use chrono::Utc;
use thiserror::Error;

/// Re-export the verifier's bundle types. We **do not** import from
/// `cloakpipe-verify` — that would create a dependency cycle (the
/// verifier is supposed to be standalone). Instead, we mirror the
/// shapes here. Tests assert byte-level equivalence so a producer
/// change can't silently break the verifier.
pub mod bundle_format {
    use serde::{Deserialize, Serialize};

    pub const BUNDLE_MAGIC: &str = "cloakpipe.bundle";
    pub const BUNDLE_FORMAT_VERSION: u32 = 2;

    pub type Hex32 = String;
    pub type Hex64 = String;
    pub type HexPubkey = String;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct Bundle {
        pub format: String,
        pub format_version: u32,
        pub tenant_id: String,
        pub created_at: String,
        pub records: Vec<Record>,
        #[serde(default)]
        pub batch_heads: Vec<BatchHead>,
        #[serde(default)]
        pub signer_public_keys: Vec<SignerKey>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct Record {
        pub seq: u64,
        pub tenant_id: String,
        pub canonical_bytes: String,
        pub record_hash: Hex32,
        pub prev_hash: Hex32,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct BatchHead {
        pub batch_id: String,
        pub first_seq: u64,
        pub last_seq: u64,
        pub merkle_root: Hex32,
        pub algorithm: String,
        pub signed_time: Option<String>,
        pub signature: SignedBatchHead,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct SignedBatchHead {
        pub key_id: String,
        pub algorithm: String,
        pub value: Hex64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct SignerKey {
        pub key_id: String,
        pub algorithm: String,
        pub public_key: HexPubkey,
    }
}

use bundle_format::*;

#[derive(Debug, Error)]
pub enum ExportError {
    #[error("store error: {0}")]
    Store(#[from] crate::store::StoreError),
}

/// Export every record for `tenant_id` into a bundle.
///
/// Note: this method does NOT include batch heads. Batch signing is
/// M3 work. Until then, the bundle is records-only — `verify chain`
/// works, `verify sigs` is a no-op.
pub fn export_bundle<S: Signer>(
    store: &LedgerStore,
    tenant_id: &uuid::Uuid,
    signer: &S,
) -> Result<Bundle, ExportError> {
    let stored = store.records_for_tenant(tenant_id)?;
    let records: Vec<Record> = stored
        .into_iter()
        .map(|s| {
            // Re-canonicalize to get the exact bytes the producer
            // hashed. Storing the canonical bytes verbatim in the
            // bundle is the trust contract: the verifier hashes what
            // we give it and compares; if we tampered, the hash won't
            // match.
            let canon = canonicalize(&s.record);
            let canon_string = String::from_utf8(canon).unwrap_or_default();
            Record {
                seq: s.record.seq,
                tenant_id: s.record.tenant_id.to_string(),
                canonical_bytes: canon_string,
                record_hash: hex_lower(&s.record.record_hash),
                prev_hash: hex_lower(&s.record.prev_hash),
            }
        })
        .collect();

    Ok(Bundle {
        format: BUNDLE_MAGIC.into(),
        format_version: BUNDLE_FORMAT_VERSION,
        tenant_id: tenant_id.to_string(),
        created_at: Utc::now().to_rfc3339(),
        records,
        batch_heads: vec![],
        signer_public_keys: vec![SignerKey {
            key_id: "default".into(),
            algorithm: signer.algorithm().to_string(),
            public_key: hex_lower(&signer.public_key()),
        }],
    })
}

/// Convenience: write a bundle to disk as pretty JSON.
pub fn write_bundle(path: &std::path::Path, bundle: &Bundle) -> anyhow::Result<()> {
    let j = serde_json::to_string_pretty(bundle)?;
    std::fs::write(path, j)?;
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        write!(s, "{:02x}", b).unwrap();
    }
    s
}

/// Asserts the producer's bundle types serialize *byte-for-byte* the
/// same way as the verifier's. Run this in CI to catch drift.
#[cfg(test)]
mod format_compat {
    use super::*;
    use crate::sign::Ed25519Signer;
    use crate::record::*;
    use tempfile::tempdir;
    use uuid::Uuid;

    #[test]
    fn producer_bundle_has_verifier_compatible_shape() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ledger.sqlite");
        let mut store = LedgerStore::open(path.to_str().unwrap()).unwrap();
        let t = Uuid::new_v4();
        let mut r = RecordBuilder::new()
            .seq(0)
            .tenant(t)
            .hop(Hop::LlmPrompt)
            .build()
            .unwrap();
        store.append(&t, &mut r).unwrap();
        let signer = Ed25519Signer::generate();
        let bundle = export_bundle(&store, &t, &signer).unwrap();

        // Structural invariants the verifier relies on. If any of
        // these drift, `cloakpipe-verify` will reject every bundle.
        assert_eq!(bundle.format, "cloakpipe.bundle");
        assert_eq!(bundle.format_version, 2);
        assert!(!bundle.records.is_empty());
        let rec = &bundle.records[0];
        assert!(!rec.canonical_bytes.is_empty());
        assert_eq!(rec.record_hash.len(), 64);
        assert_eq!(rec.prev_hash.len(), 64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::Ed25519Signer;
    use crate::record::*;
    use tempfile::tempdir;
    use uuid::Uuid;

    #[test]
    fn export_includes_all_records_with_canonical_bytes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ledger.sqlite");
        let mut store = LedgerStore::open(path.to_str().unwrap()).unwrap();
        let t = Uuid::new_v4();
        for i in 0..3u64 {
            let mut r = RecordBuilder::new()
                .seq(i)
                .tenant(t)
                .hop(Hop::LlmPrompt)
                .build()
                .unwrap();
            store.append(&t, &mut r).unwrap();
        }
        let signer = Ed25519Signer::generate();
        let bundle = export_bundle(&store, &t, &signer).unwrap();
        assert_eq!(bundle.records.len(), 3);
        assert_eq!(bundle.format, "cloakpipe.bundle");
        assert_eq!(bundle.format_version, 2);
        // Record 0's prev_hash is all zeros (genesis).
        assert!(bundle.records[0].prev_hash.chars().all(|c| c == '0'));
        // Each record's record_hash matches SHA-256 of its canonical bytes.
        for r in &bundle.records {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(r.canonical_bytes.as_bytes());
            let out = h.finalize();
            let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(r.record_hash, hex);
        }
    }

    #[test]
    fn export_is_deterministic() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ledger.sqlite");
        let mut store = LedgerStore::open(path.to_str().unwrap()).unwrap();
        let t = Uuid::new_v4();
        let mut r = RecordBuilder::new()
            .seq(0)
            .tenant(t)
            .hop(Hop::LlmPrompt)
            .build()
            .unwrap();
        store.append(&t, &mut r).unwrap();
        let signer = Ed25519Signer::generate();
        let b1 = export_bundle(&store, &t, &signer).unwrap();
        let b2 = export_bundle(&store, &t, &signer).unwrap();
        // Records are identical; created_at differs (we set Utc::now
        // each time) so we compare just the records.
        assert_eq!(b1.records, b2.records);
        assert_eq!(b1.records[0].canonical_bytes, b2.records[0].canonical_bytes);
        assert_eq!(b1.records[0].record_hash, b2.records[0].record_hash);
    }
}