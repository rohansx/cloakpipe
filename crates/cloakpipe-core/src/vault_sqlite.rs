//! SQLite-backed vault — persistent entity<->pseudo-token mappings.
//!
//! Replaces the file-based vault with SQLite for:
//! - Better concurrent access and crash safety (WAL mode)
//! - Per-row AES-256-GCM encryption of sensitive values
//! - Multi-user support via user_id scoping
//! - Efficient lookups without loading entire vault into memory

use crate::{EntityCategory, PseudoToken};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use anyhow::{bail, Context, Result};
use rand::RngCore;
use rusqlite::{params, Connection};
use std::collections::HashMap;
use zeroize::Zeroize;

/// SQLite-backed vault with per-value encryption.
pub struct SqliteVault {
    conn: Connection,
    cipher: Aes256Gcm,
    /// In-memory caches for hot path performance
    forward_cache: HashMap<String, PseudoToken>,
    reverse_cache: HashMap<String, String>,
}

/// Bytes that are zeroized from memory when dropped.
struct SensitiveBytes(Vec<u8>);

impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl SqliteVault {
    /// Open or create a SQLite vault at the given path.
    pub fn open(path: &str, key: Vec<u8>) -> Result<Self> {
        if key.len() != 32 {
            bail!("Vault key must be exactly 32 bytes (AES-256)");
        }

        let conn = Connection::open(path)
            .with_context(|| format!("Failed to open vault database: {}", path))?;

        // WAL mode for better concurrent read performance
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;

        Self::init_schema(&conn)?;

        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| anyhow::anyhow!("Invalid AES-256-GCM key"))?;

        let _key_guard = SensitiveBytes(key);

        let mut vault = Self {
            conn,
            cipher,
            forward_cache: HashMap::new(),
            reverse_cache: HashMap::new(),
        };

        vault.load_cache()?;
        Ok(vault)
    }

    /// Create an ephemeral (in-memory) vault for testing.
    pub fn ephemeral() -> Self {
        let mut key = vec![0u8; 32];
        OsRng.fill_bytes(&mut key);

        let conn = Connection::open_in_memory().expect("Failed to open in-memory SQLite");
        Self::init_schema(&conn).expect("Failed to init schema");

        let cipher = Aes256Gcm::new_from_slice(&key)
            .expect("Invalid key");

        let _key_guard = SensitiveBytes(key);

        Self {
            conn,
            cipher,
            forward_cache: HashMap::new(),
            reverse_cache: HashMap::new(),
        }
    }

    fn init_schema(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS mappings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_enc BLOB NOT NULL,
                token TEXT NOT NULL UNIQUE,
                category TEXT NOT NULL,
                token_id INTEGER NOT NULL,
                user_id TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_mappings_token ON mappings(token);
            CREATE INDEX IF NOT EXISTS idx_mappings_user ON mappings(user_id);

            CREATE TABLE IF NOT EXISTS counters (
                category TEXT NOT NULL,
                user_id TEXT,
                counter INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (category, user_id)
            );"
        ).context("Failed to initialize vault schema")?;
        Ok(())
    }

    /// Load all mappings into the in-memory cache.
    fn load_cache(&mut self) -> Result<()> {
        let mut stmt = self.conn.prepare(
            "SELECT original_enc, token, category, token_id FROM mappings"
        )?;

        let rows = stmt.query_map([], |row| {
            let enc: Vec<u8> = row.get(0)?;
            let token: String = row.get(1)?;
            let category: String = row.get(2)?;
            let token_id: u32 = row.get(3)?;
            Ok((enc, token, category, token_id))
        })?;

        for row in rows {
            let (enc, token, category_str, token_id) = row?;
            let original = self.decrypt_value(&enc)
                .unwrap_or_else(|_| "[decrypt_failed]".to_string());
            let category = Self::parse_category(&category_str);

            let pseudo = PseudoToken {
                token: token.clone(),
                category,
                id: token_id,
            };

            self.forward_cache.insert(original.clone(), pseudo);
            self.reverse_cache.insert(token, original);
        }

        Ok(())
    }

    /// Get or create a pseudo-token for the given original value.
    pub fn get_or_create(&mut self, original: &str, category: &EntityCategory) -> PseudoToken {
        self.get_or_create_for_user(original, category, None)
    }

    /// Get or create a pseudo-token scoped to a user.
    pub fn get_or_create_for_user(
        &mut self,
        original: &str,
        category: &EntityCategory,
        user_id: Option<&str>,
    ) -> PseudoToken {
        // Check cache first
        if let Some(token) = self.forward_cache.get(original) {
            return token.clone();
        }

        let prefix = Self::category_prefix(category);
        let user_key = user_id.unwrap_or("");

        // Increment counter
        self.conn.execute(
            "INSERT INTO counters (category, user_id, counter) VALUES (?1, ?2, 1)
             ON CONFLICT(category, user_id) DO UPDATE SET counter = counter + 1",
            params![prefix, user_key],
        ).expect("Failed to update counter");

        let counter: u32 = self.conn.query_row(
            "SELECT counter FROM counters WHERE category = ?1 AND user_id = ?2",
            params![prefix, user_key],
            |row| row.get(0),
        ).expect("Failed to read counter");

        // Include user_id in token to avoid collisions across users
        let token_str = if user_key.is_empty() {
            format!("{}_{}", prefix, counter)
        } else {
            format!("{}_{}_{}", prefix, user_key, counter)
        };

        let token = PseudoToken {
            token: token_str,
            category: category.clone(),
            id: counter,
        };

        // Encrypt and store
        let encrypted = self.encrypt_value(original)
            .expect("Failed to encrypt value");

        self.conn.execute(
            "INSERT INTO mappings (original_enc, token, category, token_id, user_id) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![encrypted, token.token, prefix, counter, user_id],
        ).expect("Failed to insert mapping");

        // Update caches
        self.forward_cache.insert(original.to_string(), token.clone());
        self.reverse_cache.insert(token.token.clone(), original.to_string());

        token
    }

    /// Look up the original value for a pseudo-token.
    pub fn lookup(&self, token: &str) -> Option<&str> {
        self.reverse_cache.get(token).map(|s| s.as_str())
    }

    /// Get all reverse mappings.
    pub fn reverse_mappings(&self) -> HashMap<String, String> {
        self.reverse_cache.clone()
    }

    /// Save is a no-op for SQLite (writes are immediate).
    pub fn save(&self) -> Result<()> {
        Ok(())
    }

    /// Get vault statistics.
    pub fn stats(&self) -> VaultStats {
        let mut categories = HashMap::new();

        let mut stmt = self.conn.prepare(
            "SELECT category, counter FROM counters WHERE user_id = ''"
        ).expect("Failed to prepare stats query");

        let rows = stmt.query_map([], |row| {
            let cat: String = row.get(0)?;
            let count: u32 = row.get(1)?;
            Ok((cat, count))
        }).expect("Failed to query stats");

        for (cat, count) in rows.flatten() {
            categories.insert(cat, count);
        }

        VaultStats {
            total_mappings: self.forward_cache.len(),
            categories,
        }
    }

    /// Get mappings for a specific user.
    pub fn user_stats(&self, user_id: &str) -> Result<VaultStats> {
        let count: usize = self.conn.query_row(
            "SELECT COUNT(*) FROM mappings WHERE user_id = ?1",
            params![user_id],
            |row| row.get(0),
        )?;

        let mut categories = HashMap::new();
        let mut stmt = self.conn.prepare(
            "SELECT category, counter FROM counters WHERE user_id = ?1"
        )?;

        let rows = stmt.query_map(params![user_id], |row| {
            let cat: String = row.get(0)?;
            let cnt: u32 = row.get(1)?;
            Ok((cat, cnt))
        })?;

        for (cat, cnt) in rows.flatten() {
            categories.insert(cat, cnt);
        }

        Ok(VaultStats {
            total_mappings: count,
            categories,
        })
    }

    fn encrypt_value(&self, plaintext: &str) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self.cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        let mut output = Vec::with_capacity(12 + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    fn decrypt_value(&self, data: &[u8]) -> Result<String> {
        if data.len() < 12 {
            bail!("Encrypted data too short");
        }
        let nonce = Nonce::from_slice(&data[..12]);
        let ciphertext = &data[12..];

        let plaintext = self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow::anyhow!("Decryption failed — wrong key or corrupted data"))?;

        String::from_utf8(plaintext).context("Decrypted value is not valid UTF-8")
    }

    fn category_prefix(category: &EntityCategory) -> String {
        match category {
            EntityCategory::Person => "PERSON".into(),
            EntityCategory::Organization => "ORG".into(),
            EntityCategory::Location => "LOC".into(),
            EntityCategory::Amount => "AMOUNT".into(),
            EntityCategory::Percentage => "PCT".into(),
            EntityCategory::Date => "DATE".into(),
            EntityCategory::Email => "EMAIL".into(),
            EntityCategory::PhoneNumber => "PHONE".into(),
            EntityCategory::IpAddress => "IP".into(),
            EntityCategory::Secret => "SECRET".into(),
            EntityCategory::Url => "URL".into(),
            EntityCategory::Project => "PROJECT".into(),
            EntityCategory::Business => "BIZ".into(),
            EntityCategory::Infra => "INFRA".into(),
            EntityCategory::Custom(name) => name.to_uppercase(),
        }
    }

    fn parse_category(s: &str) -> EntityCategory {
        match s {
            "PERSON" => EntityCategory::Person,
            "ORG" => EntityCategory::Organization,
            "LOC" => EntityCategory::Location,
            "AMOUNT" => EntityCategory::Amount,
            "PCT" => EntityCategory::Percentage,
            "DATE" => EntityCategory::Date,
            "EMAIL" => EntityCategory::Email,
            "PHONE" => EntityCategory::PhoneNumber,
            "IP" => EntityCategory::IpAddress,
            "SECRET" => EntityCategory::Secret,
            "URL" => EntityCategory::Url,
            "PROJECT" => EntityCategory::Project,
            "BIZ" => EntityCategory::Business,
            "INFRA" => EntityCategory::Infra,
            other => EntityCategory::Custom(other.to_string()),
        }
    }
}

#[derive(Debug, serde::Serialize)]
pub struct VaultStats {
    pub total_mappings: usize,
    pub categories: HashMap<String, u32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EntityCategory;

    #[test]
    fn test_sqlite_vault_get_or_create() {
        let mut vault = SqliteVault::ephemeral();
        let t1 = vault.get_or_create("Tata Motors", &EntityCategory::Organization);
        let t2 = vault.get_or_create("Tata Motors", &EntityCategory::Organization);
        assert_eq!(t1.token, t2.token);
        assert_eq!(t1.token, "ORG_1");
    }

    #[test]
    fn test_sqlite_vault_different_entities() {
        let mut vault = SqliteVault::ephemeral();
        let t1 = vault.get_or_create("Tata Motors", &EntityCategory::Organization);
        let t2 = vault.get_or_create("Infosys", &EntityCategory::Organization);
        assert_ne!(t1.token, t2.token);
        assert_eq!(t1.token, "ORG_1");
        assert_eq!(t2.token, "ORG_2");
    }

    #[test]
    fn test_sqlite_vault_lookup() {
        let mut vault = SqliteVault::ephemeral();
        vault.get_or_create("secret@example.com", &EntityCategory::Email);
        assert_eq!(vault.lookup("EMAIL_1"), Some("secret@example.com"));
        assert_eq!(vault.lookup("NONEXISTENT_99"), None);
    }

    #[test]
    fn test_sqlite_vault_stats() {
        let mut vault = SqliteVault::ephemeral();
        vault.get_or_create("Alice", &EntityCategory::Person);
        vault.get_or_create("Bob", &EntityCategory::Person);
        vault.get_or_create("Acme Corp", &EntityCategory::Organization);
        let stats = vault.stats();
        assert_eq!(stats.total_mappings, 3);
        assert_eq!(stats.categories.get("PERSON"), Some(&2));
        assert_eq!(stats.categories.get("ORG"), Some(&1));
    }

    #[test]
    fn test_sqlite_vault_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("test.db");
        let path_str = vault_path.to_str().unwrap();
        let key = vec![0xAB; 32];

        // Create and populate
        {
            let mut vault = SqliteVault::open(path_str, key.clone()).unwrap();
            vault.get_or_create("Tata Motors", &EntityCategory::Organization);
            vault.get_or_create("$1.2M", &EntityCategory::Amount);
        }

        // Reopen and verify
        {
            let vault = SqliteVault::open(path_str, key).unwrap();
            assert_eq!(vault.lookup("ORG_1"), Some("Tata Motors"));
            assert_eq!(vault.lookup("AMOUNT_1"), Some("$1.2M"));
            assert_eq!(vault.stats().total_mappings, 2);
        }
    }

    #[test]
    fn test_sqlite_vault_wrong_key() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("test.db");
        let path_str = vault_path.to_str().unwrap();

        {
            let mut vault = SqliteVault::open(path_str, vec![0xAB; 32]).unwrap();
            vault.get_or_create("secret", &EntityCategory::Secret);
        }

        // Reopen with wrong key — decryption should fail but not crash
        let vault = SqliteVault::open(path_str, vec![0xCD; 32]).unwrap();
        // The decrypted value will be "[decrypt_failed]"
        assert_ne!(vault.lookup("SECRET_1"), Some("secret"));
    }

    #[test]
    fn test_sqlite_vault_multi_user() {
        let mut vault = SqliteVault::ephemeral();
        let t1 = vault.get_or_create_for_user("Alice", &EntityCategory::Person, Some("user-1"));
        let t2 = vault.get_or_create_for_user("Bob", &EntityCategory::Person, Some("user-2"));
        assert_eq!(t1.token, "PERSON_user-1_1");
        assert_eq!(t2.token, "PERSON_user-2_1");
        // Each user gets their own counter
        assert_eq!(t1.id, 1);
        assert_eq!(t2.id, 1);
    }
}
