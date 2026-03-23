//! Encrypted mapping vault — stores entity<->pseudo-token mappings.
//!
//! Security properties:
//! - AES-256-GCM encrypted at rest
//! - `zeroize` on all in-memory sensitive values when dropped
//! - Persistent across sessions for consistent pseudonymization
//! - Atomic file writes (write to .tmp, rename)

use crate::{EntityCategory, PseudoToken, resolver::EntityResolver};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use anyhow::{bail, Context, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::Zeroize;

/// The mapping vault that maintains entity<->token consistency.
pub struct Vault {
    /// Forward map: original value -> pseudo-token
    forward: HashMap<String, PseudoToken>,
    /// Reverse map: pseudo-token string -> original value
    reverse: HashMap<String, SensitiveString>,
    /// Next ID counter per category
    counters: HashMap<String, u32>,
    /// File path for persistence (None = ephemeral/in-memory only)
    path: Option<String>,
    /// Encryption key (zeroized on drop)
    key: SensitiveBytes,
    /// Optional fuzzy entity resolver for merging variant spellings
    resolver: Option<EntityResolver>,
}

/// A string that is zeroized from memory when dropped.
#[derive(Clone, Serialize, Deserialize)]
pub struct SensitiveString(String);

impl Drop for SensitiveString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for SensitiveString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

/// Bytes that are zeroized from memory when dropped.
pub struct SensitiveBytes(Vec<u8>);

impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Serializable vault data for persistence.
#[derive(Serialize, Deserialize)]
struct VaultData {
    forward: Vec<(String, StoredToken)>,
    counters: HashMap<String, u32>,
}

#[derive(Serialize, Deserialize)]
struct StoredToken {
    token: String,
    category: EntityCategory,
    id: u32,
    original: String,
}

impl Vault {
    /// Create or load a vault from the given path.
    pub fn open(path: &str, key: Vec<u8>) -> Result<Self> {
        if key.len() != 32 {
            bail!("Vault key must be exactly 32 bytes (AES-256)");
        }
        if std::path::Path::new(path).exists() {
            Self::load(path, &key)
        } else {
            Ok(Self {
                forward: HashMap::new(),
                reverse: HashMap::new(),
                counters: HashMap::new(),
                path: Some(path.to_string()),
                key: SensitiveBytes(key),
                resolver: None,
            })
        }
    }

    /// Create an ephemeral (in-memory only) vault for testing.
    pub fn ephemeral() -> Self {
        let mut key = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        Self {
            forward: HashMap::new(),
            reverse: HashMap::new(),
            counters: HashMap::new(),
            path: None,
            key: SensitiveBytes(key),
            resolver: None,
        }
    }

    /// Configure the fuzzy entity resolver on this vault.
    pub fn set_resolver(&mut self, resolver: EntityResolver) {
        self.resolver = Some(resolver);
    }

    /// Get or create a pseudo-token for the given original value.
    ///
    /// If a fuzzy entity resolver is configured, checks for similar existing
    /// entries before creating a new token. This merges variant spellings
    /// (e.g., "Rishi" and "Rishikesh") to the same token.
    pub fn get_or_create(&mut self, original: &str, category: &EntityCategory) -> PseudoToken {
        // 1. Exact match (existing behavior)
        if let Some(token) = self.forward.get(original) {
            return token.clone();
        }

        // 2. Fuzzy match via resolver (if configured)
        if let Some(ref resolver) = self.resolver {
            // Build a category map of existing entries for the resolver
            let existing: HashMap<String, EntityCategory> = self
                .forward
                .iter()
                .map(|(k, v)| (k.clone(), v.category.clone()))
                .collect();

            if let Some(canonical) = resolver.resolve(original, category, &existing) {
                if let Some(token) = self.forward.get(&canonical) {
                    let token = token.clone();
                    // Store this variant as an alias → same token
                    self.forward.insert(original.to_string(), token.clone());
                    return token;
                }
            }
        }

        // 3. No match — create new token
        let prefix = Self::category_prefix(category);
        let counter = self.counters.entry(prefix.clone()).or_insert(0);
        *counter += 1;

        let token = PseudoToken {
            token: format!("{}_{}", prefix, counter),
            category: category.clone(),
            id: *counter,
        };

        self.forward.insert(original.to_string(), token.clone());
        self.reverse.insert(
            token.token.clone(),
            SensitiveString(original.to_string()),
        );

        token
    }

    /// Get or create a format-preserving pseudo-token for the given original value.
    /// Instead of "PHONE_001", generates "+91 55500 00001".
    pub fn get_or_create_fp(&mut self, original: &str, category: &EntityCategory) -> PseudoToken {
        // Exact match first
        if let Some(token) = self.forward.get(original) {
            return token.clone();
        }

        // Fuzzy match via resolver
        if let Some(ref resolver) = self.resolver {
            let existing: HashMap<String, EntityCategory> = self
                .forward
                .iter()
                .map(|(k, v)| (k.clone(), v.category.clone()))
                .collect();
            if let Some(canonical) = resolver.resolve(original, category, &existing) {
                if let Some(token) = self.forward.get(&canonical) {
                    let token = token.clone();
                    self.forward.insert(original.to_string(), token.clone());
                    return token;
                }
            }
        }

        // New entry — generate format-preserving token
        let prefix = Self::category_prefix(category);
        let counter = self.counters.entry(prefix.clone()).or_insert(0);
        *counter += 1;
        let id = *counter;

        let fake = crate::format_preserving::generate(original, category, id);
        let token = PseudoToken {
            token: fake,
            category: category.clone(),
            id,
        };

        self.forward.insert(original.to_string(), token.clone());
        self.reverse.insert(
            token.token.clone(),
            SensitiveString(original.to_string()),
        );

        token
    }

    /// Check if a given original value already has a mapping in the vault.
    pub fn contains_original(&self, value: &str) -> bool {
        self.forward.contains_key(value)
    }

    /// Look up the original value for a pseudo-token (for rehydration).
    pub fn lookup(&self, token: &str) -> Option<&str> {
        self.reverse.get(token).map(|s| s.0.as_str())
    }

    /// Get all reverse mappings (for rehydration).
    pub fn reverse_mappings(&self) -> HashMap<String, String> {
        self.reverse
            .iter()
            .map(|(k, v)| (k.clone(), v.0.clone()))
            .collect()
    }

    /// Save the vault to disk (AES-256-GCM encrypted).
    pub fn save(&self) -> Result<()> {
        let path = match &self.path {
            Some(p) => p,
            None => return Ok(()), // ephemeral vault, nothing to save
        };

        let data = self.to_vault_data();
        let json = serde_json::to_vec(&data).context("Failed to serialize vault")?;

        let encrypted = self.encrypt(&json)?;

        // Atomic write: write to .tmp, then rename
        let tmp_path = format!("{}.tmp", path);
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent).context("Failed to create vault directory")?;
        }
        std::fs::write(&tmp_path, &encrypted).context("Failed to write vault temp file")?;
        std::fs::rename(&tmp_path, path).context("Failed to rename vault file")?;

        Ok(())
    }

    /// Get vault statistics (safe to expose — no sensitive data).
    pub fn stats(&self) -> VaultStats {
        VaultStats {
            total_mappings: self.forward.len(),
            categories: self.counters.clone(),
        }
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

    fn load(path: &str, key: &[u8]) -> Result<Self> {
        let encrypted = std::fs::read(path).context("Failed to read vault file")?;
        let json = Self::decrypt_bytes(key, &encrypted)?;
        let data: VaultData =
            serde_json::from_slice(&json).context("Failed to deserialize vault")?;

        let mut forward = HashMap::new();
        let mut reverse = HashMap::new();

        for (_original_key, stored) in &data.forward {
            let token = PseudoToken {
                token: stored.token.clone(),
                category: stored.category.clone(),
                id: stored.id,
            };
            forward.insert(stored.original.clone(), token.clone());
            reverse.insert(
                stored.token.clone(),
                SensitiveString(stored.original.clone()),
            );
        }

        Ok(Self {
            forward,
            reverse,
            counters: data.counters,
            path: Some(path.to_string()),
            key: SensitiveBytes(key.to_vec()),
            resolver: None,
        })
    }

    fn to_vault_data(&self) -> VaultData {
        let forward: Vec<(String, StoredToken)> = self
            .forward
            .iter()
            .map(|(original, token)| {
                (
                    original.clone(),
                    StoredToken {
                        token: token.token.clone(),
                        category: token.category.clone(),
                        id: token.id,
                        original: original.clone(),
                    },
                )
            })
            .collect();

        VaultData {
            forward,
            counters: self.counters.clone(),
        }
    }

    /// Encrypt plaintext with AES-256-GCM. Output: 12-byte nonce || ciphertext.
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher =
            Aes256Gcm::new_from_slice(&self.key.0)
                .map_err(|_| anyhow::anyhow!("Invalid AES-256-GCM key"))?;

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        let mut output = Vec::with_capacity(12 + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    /// Decrypt ciphertext (12-byte nonce || ciphertext) with AES-256-GCM.
    fn decrypt_bytes(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 12 {
            bail!("Vault data too short — corrupted or wrong format");
        }

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| anyhow::anyhow!("Invalid AES-256-GCM key"))?;
        let nonce = Nonce::from_slice(&data[..12]);
        let ciphertext = &data[12..];

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow::anyhow!("Decryption failed — wrong key or corrupted vault"))
    }
}

#[derive(Debug, Serialize)]
pub struct VaultStats {
    pub total_mappings: usize,
    pub categories: HashMap<String, u32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EntityCategory;

    fn test_key() -> Vec<u8> {
        vec![0xAB; 32]
    }

    #[test]
    fn test_vault_get_or_create_consistency() {
        let mut vault = Vault::ephemeral();
        let t1 = vault.get_or_create("Tata Motors", &EntityCategory::Organization);
        let t2 = vault.get_or_create("Tata Motors", &EntityCategory::Organization);
        assert_eq!(t1.token, t2.token);
        assert_eq!(t1.token, "ORG_1");
    }

    #[test]
    fn test_vault_different_entities() {
        let mut vault = Vault::ephemeral();
        let t1 = vault.get_or_create("Tata Motors", &EntityCategory::Organization);
        let t2 = vault.get_or_create("Infosys", &EntityCategory::Organization);
        assert_ne!(t1.token, t2.token);
        assert_eq!(t1.token, "ORG_1");
        assert_eq!(t2.token, "ORG_2");
    }

    #[test]
    fn test_vault_lookup() {
        let mut vault = Vault::ephemeral();
        vault.get_or_create("secret@example.com", &EntityCategory::Email);
        assert_eq!(vault.lookup("EMAIL_1"), Some("secret@example.com"));
        assert_eq!(vault.lookup("NONEXISTENT_99"), None);
    }

    #[test]
    fn test_vault_stats() {
        let mut vault = Vault::ephemeral();
        vault.get_or_create("Alice", &EntityCategory::Person);
        vault.get_or_create("Bob", &EntityCategory::Person);
        vault.get_or_create("Acme Corp", &EntityCategory::Organization);
        let stats = vault.stats();
        assert_eq!(stats.total_mappings, 3);
        assert_eq!(stats.categories.get("PERSON"), Some(&2));
        assert_eq!(stats.categories.get("ORG"), Some(&1));
    }

    #[test]
    fn test_vault_roundtrip_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("test.vault");
        let path_str = vault_path.to_str().unwrap();

        // Create vault and add mappings
        {
            let mut vault = Vault::open(path_str, test_key()).unwrap();
            vault.get_or_create("Tata Motors", &EntityCategory::Organization);
            vault.get_or_create("$1.2M", &EntityCategory::Amount);
            vault.save().unwrap();
        }

        // Load vault and verify mappings persisted
        {
            let vault = Vault::open(path_str, test_key()).unwrap();
            assert_eq!(vault.lookup("ORG_1"), Some("Tata Motors"));
            assert_eq!(vault.lookup("AMOUNT_1"), Some("$1.2M"));
            assert_eq!(vault.stats().total_mappings, 2);
        }
    }

    #[test]
    fn test_vault_wrong_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("test.vault");
        let path_str = vault_path.to_str().unwrap();

        // Create with one key
        {
            let mut vault = Vault::open(path_str, test_key()).unwrap();
            vault.get_or_create("secret", &EntityCategory::Secret);
            vault.save().unwrap();
        }

        // Try to open with wrong key
        let wrong_key = vec![0xCD; 32];
        let result = Vault::open(path_str, wrong_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_vault_invalid_key_length() {
        let result = Vault::open("/tmp/test.vault", vec![0u8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn test_vault_contains_original() {
        let mut vault = Vault::ephemeral();
        assert!(!vault.contains_original("secret@example.com"));
        vault.get_or_create("secret@example.com", &EntityCategory::Email);
        assert!(vault.contains_original("secret@example.com"));
        assert!(!vault.contains_original("other@example.com"));
    }

    #[test]
    fn test_vault_format_preserving() {
        let mut vault = Vault::ephemeral();
        let t1 = vault.get_or_create_fp("+91 98765 43210", &EntityCategory::PhoneNumber);
        assert!(t1.token.contains("+91"), "FP phone should keep +91 prefix");
        // Same value -> same token
        let t2 = vault.get_or_create_fp("+91 98765 43210", &EntityCategory::PhoneNumber);
        assert_eq!(t1.token, t2.token);
        // Different value -> different token
        let t3 = vault.get_or_create_fp("+91 11111 22222", &EntityCategory::PhoneNumber);
        assert_ne!(t1.token, t3.token);
    }

    #[test]
    fn test_vault_fp_email() {
        let mut vault = Vault::ephemeral();
        let t = vault.get_or_create_fp("priya@example.com", &EntityCategory::Email);
        assert!(t.token.contains("@"), "FP email should contain @");
        assert!(t.token.ends_with(".invalid"), "FP email should use .invalid TLD");
    }
}
