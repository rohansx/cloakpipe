//! Configuration types parsed from cloakpipe.toml.

use crate::resolver::ResolverConfig;
use crate::session::SessionConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CloakPipeConfig {
    pub proxy: ProxyConfig,
    pub vault: VaultConfig,
    /// Industry profile for smart detection defaults (general, legal, healthcare, fintech).
    #[serde(default)]
    pub profile: Option<String>,
    pub detection: DetectionConfig,
    #[serde(default)]
    pub tree: TreeConfig,
    #[serde(default)]
    pub vectors: VectorConfig,
    #[serde(default)]
    pub local: LocalConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub session: SessionConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProxyConfig {
    pub listen: String,
    pub upstream: String,
    #[serde(default = "default_api_key_env")]
    pub api_key_env: String,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: usize,
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub masking_strategy: crate::MaskingStrategy,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VaultConfig {
    pub path: String,
    #[serde(default = "default_encryption")]
    pub encryption: String,
    pub key_env: Option<String>,
    #[serde(default)]
    pub key_keyring: bool,
    #[serde(default = "default_vault_backend")]
    pub backend: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DetectionConfig {
    #[serde(default = "default_true")]
    pub secrets: bool,
    #[serde(default = "default_true")]
    pub financial: bool,
    #[serde(default = "default_true")]
    pub dates: bool,
    #[serde(default = "default_true")]
    pub emails: bool,
    #[serde(default)]
    pub phone_numbers: bool,
    #[serde(default)]
    pub ip_addresses: bool,
    #[serde(default)]
    pub urls_internal: bool,
    #[serde(default)]
    pub ner: NerConfig,
    #[serde(default)]
    pub custom: CustomConfig,
    #[serde(default)]
    pub overrides: OverrideConfig,
    #[serde(default)]
    pub resolver: ResolverConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum NerBackend {
    #[default]
    Bert,
    Gliner,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct NerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub backend: NerBackend,
    pub model: Option<String>,
    #[serde(default = "default_confidence")]
    pub confidence_threshold: f64,
    #[serde(default)]
    pub entity_types: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct CustomConfig {
    #[serde(default)]
    pub patterns: Vec<CustomPattern>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CustomPattern {
    pub name: String,
    pub regex: String,
    pub category: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct OverrideConfig {
    #[serde(default)]
    pub preserve: Vec<String>,
    #[serde(default)]
    pub force: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TreeConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_tree_path")]
    pub storage_path: String,
    #[serde(default = "default_tree_model")]
    pub index_model: String,
    #[serde(default = "default_tree_model")]
    pub search_model: String,
    #[serde(default = "default_max_pages")]
    pub max_pages_per_node: usize,
    #[serde(default = "default_max_tokens")]
    pub max_tokens_per_node: usize,
    #[serde(default = "default_true")]
    pub add_node_summaries: bool,
    #[serde(default = "default_true")]
    pub pseudonymize_summaries: bool,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct VectorConfig {
    #[serde(default)]
    pub encrypt: bool,
    #[serde(default = "default_adcpe")]
    pub algorithm: String,
    pub key_env: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct LocalConfig {
    pub embeddings_model: Option<String>,
    #[serde(default = "default_vector_db")]
    pub vector_db: String,
    pub vector_db_path: Option<String>,
    pub llm_model: Option<String>,
    pub llm_backend: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuditConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_audit_path")]
    pub log_path: String,
    #[serde(default = "default_jsonl")]
    pub format: String,
    #[serde(default = "default_retention")]
    pub retention_days: u32,
    #[serde(default = "default_true")]
    pub log_entities: bool,
    #[serde(default)]
    pub log_mappings: bool,
    #[serde(default = "default_audit_backend")]
    pub backend: String,
}

// Default value functions
fn default_true() -> bool { true }
fn default_api_key_env() -> String { "OPENAI_API_KEY".into() }
fn default_timeout() -> u64 { 120 }
fn default_max_concurrent() -> usize { 256 }
fn default_mode() -> String { "cloaktree".into() }
fn default_encryption() -> String { "aes-256-gcm".into() }
fn default_vault_backend() -> String { "file".into() }
fn default_audit_backend() -> String { "jsonl".into() }
fn default_confidence() -> f64 { 0.85 }
fn default_tree_path() -> String { "./trees/".into() }
fn default_tree_model() -> String { "gpt-4o".into() }
fn default_max_pages() -> usize { 10 }
fn default_max_tokens() -> usize { 20000 }
fn default_adcpe() -> String { "adcpe".into() }
fn default_vector_db() -> String { "lancedb".into() }
fn default_audit_path() -> String { "./audit/".into() }
fn default_jsonl() -> String { "jsonl".into() }
fn default_retention() -> u32 { 90 }

impl Default for TreeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            storage_path: default_tree_path(),
            index_model: default_tree_model(),
            search_model: default_tree_model(),
            max_pages_per_node: default_max_pages(),
            max_tokens_per_node: default_max_tokens(),
            add_node_summaries: true,
            pseudonymize_summaries: true,
        }
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_path: default_audit_path(),
            format: default_jsonl(),
            retention_days: default_retention(),
            log_entities: true,
            log_mappings: false,
            backend: default_audit_backend(),
        }
    }
}
