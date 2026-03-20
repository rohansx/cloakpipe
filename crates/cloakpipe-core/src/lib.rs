//! CloakPipe Core — Detection, pseudonymization, and rehydration engine.
//!
//! This crate provides the foundational privacy primitives:
//! - Multi-layer entity detection (regex, financial, NER, custom rules)
//! - Consistent pseudonymization with stable entity→token mappings
//! - Encrypted mapping vault (AES-256-GCM + zeroize)
//! - Response rehydration (including SSE streaming support)

pub mod detector;
pub mod format_preserving;
pub mod replacer;
pub mod resolver;
pub mod session;
pub mod vault;
pub mod vault_sqlite;
pub mod rehydrator;
pub mod config;
pub mod profiles;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A detected sensitive entity within text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedEntity {
    /// The raw sensitive text that was detected.
    pub original: String,
    /// Byte offset start in the source text.
    pub start: usize,
    /// Byte offset end in the source text.
    pub end: usize,
    /// The category of sensitive data (e.g., PERSON, ORG, AMOUNT, SECRET).
    pub category: EntityCategory,
    /// Detection confidence (0.0–1.0). 1.0 for pattern-based, variable for NER.
    pub confidence: f64,
    /// Which detection layer found this entity.
    pub source: DetectionSource,
}

/// Categories of sensitive entities.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EntityCategory {
    Person,
    Organization,
    Location,
    Amount,
    Percentage,
    Date,
    Email,
    PhoneNumber,
    IpAddress,
    Secret,      // API keys, tokens, passwords
    Url,         // Internal URLs
    Project,     // Custom: project codenames
    Business,    // Custom: client tiers, deal terms
    Infra,       // Custom: internal infrastructure
    Custom(String),
}

/// Which detection layer identified the entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectionSource {
    Pattern,     // Regex-based
    Financial,   // Currency/percentage parser
    Ner,         // ONNX NER model
    Custom,      // User-defined TOML rules
}

/// A pseudonymized replacement token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PseudoToken {
    /// The replacement string (e.g., "ORG_7", "AMOUNT_12").
    pub token: String,
    /// The category prefix used.
    pub category: EntityCategory,
    /// The sequential ID within this category.
    pub id: u32,
}

/// Result of pseudonymizing a text.
#[derive(Debug, Clone)]
pub struct PseudonymizedText {
    /// The text with all sensitive entities replaced by pseudo-tokens.
    pub text: String,
    /// Map from pseudo-tokens back to original values (for rehydration).
    pub mappings: HashMap<String, String>,
    /// List of all entities that were detected and replaced.
    pub entities: Vec<DetectedEntity>,
}

/// Strategy for generating pseudo-tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaskingStrategy {
    /// Standard tokens: PERSON_001, EMAIL_002, etc. (default)
    #[default]
    Token,
    /// Format-preserving: fake phone numbers, emails, Aadhaar, etc.
    FormatPreserving,
}

/// Result of rehydrating a response.
#[derive(Debug, Clone)]
pub struct RehydratedText {
    /// The text with pseudo-tokens replaced back with original values.
    pub text: String,
    /// Number of tokens that were successfully rehydrated.
    pub rehydrated_count: usize,
}
