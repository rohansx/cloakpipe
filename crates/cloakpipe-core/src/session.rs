//! Session-aware context buffer for cross-message privacy.
//!
//! Tracks entities seen within a conversation session, enabling:
//! - **Coreference resolution**: "He" → PERSON_5 (from prior messages)
//! - **Abbreviation matching**: "TM" → ORG_7 (Tata Motors)
//! - **Sensitivity escalation**: decision-trace keyword detection
//! - **Cross-message consistency**: session-aware fuzzy matching with lower thresholds

use crate::{DetectedEntity, EntityCategory, PseudoToken};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Configuration for session-aware pseudonymization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Enable session tracking (default: false).
    #[serde(default)]
    pub enabled: bool,
    /// How to extract session IDs from requests.
    #[serde(default = "default_id_from")]
    pub id_from: String,
    /// Session TTL in seconds — flush after inactivity (default: 1800 = 30 min).
    #[serde(default = "default_ttl")]
    pub ttl_seconds: u64,
    /// Enable coreference resolution (pronouns, abbreviations).
    #[serde(default = "default_true")]
    pub coreference: bool,
    /// Enable sensitivity escalation for decision traces.
    #[serde(default = "default_true")]
    pub sensitivity_escalation: bool,
    /// Lower similarity threshold for within-session fuzzy matching (default: 0.80).
    #[serde(default = "default_session_threshold")]
    pub session_threshold: f64,
}

fn default_id_from() -> String {
    "header:x-session-id".into()
}
fn default_ttl() -> u64 {
    1800
}
fn default_true() -> bool {
    true
}
fn default_session_threshold() -> f64 {
    0.80
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            id_from: default_id_from(),
            ttl_seconds: default_ttl(),
            coreference: true,
            sensitivity_escalation: true,
            session_threshold: default_session_threshold(),
        }
    }
}

/// Sensitivity level for a session — escalates when decision-making detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitivityLevel {
    /// Normal mode: only catch high-confidence entities.
    #[default]
    Normal,
    /// Elevated: also catch role references, temporal references, precedent references.
    Elevated,
}

/// An entity observed within a session, tracked across messages.
#[derive(Debug, Clone, Serialize)]
pub struct SessionEntity {
    /// The pseudonymized token.
    pub token: PseudoToken,
    /// Category of the entity.
    pub category: EntityCategory,
    /// Original text (for internal matching only — never exposed in APIs).
    pub original: String,
    /// Message index where first seen.
    pub first_seen: u32,
    /// Message index where last seen.
    pub last_seen: u32,
    /// Related entity tokens (co-occurred in same message).
    pub related_to: Vec<String>,
}

/// A coreference mapping: pronoun/abbreviation → entity token.
#[derive(Debug, Clone, Serialize)]
pub struct Coreference {
    /// The pronoun or abbreviation (e.g., "He", "TM", "the company").
    pub surface: String,
    /// The resolved entity token (e.g., "PERSON_5", "ORG_7").
    pub target_token: String,
    /// Confidence (heuristic-based, 0.0–1.0).
    pub confidence: f64,
    /// How the resolution was made.
    pub method: CorefMethod,
}

/// Method used to resolve a coreference.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CorefMethod {
    /// Pronoun resolution (only one entity of matching type in recent context).
    Pronoun,
    /// Abbreviation (initials match entity name).
    Abbreviation,
    /// Definite article ("the company" → most recent ORG).
    DefiniteArticle,
    /// Possessive ("Rahul's" → PERSON who is "Rahul").
    Possessive,
}

/// Per-session context buffer.
#[derive(Debug)]
pub struct SessionContext {
    /// Session identifier.
    pub session_id: String,
    /// When the session was created.
    pub created_at: DateTime<Utc>,
    /// Last activity timestamp (for TTL).
    pub last_activity: DateTime<Utc>,
    /// Message counter (increments per pseudonymize call).
    pub message_count: u32,
    /// Current sensitivity level.
    pub sensitivity: SensitivityLevel,
    /// Keywords that triggered escalation.
    pub escalation_keywords: Vec<String>,
    /// Entities seen in this session (original text → SessionEntity).
    pub entities: HashMap<String, SessionEntity>,
    /// Coreference mappings (surface form → Coreference).
    pub coreferences: HashMap<String, Coreference>,
    /// Config reference.
    config: SessionConfig,
}

// Keywords that trigger sensitivity escalation to decision-trace mode.
const DECISION_KEYWORDS: &[&str] = &[
    "approved",
    "rejected",
    "exception",
    "policy",
    "override",
    "escalated",
    "waiver",
    "authorized",
    "sanctioned",
    "compliance",
    "violation",
    "audit",
    "decision",
    "ruling",
    "verdict",
    "settlement",
    "terminated",
    "suspended",
];

// Pronouns that can be resolved to entities.
const PERSON_PRONOUNS: &[&str] = &[
    "he", "him", "his", "she", "her", "hers", "they", "them", "their",
];

// Definite article patterns → entity category they likely refer to.
const DEFINITE_ARTICLES: &[(&str, EntityCategory)] = &[
    ("the company", EntityCategory::Organization),
    ("the firm", EntityCategory::Organization),
    ("the client", EntityCategory::Organization),
    ("the organization", EntityCategory::Organization),
    ("the bank", EntityCategory::Organization),
    ("the hospital", EntityCategory::Organization),
    ("the deal", EntityCategory::Amount),
    ("the amount", EntityCategory::Amount),
    ("the transaction", EntityCategory::Amount),
    ("the payment", EntityCategory::Amount),
    ("the city", EntityCategory::Location),
    ("the office", EntityCategory::Location),
    ("the employee", EntityCategory::Person),
    ("the manager", EntityCategory::Person),
    ("the patient", EntityCategory::Person),
    ("the customer", EntityCategory::Person),
    ("the applicant", EntityCategory::Person),
];

impl SessionContext {
    /// Create a new session context.
    pub fn new(session_id: String, config: SessionConfig) -> Self {
        let now = Utc::now();
        Self {
            session_id,
            created_at: now,
            last_activity: now,
            message_count: 0,
            sensitivity: SensitivityLevel::Normal,
            escalation_keywords: Vec::new(),
            entities: HashMap::new(),
            coreferences: HashMap::new(),
            config,
        }
    }

    /// Check if this session has expired based on TTL.
    pub fn is_expired(&self) -> bool {
        let elapsed = Utc::now()
            .signed_duration_since(self.last_activity)
            .num_seconds();
        elapsed > self.config.ttl_seconds as i64
    }

    /// Record entities detected in the current message.
    /// Call this after pseudonymization to update session state.
    pub fn record_entities(
        &mut self,
        entities: &[DetectedEntity],
        tokens: &[PseudoToken],
    ) {
        self.message_count += 1;
        self.last_activity = Utc::now();

        // Collect all tokens from this message for relationship tracking
        let msg_tokens: Vec<String> = tokens.iter().map(|t| t.token.clone()).collect();

        for (entity, token) in entities.iter().zip(tokens.iter()) {
            let entry = self
                .entities
                .entry(entity.original.clone())
                .or_insert_with(|| SessionEntity {
                    token: token.clone(),
                    category: entity.category.clone(),
                    original: entity.original.clone(),
                    first_seen: self.message_count,
                    last_seen: self.message_count,
                    related_to: Vec::new(),
                });

            entry.last_seen = self.message_count;

            // Track co-occurrence: all other tokens in the same message
            for t in &msg_tokens {
                if t != &token.token && !entry.related_to.contains(t) {
                    entry.related_to.push(t.clone());
                }
            }
        }

        // Update coreferences after recording entities
        if self.config.coreference {
            self.update_coreferences();
        }
    }

    /// Check text for sensitivity escalation keywords.
    /// Returns true if sensitivity was escalated.
    pub fn check_sensitivity(&mut self, text: &str) -> bool {
        if !self.config.sensitivity_escalation {
            return false;
        }
        if self.sensitivity == SensitivityLevel::Elevated {
            return false; // Already escalated
        }

        let text_lower = text.to_lowercase();
        let mut found = Vec::new();
        for &keyword in DECISION_KEYWORDS {
            if text_lower.contains(keyword) {
                found.push(keyword.to_string());
            }
        }

        if found.len() >= 2 {
            // Need at least 2 decision keywords to escalate
            self.sensitivity = SensitivityLevel::Elevated;
            self.escalation_keywords = found;
            true
        } else {
            false
        }
    }

    /// Resolve coreferences in the text — returns additional entities to pseudonymize.
    ///
    /// Finds pronouns, abbreviations, and definite articles that refer to
    /// previously seen entities, and returns them as DetectedEntity instances
    /// so the caller can pseudonymize them.
    pub fn resolve_coreferences(&self, text: &str) -> Vec<(DetectedEntity, PseudoToken)> {
        if !self.config.coreference || self.entities.is_empty() {
            return Vec::new();
        }

        let mut results = Vec::new();
        let text_lower = text.to_lowercase();

        // 1. Pronoun resolution
        for &pronoun in PERSON_PRONOUNS {
            if let Some(pos) = find_word_boundary(&text_lower, pronoun) {
                // Find the most recent PERSON entity
                if let Some(person) = self.most_recent_entity(&EntityCategory::Person) {
                    // Only resolve if there's exactly one recent person (avoid ambiguity)
                    let recent_persons = self.recent_entities_of_category(&EntityCategory::Person, 3);
                    if recent_persons.len() == 1 {
                        results.push((
                            DetectedEntity {
                                original: text[pos..pos + pronoun.len()].to_string(),
                                start: pos,
                                end: pos + pronoun.len(),
                                category: EntityCategory::Person,
                                confidence: 0.7,
                                source: crate::DetectionSource::Pattern,
                            },
                            person.token.clone(),
                        ));
                    }
                }
            }
        }

        // 2. Definite article resolution
        for &(article, ref category) in DEFINITE_ARTICLES {
            if let Some(pos) = find_word_boundary(&text_lower, article) {
                if let Some(entity) = self.most_recent_entity(category) {
                    results.push((
                        DetectedEntity {
                            original: text[pos..pos + article.len()].to_string(),
                            start: pos,
                            end: pos + article.len(),
                            category: category.clone(),
                            confidence: 0.6,
                            source: crate::DetectionSource::Pattern,
                        },
                        entity.token.clone(),
                    ));
                }
            }
        }

        // 3. Abbreviation resolution (e.g., "TM" → "Tata Motors")
        results.extend(self.resolve_abbreviations(text));

        // 4. Possessive resolution (e.g., "Rahul's" → PERSON_5)
        results.extend(self.resolve_possessives(text));

        // Deduplicate by position (keep highest confidence)
        results.sort_by(|a, b| a.0.start.cmp(&b.0.start));
        results.dedup_by(|a, b| {
            if a.0.start == b.0.start {
                if b.0.confidence > a.0.confidence {
                    std::mem::swap(a, b);
                }
                true
            } else {
                false
            }
        });

        results
    }

    /// Get the most recent entity of a given category.
    fn most_recent_entity(&self, category: &EntityCategory) -> Option<&SessionEntity> {
        self.entities
            .values()
            .filter(|e| &e.category == category)
            .max_by_key(|e| e.last_seen)
    }

    /// Get recent entities of a category (within last N messages).
    fn recent_entities_of_category(
        &self,
        category: &EntityCategory,
        within_messages: u32,
    ) -> Vec<&SessionEntity> {
        let cutoff = self.message_count.saturating_sub(within_messages);
        self.entities
            .values()
            .filter(|e| &e.category == category && e.last_seen >= cutoff)
            .collect()
    }

    /// Resolve abbreviations: "TM" might match "Tata Motors" (initials).
    fn resolve_abbreviations(&self, text: &str) -> Vec<(DetectedEntity, PseudoToken)> {
        let mut results = Vec::new();

        for entity in self.entities.values() {
            // Only check Organization and Person (multi-word names)
            if !matches!(
                entity.category,
                EntityCategory::Organization | EntityCategory::Person
            ) {
                continue;
            }

            let words: Vec<&str> = entity.original.split_whitespace().collect();
            if words.len() < 2 {
                continue;
            }

            // Build abbreviation from initials
            let abbrev: String = words.iter().map(|w| {
                w.chars().next().unwrap_or_default().to_uppercase().to_string()
            }).collect();

            if abbrev.len() < 2 {
                continue;
            }

            // Search for the abbreviation as a standalone word in text
            if let Some(pos) = find_word_boundary(text, &abbrev) {
                results.push((
                    DetectedEntity {
                        original: text[pos..pos + abbrev.len()].to_string(),
                        start: pos,
                        end: pos + abbrev.len(),
                        category: entity.category.clone(),
                        confidence: 0.65,
                        source: crate::DetectionSource::Pattern,
                    },
                    entity.token.clone(),
                ));
            }
        }

        results
    }

    /// Resolve possessives: "Rahul's" → PERSON token for "Rahul".
    fn resolve_possessives(&self, text: &str) -> Vec<(DetectedEntity, PseudoToken)> {
        let mut results = Vec::new();

        for entity in self.entities.values() {
            if entity.category != EntityCategory::Person {
                continue;
            }

            // Get the first name
            let first_name = entity
                .original
                .split_whitespace()
                .next()
                .unwrap_or(&entity.original);

            let possessive = format!("{}'s", first_name);
            if let Some(pos) = find_word_boundary(text, &possessive) {
                results.push((
                    DetectedEntity {
                        original: text[pos..pos + possessive.len()].to_string(),
                        start: pos,
                        end: pos + possessive.len(),
                        category: EntityCategory::Person,
                        confidence: 0.75,
                        source: crate::DetectionSource::Pattern,
                    },
                    entity.token.clone(),
                ));
            }
        }

        results
    }

    /// Update coreference mappings based on current entity state.
    fn update_coreferences(&mut self) {
        // Collect all coref entries first, then insert (avoids borrow issues)
        let mut new_corefs: Vec<(String, Coreference)> = Vec::new();

        // Pronouns → most recent unambiguous person
        {
            let recent_persons = self.recent_entities_of_category(&EntityCategory::Person, 3);
            if recent_persons.len() == 1 {
                let token_str = recent_persons[0].token.token.clone();
                for &pronoun in PERSON_PRONOUNS {
                    new_corefs.push((
                        pronoun.to_string(),
                        Coreference {
                            surface: pronoun.to_string(),
                            target_token: token_str.clone(),
                            confidence: 0.7,
                            method: CorefMethod::Pronoun,
                        },
                    ));
                }
            }
        }

        // Definite articles → most recent entity of matching category
        for &(article, ref category) in DEFINITE_ARTICLES {
            if let Some(entity) = self.most_recent_entity(category) {
                let token_str = entity.token.token.clone();
                new_corefs.push((
                    article.to_string(),
                    Coreference {
                        surface: article.to_string(),
                        target_token: token_str,
                        confidence: 0.6,
                        method: CorefMethod::DefiniteArticle,
                    },
                ));
            }
        }

        // Abbreviations
        for entity in self.entities.values() {
            if !matches!(
                entity.category,
                EntityCategory::Organization | EntityCategory::Person
            ) {
                continue;
            }
            let words: Vec<&str> = entity.original.split_whitespace().collect();
            if words.len() < 2 {
                continue;
            }
            let abbrev: String = words
                .iter()
                .map(|w| w.chars().next().unwrap_or_default().to_uppercase().to_string())
                .collect();
            if abbrev.len() >= 2 {
                new_corefs.push((
                    abbrev.clone(),
                    Coreference {
                        surface: abbrev,
                        target_token: entity.token.token.clone(),
                        confidence: 0.65,
                        method: CorefMethod::Abbreviation,
                    },
                ));
            }
        }

        // Apply all collected coreferences
        self.coreferences.clear();
        for (key, coref) in new_corefs {
            self.coreferences.insert(key, coref);
        }
    }

    /// Get a summary of this session's state (safe — no raw PII).
    pub fn stats(&self) -> SessionStats {
        let mut categories = HashMap::new();
        for entity in self.entities.values() {
            *categories.entry(format!("{:?}", entity.category)).or_insert(0u32) += 1;
        }

        SessionStats {
            session_id: self.session_id.clone(),
            message_count: self.message_count,
            entity_count: self.entities.len(),
            coreference_count: self.coreferences.len(),
            sensitivity: self.sensitivity,
            escalation_keywords: self.escalation_keywords.clone(),
            categories,
            created_at: self.created_at.to_rfc3339(),
            last_activity: self.last_activity.to_rfc3339(),
        }
    }

    /// Get all coreference mappings (for inspection/debugging).
    pub fn coreference_map(&self) -> &HashMap<String, Coreference> {
        &self.coreferences
    }

    /// Get the session-aware resolver threshold (lower than global).
    pub fn resolver_threshold(&self) -> f64 {
        self.config.session_threshold
    }
}

/// Safe session statistics (no PII).
#[derive(Debug, Clone, Serialize)]
pub struct SessionStats {
    pub session_id: String,
    pub message_count: u32,
    pub entity_count: usize,
    pub coreference_count: usize,
    pub sensitivity: SensitivityLevel,
    pub escalation_keywords: Vec<String>,
    pub categories: HashMap<String, u32>,
    pub created_at: String,
    pub last_activity: String,
}

/// Thread-safe session manager — stores all active sessions.
pub struct SessionManager {
    sessions: std::sync::RwLock<HashMap<String, SessionContext>>,
    config: SessionConfig,
}

impl SessionManager {
    /// Create a new session manager.
    pub fn new(config: SessionConfig) -> Self {
        Self {
            sessions: std::sync::RwLock::new(HashMap::new()),
            config,
        }
    }

    /// Get or create a session context.
    pub fn get_or_create(&self, session_id: &str) -> String {
        let mut sessions = self.sessions.write().unwrap();

        // Check if session exists and is not expired
        if let Some(session) = sessions.get(session_id) {
            if !session.is_expired() {
                return session_id.to_string();
            }
            // Expired — remove it
            sessions.remove(session_id);
        }

        // Create new session
        sessions.insert(
            session_id.to_string(),
            SessionContext::new(session_id.to_string(), self.config.clone()),
        );
        session_id.to_string()
    }

    /// Execute a function with mutable access to a session.
    pub fn with_session<F, R>(&self, session_id: &str, f: F) -> Option<R>
    where
        F: FnOnce(&mut SessionContext) -> R,
    {
        let mut sessions = self.sessions.write().unwrap();
        sessions.get_mut(session_id).map(f)
    }

    /// Execute a function with read access to a session.
    pub fn with_session_ref<F, R>(&self, session_id: &str, f: F) -> Option<R>
    where
        F: FnOnce(&SessionContext) -> R,
    {
        let sessions = self.sessions.read().unwrap();
        sessions.get(session_id).map(f)
    }

    /// List all active sessions (stats only, no PII).
    pub fn list_sessions(&self) -> Vec<SessionStats> {
        let sessions = self.sessions.read().unwrap();
        sessions.values().map(|s| s.stats()).collect()
    }

    /// Inspect a specific session (stats only).
    pub fn inspect(&self, session_id: &str) -> Option<SessionStats> {
        let sessions = self.sessions.read().unwrap();
        sessions.get(session_id).map(|s| s.stats())
    }

    /// Flush (remove) a specific session.
    pub fn flush_session(&self, session_id: &str) -> bool {
        let mut sessions = self.sessions.write().unwrap();
        sessions.remove(session_id).is_some()
    }

    /// Flush all sessions.
    pub fn flush_all(&self) -> usize {
        let mut sessions = self.sessions.write().unwrap();
        let count = sessions.len();
        sessions.clear();
        count
    }

    /// Evict expired sessions. Returns number evicted.
    pub fn evict_expired(&self) -> usize {
        let mut sessions = self.sessions.write().unwrap();
        let before = sessions.len();
        sessions.retain(|_, s| !s.is_expired());
        before - sessions.len()
    }

    /// Check if session tracking is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

/// Find a word at a word boundary in text. Returns byte offset if found.
fn find_word_boundary(text: &str, word: &str) -> Option<usize> {
    let text_lower = text.to_lowercase();
    let word_lower = word.to_lowercase();
    let mut start = 0;
    while let Some(pos) = text_lower[start..].find(&word_lower) {
        let abs_pos = start + pos;
        let before_ok = abs_pos == 0
            || !text.as_bytes()[abs_pos - 1].is_ascii_alphanumeric();
        let after_pos = abs_pos + word_lower.len();
        let after_ok = after_pos >= text.len()
            || !text.as_bytes()[after_pos].is_ascii_alphanumeric();

        if before_ok && after_ok {
            return Some(abs_pos);
        }
        start = abs_pos + 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DetectedEntity, DetectionSource, EntityCategory, PseudoToken};

    fn test_config() -> SessionConfig {
        SessionConfig {
            enabled: true,
            id_from: "header:x-session-id".into(),
            ttl_seconds: 1800,
            coreference: true,
            sensitivity_escalation: true,
            session_threshold: 0.80,
        }
    }

    fn make_entity(original: &str, category: EntityCategory) -> DetectedEntity {
        DetectedEntity {
            original: original.to_string(),
            start: 0,
            end: original.len(),
            category,
            confidence: 1.0,
            source: DetectionSource::Pattern,
        }
    }

    fn make_token(token: &str, category: EntityCategory, id: u32) -> PseudoToken {
        PseudoToken {
            token: token.to_string(),
            category,
            id,
        }
    }

    #[test]
    fn test_session_creation() {
        let ctx = SessionContext::new("sess-1".into(), test_config());
        assert_eq!(ctx.session_id, "sess-1");
        assert_eq!(ctx.message_count, 0);
        assert_eq!(ctx.sensitivity, SensitivityLevel::Normal);
        assert!(ctx.entities.is_empty());
    }

    #[test]
    fn test_record_entities() {
        let mut ctx = SessionContext::new("sess-1".into(), test_config());

        let entities = vec![
            make_entity("Rahul Sharma", EntityCategory::Person),
            make_entity("Tata Motors", EntityCategory::Organization),
        ];
        let tokens = vec![
            make_token("PERSON_1", EntityCategory::Person, 1),
            make_token("ORG_1", EntityCategory::Organization, 1),
        ];

        ctx.record_entities(&entities, &tokens);

        assert_eq!(ctx.message_count, 1);
        assert_eq!(ctx.entities.len(), 2);

        let rahul = ctx.entities.get("Rahul Sharma").unwrap();
        assert_eq!(rahul.token.token, "PERSON_1");
        assert_eq!(rahul.first_seen, 1);
        assert_eq!(rahul.related_to, vec!["ORG_1"]);
    }

    #[test]
    fn test_pronoun_resolution() {
        let mut ctx = SessionContext::new("sess-1".into(), test_config());

        // Message 1: introduce Rahul
        ctx.record_entities(
            &[make_entity("Rahul Sharma", EntityCategory::Person)],
            &[make_token("PERSON_1", EntityCategory::Person, 1)],
        );

        // Message 2: "He approved the deal"
        let corefs = ctx.resolve_coreferences("He approved the deal");
        assert!(!corefs.is_empty());

        let he_coref = corefs.iter().find(|(e, _)| e.original.to_lowercase() == "he");
        assert!(he_coref.is_some());
        assert_eq!(he_coref.unwrap().1.token, "PERSON_1");
    }

    #[test]
    fn test_pronoun_ambiguity_blocks_resolution() {
        let mut ctx = SessionContext::new("sess-1".into(), test_config());

        // Two recent persons — pronouns should NOT resolve (ambiguous)
        ctx.record_entities(
            &[
                make_entity("Rahul Sharma", EntityCategory::Person),
                make_entity("Priya Singh", EntityCategory::Person),
            ],
            &[
                make_token("PERSON_1", EntityCategory::Person, 1),
                make_token("PERSON_2", EntityCategory::Person, 2),
            ],
        );

        let corefs = ctx.resolve_coreferences("He approved the deal");
        let he_coref = corefs.iter().find(|(e, _)| e.original.to_lowercase() == "he");
        assert!(he_coref.is_none());
    }

    #[test]
    fn test_abbreviation_resolution() {
        let mut ctx = SessionContext::new("sess-1".into(), test_config());

        ctx.record_entities(
            &[make_entity("Tata Motors", EntityCategory::Organization)],
            &[make_token("ORG_1", EntityCategory::Organization, 1)],
        );

        let corefs = ctx.resolve_coreferences("TM reported strong quarterly earnings");
        let tm_coref = corefs.iter().find(|(e, _)| e.original == "TM");
        assert!(tm_coref.is_some());
        assert_eq!(tm_coref.unwrap().1.token, "ORG_1");
    }

    #[test]
    fn test_definite_article_resolution() {
        let mut ctx = SessionContext::new("sess-1".into(), test_config());

        ctx.record_entities(
            &[make_entity("Infosys Ltd", EntityCategory::Organization)],
            &[make_token("ORG_1", EntityCategory::Organization, 1)],
        );

        let corefs = ctx.resolve_coreferences("the company posted record revenue");
        let co_coref = corefs
            .iter()
            .find(|(e, _)| e.original.to_lowercase() == "the company");
        assert!(co_coref.is_some());
        assert_eq!(co_coref.unwrap().1.token, "ORG_1");
    }

    #[test]
    fn test_possessive_resolution() {
        let mut ctx = SessionContext::new("sess-1".into(), test_config());

        ctx.record_entities(
            &[make_entity("Rahul Sharma", EntityCategory::Person)],
            &[make_token("PERSON_1", EntityCategory::Person, 1)],
        );

        let corefs = ctx.resolve_coreferences("Rahul's decision was final");
        let poss = corefs
            .iter()
            .find(|(e, _)| e.original.contains("Rahul's"));
        assert!(poss.is_some());
        assert_eq!(poss.unwrap().1.token, "PERSON_1");
    }

    #[test]
    fn test_sensitivity_escalation() {
        let mut ctx = SessionContext::new("sess-1".into(), test_config());

        // Single keyword — not enough
        assert!(!ctx.check_sensitivity("The request was approved"));
        assert_eq!(ctx.sensitivity, SensitivityLevel::Normal);

        // Two keywords — escalates
        assert!(ctx.check_sensitivity("The exception was approved per policy override"));
        assert_eq!(ctx.sensitivity, SensitivityLevel::Elevated);
        assert!(ctx.escalation_keywords.len() >= 2);
    }

    #[test]
    fn test_sensitivity_no_double_escalation() {
        let mut ctx = SessionContext::new("sess-1".into(), test_config());

        ctx.check_sensitivity("approved policy override exception");
        assert_eq!(ctx.sensitivity, SensitivityLevel::Elevated);

        // Already elevated — returns false
        assert!(!ctx.check_sensitivity("another decision violation"));
    }

    #[test]
    fn test_session_ttl_expiry() {
        let mut ctx = SessionContext::new("sess-1".into(), SessionConfig {
            ttl_seconds: 0, // Immediately expire
            ..test_config()
        });
        ctx.last_activity = Utc::now() - chrono::Duration::seconds(1);
        assert!(ctx.is_expired());
    }

    #[test]
    fn test_session_manager_create_and_list() {
        let mgr = SessionManager::new(test_config());
        mgr.get_or_create("sess-1");
        mgr.get_or_create("sess-2");

        let sessions = mgr.list_sessions();
        assert_eq!(sessions.len(), 2);
    }

    #[test]
    fn test_session_manager_flush() {
        let mgr = SessionManager::new(test_config());
        mgr.get_or_create("sess-1");
        mgr.get_or_create("sess-2");

        assert!(mgr.flush_session("sess-1"));
        assert!(!mgr.flush_session("nonexistent"));

        let sessions = mgr.list_sessions();
        assert_eq!(sessions.len(), 1);
    }

    #[test]
    fn test_session_manager_flush_all() {
        let mgr = SessionManager::new(test_config());
        mgr.get_or_create("sess-1");
        mgr.get_or_create("sess-2");

        assert_eq!(mgr.flush_all(), 2);
        assert!(mgr.list_sessions().is_empty());
    }

    #[test]
    fn test_session_stats() {
        let mut ctx = SessionContext::new("sess-1".into(), test_config());
        ctx.record_entities(
            &[
                make_entity("Alice", EntityCategory::Person),
                make_entity("Acme Corp", EntityCategory::Organization),
            ],
            &[
                make_token("PERSON_1", EntityCategory::Person, 1),
                make_token("ORG_1", EntityCategory::Organization, 1),
            ],
        );

        let stats = ctx.stats();
        assert_eq!(stats.session_id, "sess-1");
        assert_eq!(stats.message_count, 1);
        assert_eq!(stats.entity_count, 2);
        assert_eq!(stats.sensitivity, SensitivityLevel::Normal);
    }

    #[test]
    fn test_find_word_boundary() {
        assert_eq!(find_word_boundary("He went home", "he"), Some(0));
        assert_eq!(find_word_boundary("Then he went", "he"), Some(5));
        assert!(find_word_boundary("The cat", "he").is_none()); // "he" inside "The"
        assert_eq!(find_word_boundary("Say TM earnings", "TM"), Some(4));
        assert!(find_word_boundary("ATMS are here", "TM").is_none()); // inside word
    }

    #[test]
    fn test_cross_message_entity_tracking() {
        let mut ctx = SessionContext::new("sess-1".into(), test_config());

        // Message 1
        ctx.record_entities(
            &[make_entity("Rahul", EntityCategory::Person)],
            &[make_token("PERSON_1", EntityCategory::Person, 1)],
        );

        // Message 2 — same entity
        ctx.record_entities(
            &[make_entity("Rahul", EntityCategory::Person)],
            &[make_token("PERSON_1", EntityCategory::Person, 1)],
        );

        let rahul = ctx.entities.get("Rahul").unwrap();
        assert_eq!(rahul.first_seen, 1);
        assert_eq!(rahul.last_seen, 2);
    }

    #[test]
    fn test_coreference_map_updates() {
        let mut ctx = SessionContext::new("sess-1".into(), test_config());

        ctx.record_entities(
            &[make_entity("Tata Motors", EntityCategory::Organization)],
            &[make_token("ORG_1", EntityCategory::Organization, 1)],
        );

        let corefs = ctx.coreference_map();
        assert!(corefs.contains_key("TM")); // Abbreviation
        assert!(corefs.contains_key("the company")); // Definite article
    }

    // --- Comprehensive tests ---

    #[test]
    fn test_multi_message_conversation_flow() {
        // Simulate a realistic 4-message conversation
        let mut ctx = SessionContext::new("conv-1".into(), test_config());

        // Message 1: Introduce people and company
        ctx.record_entities(
            &[
                make_entity("Rahul Sharma", EntityCategory::Person),
                make_entity("Tata Motors", EntityCategory::Organization),
            ],
            &[
                make_token("PERSON_1", EntityCategory::Person, 1),
                make_token("ORG_1", EntityCategory::Organization, 1),
            ],
        );
        assert_eq!(ctx.message_count, 1);

        // Message 2: Add a location
        ctx.record_entities(
            &[make_entity("Mumbai", EntityCategory::Location)],
            &[make_token("LOC_1", EntityCategory::Location, 1)],
        );
        assert_eq!(ctx.message_count, 2);
        assert_eq!(ctx.entities.len(), 3);

        // Message 3: Reference Rahul with pronoun — only 1 person so should resolve
        let corefs = ctx.resolve_coreferences("He was transferred to the office");
        let he = corefs.iter().find(|(e, _)| e.original.to_lowercase() == "he");
        assert!(he.is_some());
        assert_eq!(he.unwrap().1.token, "PERSON_1");

        // "the office" should resolve to LOC_1
        let office = corefs.iter().find(|(e, _)| e.original.to_lowercase() == "the office");
        assert!(office.is_some());
        assert_eq!(office.unwrap().1.token, "LOC_1");

        // Message 4: Add a second person — pronouns should now be blocked
        ctx.record_entities(
            &[make_entity("Priya Patel", EntityCategory::Person)],
            &[make_token("PERSON_2", EntityCategory::Person, 2)],
        );

        let corefs2 = ctx.resolve_coreferences("She approved the transfer");
        let she = corefs2.iter().find(|(e, _)| e.original.to_lowercase() == "she");
        assert!(she.is_none()); // Ambiguous — 2 persons
    }

    #[test]
    fn test_sensitivity_requires_two_keywords() {
        let mut ctx = SessionContext::new("s-1".into(), test_config());

        // Single keywords — should not escalate
        assert!(!ctx.check_sensitivity("This was approved."));
        assert!(!ctx.check_sensitivity("Check compliance"));
        assert!(!ctx.check_sensitivity("The verdict is in"));
        assert_eq!(ctx.sensitivity, SensitivityLevel::Normal);
    }

    #[test]
    fn test_sensitivity_various_keyword_pairs() {
        // Test different keyword combinations
        let pairs = [
            "The verdict was approved",
            "compliance violation detected",
            "authorized the exception",
            "settlement was sanctioned",
            "decision to terminate suspended",
        ];
        for text in pairs {
            let mut ctx = SessionContext::new("s".into(), test_config());
            assert!(ctx.check_sensitivity(text), "Should escalate for: {}", text);
        }
    }

    #[test]
    fn test_sensitivity_disabled() {
        let mut ctx = SessionContext::new("s-1".into(), SessionConfig {
            sensitivity_escalation: false,
            ..test_config()
        });
        assert!(!ctx.check_sensitivity("approved the policy exception override waiver"));
        assert_eq!(ctx.sensitivity, SensitivityLevel::Normal);
    }

    #[test]
    fn test_coreference_disabled() {
        let mut ctx = SessionContext::new("s-1".into(), SessionConfig {
            coreference: false,
            ..test_config()
        });
        ctx.record_entities(
            &[make_entity("Rahul Sharma", EntityCategory::Person)],
            &[make_token("PERSON_1", EntityCategory::Person, 1)],
        );

        let corefs = ctx.resolve_coreferences("He approved it");
        assert!(corefs.is_empty());
        assert!(ctx.coreference_map().is_empty());
    }

    #[test]
    fn test_abbreviation_needs_multi_word() {
        let mut ctx = SessionContext::new("s-1".into(), test_config());

        // Single-word org — no abbreviation should be generated
        ctx.record_entities(
            &[make_entity("Google", EntityCategory::Organization)],
            &[make_token("ORG_1", EntityCategory::Organization, 1)],
        );
        let corefs = ctx.resolve_coreferences("G is great");
        let g = corefs.iter().find(|(e, _)| e.original == "G");
        assert!(g.is_none()); // Single letter abbreviation should not match
    }

    #[test]
    fn test_abbreviation_case_insensitive_source() {
        let mut ctx = SessionContext::new("s-1".into(), test_config());

        ctx.record_entities(
            &[make_entity("New York City", EntityCategory::Location)],
            &[make_token("LOC_1", EntityCategory::Location, 1)],
        );
        // NYC abbreviation — but Location isn't checked for abbreviations
        let corefs = ctx.resolve_coreferences("NYC is busy");
        let nyc = corefs.iter().find(|(e, _)| e.original == "NYC");
        assert!(nyc.is_none()); // Only Org and Person get abbreviation resolution
    }

    #[test]
    fn test_possessive_first_name_only() {
        let mut ctx = SessionContext::new("s-1".into(), test_config());

        ctx.record_entities(
            &[make_entity("Alice Johnson", EntityCategory::Person)],
            &[make_token("PERSON_1", EntityCategory::Person, 1)],
        );

        // Should match "Alice's" (first name possessive)
        let corefs = ctx.resolve_coreferences("Alice's report was thorough");
        let poss = corefs.iter().find(|(e, _)| e.original.contains("Alice's"));
        assert!(poss.is_some());
        assert_eq!(poss.unwrap().1.token, "PERSON_1");

        // Should NOT match "Johnson's" (last name possessive not implemented)
        let corefs2 = ctx.resolve_coreferences("Johnson's report was thorough");
        let poss2 = corefs2.iter().find(|(e, _)| e.original.contains("Johnson's"));
        assert!(poss2.is_none());
    }

    #[test]
    fn test_co_occurrence_tracking() {
        let mut ctx = SessionContext::new("s-1".into(), test_config());

        ctx.record_entities(
            &[
                make_entity("Alice", EntityCategory::Person),
                make_entity("$50,000", EntityCategory::Amount),
                make_entity("Acme Corp", EntityCategory::Organization),
            ],
            &[
                make_token("PERSON_1", EntityCategory::Person, 1),
                make_token("AMOUNT_1", EntityCategory::Amount, 1),
                make_token("ORG_1", EntityCategory::Organization, 1),
            ],
        );

        let alice = ctx.entities.get("Alice").unwrap();
        assert!(alice.related_to.contains(&"AMOUNT_1".to_string()));
        assert!(alice.related_to.contains(&"ORG_1".to_string()));
        assert!(!alice.related_to.contains(&"PERSON_1".to_string())); // Not self

        let amount = ctx.entities.get("$50,000").unwrap();
        assert!(amount.related_to.contains(&"PERSON_1".to_string()));
        assert!(amount.related_to.contains(&"ORG_1".to_string()));
    }

    #[test]
    fn test_definite_article_all_categories() {
        let mut ctx = SessionContext::new("s-1".into(), test_config());

        ctx.record_entities(
            &[
                make_entity("Acme Corp", EntityCategory::Organization),
                make_entity("$1M", EntityCategory::Amount),
                make_entity("Chicago", EntityCategory::Location),
                make_entity("Jane Doe", EntityCategory::Person),
            ],
            &[
                make_token("ORG_1", EntityCategory::Organization, 1),
                make_token("AMOUNT_1", EntityCategory::Amount, 1),
                make_token("LOC_1", EntityCategory::Location, 1),
                make_token("PERSON_1", EntityCategory::Person, 1),
            ],
        );

        // Test various definite articles
        let org = ctx.resolve_coreferences("the firm announced profits");
        assert!(org.iter().any(|(e, t)| e.original.to_lowercase() == "the firm" && t.token == "ORG_1"));

        let amt = ctx.resolve_coreferences("the deal was finalized");
        assert!(amt.iter().any(|(e, t)| e.original.to_lowercase() == "the deal" && t.token == "AMOUNT_1"));

        let loc = ctx.resolve_coreferences("the city experienced growth");
        assert!(loc.iter().any(|(e, t)| e.original.to_lowercase() == "the city" && t.token == "LOC_1"));

        // "the employee" → PERSON (only 1 person, so pronoun wouldn't block this)
        let person = ctx.resolve_coreferences("the employee was promoted");
        assert!(person.iter().any(|(e, t)| e.original.to_lowercase() == "the employee" && t.token == "PERSON_1"));
    }

    #[test]
    fn test_session_manager_with_session() {
        let mgr = SessionManager::new(test_config());
        mgr.get_or_create("sess-1");

        // Record entities through the manager
        let result = mgr.with_session("sess-1", |ctx| {
            ctx.record_entities(
                &[make_entity("Bob", EntityCategory::Person)],
                &[make_token("PERSON_1", EntityCategory::Person, 1)],
            );
            ctx.message_count
        });
        assert_eq!(result, Some(1));

        // Verify via inspect
        let stats = mgr.inspect("sess-1").unwrap();
        assert_eq!(stats.entity_count, 1);
        assert_eq!(stats.message_count, 1);
    }

    #[test]
    fn test_session_manager_with_session_ref() {
        let mgr = SessionManager::new(test_config());
        mgr.get_or_create("sess-1");

        // Read-only access
        let count = mgr.with_session_ref("sess-1", |ctx| ctx.message_count);
        assert_eq!(count, Some(0));

        // Non-existent session
        let none = mgr.with_session_ref("nonexistent", |ctx| ctx.message_count);
        assert!(none.is_none());
    }

    #[test]
    fn test_session_manager_evict_expired() {
        let mgr = SessionManager::new(SessionConfig {
            ttl_seconds: 0,
            ..test_config()
        });
        mgr.get_or_create("sess-1");
        mgr.get_or_create("sess-2");

        // Force sessions to be expired by manipulating last_activity
        mgr.with_session("sess-1", |ctx| {
            ctx.last_activity = Utc::now() - chrono::Duration::seconds(2);
        });
        mgr.with_session("sess-2", |ctx| {
            ctx.last_activity = Utc::now() - chrono::Duration::seconds(2);
        });

        let evicted = mgr.evict_expired();
        assert_eq!(evicted, 2);
        assert!(mgr.list_sessions().is_empty());
    }

    #[test]
    fn test_session_manager_get_or_create_replaces_expired() {
        let mgr = SessionManager::new(SessionConfig {
            ttl_seconds: 0,
            ..test_config()
        });
        mgr.get_or_create("sess-1");

        // Record something
        mgr.with_session("sess-1", |ctx| {
            ctx.record_entities(
                &[make_entity("Alice", EntityCategory::Person)],
                &[make_token("PERSON_1", EntityCategory::Person, 1)],
            );
            ctx.last_activity = Utc::now() - chrono::Duration::seconds(2);
        });

        // Getting the same session should create a fresh one (old one expired)
        mgr.get_or_create("sess-1");
        let stats = mgr.inspect("sess-1").unwrap();
        assert_eq!(stats.entity_count, 0); // Fresh session
        assert_eq!(stats.message_count, 0);
    }

    #[test]
    fn test_session_manager_is_enabled() {
        let mgr = SessionManager::new(test_config());
        assert!(mgr.is_enabled());

        let mgr2 = SessionManager::new(SessionConfig {
            enabled: false,
            ..test_config()
        });
        assert!(!mgr2.is_enabled());
    }

    #[test]
    fn test_stats_categories_counted() {
        let mut ctx = SessionContext::new("s-1".into(), test_config());
        ctx.record_entities(
            &[
                make_entity("Alice", EntityCategory::Person),
                make_entity("Bob", EntityCategory::Person),
                make_entity("Acme", EntityCategory::Organization),
                make_entity("secret-key-123", EntityCategory::Secret),
            ],
            &[
                make_token("PERSON_1", EntityCategory::Person, 1),
                make_token("PERSON_2", EntityCategory::Person, 2),
                make_token("ORG_1", EntityCategory::Organization, 1),
                make_token("SECRET_1", EntityCategory::Secret, 1),
            ],
        );

        let stats = ctx.stats();
        assert_eq!(*stats.categories.get("Person").unwrap(), 2);
        assert_eq!(*stats.categories.get("Organization").unwrap(), 1);
        assert_eq!(*stats.categories.get("Secret").unwrap(), 1);
    }

    #[test]
    fn test_resolve_coreferences_empty_session() {
        let ctx = SessionContext::new("s-1".into(), test_config());
        let corefs = ctx.resolve_coreferences("He went to the company");
        assert!(corefs.is_empty()); // No entities yet
    }

    #[test]
    fn test_word_boundary_edge_cases() {
        // Start of string
        assert_eq!(find_word_boundary("He is here", "he"), Some(0));
        // End of string
        assert_eq!(find_word_boundary("it was he", "he"), Some(7));
        // With punctuation
        assert_eq!(find_word_boundary("he, she, they", "she"), Some(4));
        assert_eq!(find_word_boundary("(he) was there", "he"), Some(1));
        // Should not match inside words
        assert!(find_word_boundary("sheet", "he").is_none());
        assert!(find_word_boundary("ether", "he").is_none());
    }

    #[test]
    fn test_resolver_threshold() {
        let ctx = SessionContext::new("s-1".into(), test_config());
        assert!((ctx.resolver_threshold() - 0.80).abs() < f64::EPSILON);

        let ctx2 = SessionContext::new("s-2".into(), SessionConfig {
            session_threshold: 0.70,
            ..test_config()
        });
        assert!((ctx2.resolver_threshold() - 0.70).abs() < f64::EPSILON);
    }

    #[test]
    fn test_default_session_config() {
        let config = SessionConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.id_from, "header:x-session-id");
        assert_eq!(config.ttl_seconds, 1800);
        assert!(config.coreference);
        assert!(config.sensitivity_escalation);
        assert!((config.session_threshold - 0.80).abs() < f64::EPSILON);
    }

    #[test]
    fn test_dedup_coreferences_by_position() {
        let mut ctx = SessionContext::new("s-1".into(), test_config());

        // Add an entity named "The Company LLC" — org
        ctx.record_entities(
            &[make_entity("The Company LLC", EntityCategory::Organization)],
            &[make_token("ORG_1", EntityCategory::Organization, 1)],
        );

        // "the company" could match as definite article;
        // dedup should keep highest confidence
        let corefs = ctx.resolve_coreferences("the company is doing well");
        let at_zero: Vec<_> = corefs.iter().filter(|(e, _)| e.start == 0).collect();
        assert!(at_zero.len() <= 1); // Deduped
    }
}
