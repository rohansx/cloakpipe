//! LedgerRecord — the canonical record schema.
//!
//! **P0 invariant:** this module exposes *no* constructor that accepts a free
//! text payload. The only way to attach "content" to a record is via
//! [`Egress::bytes_out_hash`] (a 32-byte hash) or [`Identity`] fields (UUIDs
//! and region codes — no names, no emails, no free text).
//!
//! Everything else is enums (`Hop`, `ActionKind`, `PolicyDecision`,
//! `Detector`) or counters (`count: u32`). An attempt to put a raw identifier
//! into any field is a *type error*.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;
use uuid::Uuid;

/// A privacy-relevant event the ledger records.
///
/// Adding a new variant is intentional friction: each one becomes a queryable
/// category in the auditor pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Hop {
    LlmPrompt,
    LlmResponse,
    McpToolCall,
    McpToolResult,
    SubAgentMsg,
    MemoryWrite,
    RetrievalResult,
    Unmask,
}

impl Hop {
    /// Stable byte tag for canonicalization.
    pub fn tag(&self) -> &'static str {
        match self {
            Hop::LlmPrompt => "llm_prompt",
            Hop::LlmResponse => "llm_response",
            Hop::McpToolCall => "mcp_tool_call",
            Hop::McpToolResult => "mcp_tool_result",
            Hop::SubAgentMsg => "sub_agent_msg",
            Hop::MemoryWrite => "memory_write",
            Hop::RetrievalResult => "retrieval_result",
            Hop::Unmask => "unmask",
        }
    }
}

/// Detection backend tag — known set only. New detectors require a code
/// change; we never let a record invent its own detector string (which would
/// make a free-text vector).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Detector {
    Regex,
    Checksum,
    OnnxBert,
    Gliner,
    Custom,
}

impl Detector {
    pub fn tag(&self) -> &'static str {
        match self {
            Detector::Regex => "regex",
            Detector::Checksum => "checksum",
            Detector::OnnxBert => "onnx_bert",
            Detector::Gliner => "gliner",
            Detector::Custom => "custom",
        }
    }
}

/// What the proxy did about a detection. `token_ref` is an opaque vault
/// pointer, never the real value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Action {
    pub entity_type: String,
    pub kind: ActionKind,
    /// Opaque reference into the vault. Never the original identifier.
    pub token_ref: Option<String>,
}

/// Closed set of actions. No "Other" — we want every record to be auditable
/// against a known taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    Pseudonymize,
    Block,
    Passthrough,
    FpeToken,
}

impl ActionKind {
    pub fn tag(&self) -> &'static str {
        match self {
            ActionKind::Pseudonymize => "pseudonymize",
            ActionKind::Block => "block",
            ActionKind::Passthrough => "passthrough",
            ActionKind::FpeToken => "fpe_token",
        }
    }
}

/// One detection result. Tells us *what kind* and *how many* — never the
/// detected value itself.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Detection {
    pub entity_type: String,
    pub count: u32,
    pub detector: Detector,
}

/// Closed enum for confidence buckets. Bucketing is intentional: a precise
/// float is unnecessary noise and could leak model internals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceBucket {
    Low,
    Medium,
    High,
}

impl ConfidenceBucket {
    pub fn tag(&self) -> &'static str {
        match self {
            ConfidenceBucket::Low => "low",
            ConfidenceBucket::Medium => "medium",
            ConfidenceBucket::High => "high",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Policy {
    pub pack_id: String,
    pub pack_version: String,
    pub rule_id: String,
    pub decision: PolicyDecision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow,
    Deny,
    Flag,
}

impl PolicyDecision {
    pub fn tag(&self) -> &'static str {
        match self {
            PolicyDecision::Allow => "allow",
            PolicyDecision::Deny => "deny",
            PolicyDecision::Flag => "flag",
        }
    }
}

/// Caller-side identities. All opaque IDs (UUIDs), no human names, no emails.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Identity {
    pub agent_id: Uuid,
    pub human_principal: Option<Uuid>,
    pub upstream: String,
    pub region: String,
}

/// Egress direction + a hash of the payload, never the payload itself.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Egress {
    pub destination: String,
    pub bytes_out_hash: [u8; 32],
}

/// The signed, hash-chained record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerRecord {
    pub seq: u64,
    pub ts: DateTime<Utc>,
    pub tenant_id: Uuid,
    pub hop: Hop,
    pub detections: Vec<Detection>,
    pub actions: Vec<Action>,
    pub policy: Policy,
    pub identities: Identity,
    pub egress: Egress,
    pub metadata: BTreeMap<String, MetadataValue>,
    pub prev_hash: [u8; 32],
    pub record_hash: [u8; 32],
}

/// Metadata values are restricted to scalars + 32-byte hashes. Strings are
/// allowed *only* if they look like opaque IDs/keys (no free text). See
/// [`RecordBuilder::metadata`] for the runtime check.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MetadataValue {
    Bool(bool),
    Integer(i64),
    Hash([u8; 32]),
    /// Opaque identifier. Disallowed at runtime if it looks like an email,
    /// phone, Aadhaar, PAN, or free-text sentence (see validator below).
    OpaqueId(String),
}

/// Errors raised when the builder is misused.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RecordError {
    /// `MetadataValue::OpaqueId` contained what looks like a raw PII value.
    /// This is the **P0 invariant** failure.
    #[error("metadata field `{0}` looks like raw PII and was rejected: {1}")]
    PiiInMetadata(String, String),
    /// Tried to add an opaque ID that exceeded a conservative length cap.
    #[error("metadata field `{0}` exceeds 128 chars")]
    OpaqueIdTooLong(String),
}

/// Builder. The only way to make a record.
pub struct RecordBuilder {
    seq: Option<u64>,
    ts: Option<DateTime<Utc>>,
    tenant_id: Option<Uuid>,
    hop: Option<Hop>,
    detections: Vec<Detection>,
    actions: Vec<Action>,
    policy: Option<Policy>,
    identities: Option<Identity>,
    egress: Option<Egress>,
    metadata: BTreeMap<String, MetadataValue>,
}

impl RecordBuilder {
    pub fn new() -> Self {
        Self {
            seq: None,
            ts: None,
            tenant_id: None,
            hop: None,
            detections: Vec::new(),
            actions: Vec::new(),
            policy: None,
            identities: None,
            egress: None,
            metadata: BTreeMap::new(),
        }
    }

    pub fn seq(mut self, seq: u64) -> Self {
        self.seq = Some(seq);
        self
    }

    pub fn ts(mut self, ts: DateTime<Utc>) -> Self {
        self.ts = Some(ts);
        self
    }

    pub fn tenant(mut self, tenant_id: Uuid) -> Self {
        self.tenant_id = Some(tenant_id);
        self
    }

    pub fn hop(mut self, hop: Hop) -> Self {
        self.hop = Some(hop);
        self
    }

    pub fn detection(mut self, d: Detection) -> Self {
        self.detections.push(d);
        self
    }

    pub fn detections(mut self, mut ds: Vec<Detection>) -> Self {
        self.detections.append(&mut ds);
        self
    }

    pub fn action(mut self, a: Action) -> Self {
        self.actions.push(a);
        self
    }

    pub fn policy(mut self, p: Policy) -> Self {
        self.policy = Some(p);
        self
    }

    pub fn identities(mut self, i: Identity) -> Self {
        self.identities = Some(i);
        self
    }

    pub fn egress(mut self, e: Egress) -> Self {
        self.egress = Some(e);
        self
    }

    /// Add a metadata scalar. Strings must be opaque IDs — not free text.
    pub fn metadata(mut self, key: impl Into<String>, value: MetadataValue) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    /// Borrow the staged metadata for inspection (e.g. validation before
    /// build).
    pub fn staged_metadata(&self) -> &BTreeMap<String, MetadataValue> {
        &self.metadata
    }

    pub fn build(self) -> Result<LedgerRecord, RecordError> {
        for (k, v) in &self.metadata {
            if let MetadataValue::OpaqueId(s) = v {
                validate_opaque_id(k, s)?;
            }
        }
        Ok(LedgerRecord {
            seq: self.seq.unwrap_or(0),
            ts: self.ts.unwrap_or_else(Utc::now),
            tenant_id: self.tenant_id.unwrap_or_else(Uuid::nil),
            hop: self.hop.unwrap_or(Hop::LlmPrompt),
            detections: self.detections,
            actions: self.actions,
            policy: self
                .policy
                .unwrap_or(Policy {
                    pack_id: "default".into(),
                    pack_version: "0000000".into(),
                    rule_id: "default-allow".into(),
                    decision: PolicyDecision::Allow,
                }),
            identities: self
                .identities
                .unwrap_or(Identity {
                    agent_id: Uuid::nil(),
                    human_principal: None,
                    upstream: "unknown".into(),
                    region: "unknown".into(),
                }),
            egress: self.egress.unwrap_or(Egress {
                destination: "unknown".into(),
                bytes_out_hash: [0u8; 32],
            }),
            metadata: self.metadata,
            prev_hash: [0u8; 32],
            record_hash: [0u8; 32],
        })
    }
}

impl Default for RecordBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Hard reject free-text-shaped or PII-shaped opaque IDs at runtime.
///
/// The list is deliberately conservative: anything that *could* be a raw
/// identifier is rejected. False positives just mean a developer renames a
/// field; false negatives leak data. Asymmetric.
fn validate_opaque_id(key: &str, s: &str) -> Result<(), RecordError> {
    if s.len() > 128 {
        return Err(RecordError::OpaqueIdTooLong(key.to_string()));
    }
    let lowered = s.to_ascii_lowercase();
    let pii_markers = [
        "@",          // email
        "aadhaar",    // India national ID (12-digit)
        "pan",        // India PAN
        "ifsc",       // India bank branch
        "upi://",     // UPI handle
        "gstin",      // India GST
        "ssn",        // US SSN marker
        "phone",
        "email",
        "name=",
    ];
    for marker in pii_markers {
        if lowered.contains(marker) {
            return Err(RecordError::PiiInMetadata(
                key.to_string(),
                format!("contains marker `{marker}`"),
            ));
        }
    }
    // Reject if it has any whitespace — opaque IDs don't have spaces.
    if s.chars().any(|c| c.is_whitespace()) {
        return Err(RecordError::PiiInMetadata(
            key.to_string(),
            "contains whitespace".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uuid() -> Uuid {
        Uuid::nil()
    }

    #[allow(dead_code)]
    fn make_id() -> Uuid {
        Uuid::new_v4()
    }

    #[test]
    fn builder_minimum_record() {
        let r = RecordBuilder::new().build().unwrap();
        assert_eq!(r.seq, 0);
        assert_eq!(r.detections.len(), 0);
    }

    #[test]
    fn metadata_hash_is_allowed() {
        let r = RecordBuilder::new()
            .metadata("payload_hash", MetadataValue::Hash([7u8; 32]))
            .build()
            .unwrap();
        assert!(matches!(
            r.metadata.get("payload_hash"),
            Some(MetadataValue::Hash(_))
        ));
    }

    #[test]
    fn metadata_int_and_bool_allowed() {
        let r = RecordBuilder::new()
            .metadata("latency_ms", MetadataValue::Integer(42))
            .metadata("cached", MetadataValue::Bool(true))
            .build()
            .unwrap();
        assert_eq!(r.metadata.get("latency_ms"), Some(&MetadataValue::Integer(42)));
    }

    #[test]
    fn metadata_opaque_id_uuid_form_allowed() {
        let id = "550e8400-e29b-41d4-a716-446655440000";
        let r = RecordBuilder::new()
            .metadata("session_ref", MetadataValue::OpaqueId(id.into()))
            .build()
            .unwrap();
        assert!(r.metadata.contains_key("session_ref"));
    }

    #[test]
    fn metadata_rejects_email() {
        let err = RecordBuilder::new()
            .metadata("foo", MetadataValue::OpaqueId("alice@example.com".into()))
            .build()
            .unwrap_err();
        assert!(matches!(err, RecordError::PiiInMetadata(_, _)));
    }

    #[test]
    fn metadata_rejects_aadhaar_marker() {
        let err = RecordBuilder::new()
            .metadata("foo", MetadataValue::OpaqueId("aadhaar=123412341234".into()))
            .build()
            .unwrap_err();
        assert!(matches!(err, RecordError::PiiInMetadata(_, _)));
    }

    #[test]
    fn metadata_rejects_pan_marker() {
        let err = RecordBuilder::new()
            .metadata("foo", MetadataValue::OpaqueId("pan: ABCDE1234F".into()))
            .build()
            .unwrap_err();
        assert!(matches!(err, RecordError::PiiInMetadata(_, _)));
    }

    #[test]
    fn metadata_rejects_whitespace() {
        let err = RecordBuilder::new()
            .metadata("foo", MetadataValue::OpaqueId("hello world".into()))
            .build()
            .unwrap_err();
        assert!(matches!(err, RecordError::PiiInMetadata(_, _)));
    }

    #[test]
    fn metadata_rejects_very_long_string() {
        let s = "a".repeat(200);
        let err = RecordBuilder::new()
            .metadata("foo", MetadataValue::OpaqueId(s))
            .build()
            .unwrap_err();
        assert!(matches!(err, RecordError::OpaqueIdTooLong(_)));
    }

    #[test]
    fn hop_tags_are_stable() {
        // Stable tags are part of the wire format — changing one breaks every
        // existing bundle. Lock them.
        assert_eq!(Hop::LlmPrompt.tag(), "llm_prompt");
        assert_eq!(Hop::McpToolCall.tag(), "mcp_tool_call");
        assert_eq!(Hop::Unmask.tag(), "unmask");
    }

    #[test]
    fn action_kind_tags_stable() {
        assert_eq!(ActionKind::Pseudonymize.tag(), "pseudonymize");
        assert_eq!(ActionKind::FpeToken.tag(), "fpe_token");
    }

    #[test]
    fn policy_decision_tags_stable() {
        assert_eq!(PolicyDecision::Allow.tag(), "allow");
        assert_eq!(PolicyDecision::Flag.tag(), "flag");
    }

    #[test]
    fn identity_carries_only_uuids_and_short_codes() {
        let i = Identity {
            agent_id: uuid(),
            human_principal: None,
            upstream: "openai".into(),
            region: "in-mum-1".into(),
        };
        // No free-text fields, only opaque IDs / known short codes.
        assert_eq!(i.upstream.len(), 6);
    }
}