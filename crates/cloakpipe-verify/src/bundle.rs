//! Bundle format — the wire schema an evidence bundle travels in.
//!
//! ## Why this lives in `cloakpipe-verify` (not `cloakpipe-ledger`)
//!
//! The verifier is **standalone**: a hostile third party can clone
//! *only* this crate and verify a bundle without trusting any other
//! CloakPipe component. The producer (`cloakpipe-ledger`) writes to
//! this format; the verifier reads it.
//!
//! If we put these types in `cloakpipe-ledger` and imported them
//! here, the verifier would carry an implicit trust link back to the
//! producer. That's the opposite of what we want. The verifier
//! should define its own types and *require byte-level
//! compatibility* with the producer's serialization — which we
//! enforce with tests, not by sharing code.
//!
//! ## Format
//!
//! ```text
//! Bundle {
//!   format: "cloakpipe.bundle"
//!   format_version: 1
//!   tenant_id: <uuid>
//!   created_at: <RFC3339>
//!   records: [Record]                // canonical bytes included
//!   batch_heads: [BatchHead]         // optional (Phase 1 records-only)
//!   signer_public_keys: {kid: hex}   // keys referenced by records
//! }
//! ```
//!
//! A `Record` carries **the canonical bytes the producer hashed** plus
//! the producer's `record_hash`. The verifier re-canonicalizes the
//! record fields and compares; any mismatch = tamper.

use serde::{Deserialize, Serialize};

/// Magic string at the start of every bundle file. A hostile bundle
/// that doesn't have this gets rejected.
pub const BUNDLE_MAGIC: &str = "cloakpipe.bundle";

/// Current format version. Bump on any breaking change.
pub const BUNDLE_FORMAT_VERSION: u32 = 1;

/// A tenant identifier. Lowercase hyphenated UUID.
pub type TenantId = String;

/// An agent identifier (opaque to verifier).
pub type AgentId = String;

/// A 32-byte SHA-256 digest, hex-encoded (64 chars).
pub type Hex32 = String;

/// A 64-byte Ed25519 signature, hex-encoded (128 chars).
pub type Hex64 = String;

/// A 32-byte Ed25519 public key, hex-encoded (64 chars).
pub type HexPubkey = String;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bundle {
    pub format: String,
    pub format_version: u32,
    pub tenant_id: TenantId,
    pub created_at: String,
    pub records: Vec<Record>,
    #[serde(default)]
    pub batch_heads: Vec<BatchHead>,
    #[serde(default)]
    pub signer_public_keys: Vec<SignerKey>,
}

/// A single ledger record.
///
/// `canonical_bytes` is the bytes the producer fed into SHA-256. The
/// verifier recomputes the hash from `canonical_bytes` and compares
/// it to `record_hash` — proving both that the record's fields
/// weren't tampered with AND that the producer's hashing was
/// deterministic.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Record {
    pub seq: u64,
    pub tenant_id: TenantId,
    pub canonical_bytes: String,
    pub record_hash: Hex32,
    pub prev_hash: Hex32,
}

/// One batch head (anchor submission). Phase 1 (M2) signs only batch
/// heads — per ADR-003, per-record signing would balloon the bundle.
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

/// The actual signature payload over a batch head.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_and_version_are_stable() {
        assert_eq!(BUNDLE_MAGIC, "cloakpipe.bundle");
        assert_eq!(BUNDLE_FORMAT_VERSION, 1);
    }

    #[test]
    fn bundle_round_trips() {
        let b = Bundle {
            format: BUNDLE_MAGIC.into(),
            format_version: BUNDLE_FORMAT_VERSION,
            tenant_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            created_at: "2026-07-02T12:00:00+00:00".into(),
            records: vec![Record {
                seq: 0,
                tenant_id: "550e8400-e29b-41d4-a716-446655440000".into(),
                canonical_bytes: "seq=0\n...".into(),
                record_hash: "0".repeat(64),
                prev_hash: "0".repeat(64),
            }],
            batch_heads: vec![],
            signer_public_keys: vec![],
        };
        let j = serde_json::to_string(&b).unwrap();
        let back: Bundle = serde_json::from_str(&j).unwrap();
        assert_eq!(back, b);
    }
}