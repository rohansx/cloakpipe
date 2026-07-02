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

/// Current format version.
///
/// History:
/// - v1: records + batch heads + signatures (M2)
/// - v2: + Merkle inclusion proofs per record + anchor receipts (M3)
/// - v3: + signed manifest, policy pack refs, date range, signed-tree-
///   head index (M4 — auditor pack)
pub const BUNDLE_FORMAT_VERSION: u32 = 3;

/// The version that introduced Merkle proofs and anchor receipts.
/// Bundles with version < 2 cannot have these fields; the verifier
/// accepts them but skips Merkle/anchor checks with a clear warning.
pub const MIN_BUNDLE_VERSION_FOR_ANCHORS: u32 = 2;

/// The version that introduced the signed manifest. v3+ bundles must
/// have a [`Manifest`]; v2 bundles may be promoted to v3 by re-
/// running `export` with `with_manifest = true`.
pub const MIN_BUNDLE_VERSION_FOR_MANIFEST: u32 = 3;

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
    /// Inclusive lower bound on `record.ts` (RFC3339). Optional in
    /// v2; required in v3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range_start: Option<String>,
    /// Exclusive upper bound on `record.ts`. Optional in v2; required
    /// in v3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range_end: Option<String>,
    pub records: Vec<Record>,
    /// Per-record Merkle inclusion proofs, indexed by record seq.
    /// If a record has no proof, `bundle_inclusion_proofs[seq]` is
    /// `None`.
    #[serde(default)]
    pub inclusion_proofs: Vec<Option<InclusionProofRef>>,
    #[serde(default)]
    pub batch_heads: Vec<BatchHead>,
    #[serde(default)]
    pub signer_public_keys: Vec<SignerKey>,
    /// Anchor receipts attached to the bundle. Each receipt is bound
    /// to a specific batch head via [`AnchorReceipt::batch_id`].
    /// Receipts are independently verifiable offline.
    #[serde(default)]
    pub anchor_receipts: Vec<AnchorReceiptRef>,
    /// Signed manifest. Required in v3+. v2 bundles that don't have
    /// one get accepted but the verifier skips manifest checks with a
    /// warning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<Manifest>,
    /// Active policy pack versions (git-shas) for the bundle's
    /// date range. The verifier checks that every record's
    /// `policy.pack_version` appears in this list. v3+ only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_packs: Vec<PolicyPackRef>,
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

/// One batch head (anchor submission). M3 adds the signed-time claim
/// (an RFC3339 timestamp the operator claims the batch was sealed at)
/// plus Merkle root (the root of the Merkle tree built over record
/// hashes). The signed payload covers all of these.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchHead {
    pub batch_id: String,
    pub first_seq: u64,
    pub last_seq: u64,
    pub merkle_root: Hex32,
    pub algorithm: String,
    /// Operator-claimed wall-clock seal time (RFC3339 UTC). The
    /// signed payload includes this. If an anchor receipt's claimed
    /// time is *before* this, the operator's claim is consistent with
    /// the anchor; if *after*, the seal time may be back-dated.
    pub signed_time: Option<String>,
    pub signature: SignedBatchHead,
}

/// One step of a Merkle inclusion proof.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofStepRef {
    /// `left` means the sibling is the left child (we are the right
    /// child); `right` means we are the left child.
    pub position: String,
    pub hash: Hex32,
}

/// Inclusion proof for one record in one batch. The verifier
/// reconstructs the Merkle root from `leaf_value` (the record's
/// canonical bytes) plus these steps and compares to
/// `batch_head.merkle_root`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InclusionProofRef {
    pub batch_id: String,
    pub leaf_index: u64,
    pub total_leaves: u64,
    pub steps: Vec<ProofStepRef>,
}

/// Anchor receipt reference (mirrored from `cloakpipe-anchor` types).
///
/// Two variants:
/// A reference to an active policy pack. `pack_version` is the git
/// sha of the pack at the time it was active for the bundle's
/// range. The producer MUST include every `policy.pack_version`
/// that appears in any record inside the bundle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyPackRef {
    pub pack_id: String,
    pub pack_version: String, // git sha
    /// When this version became active (RFC3339 UTC).
    pub active_from: String,
    /// When this version was superseded (RFC3339 UTC). `None` for
    /// the currently-active version.
    pub active_until: Option<String>,
}

/// The signed manifest. The signature is over the deterministic
/// JSON of `manifest_body` (everything except `signature`).
///
/// The manifest binds the bundle together: it enumerates the
/// record-seq range, the batch heads in scope, the anchor receipts
/// referenced, and the active policy packs. Tampering with any of
/// these without re-signing the manifest breaks verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub bundle_id: String,
    pub range_start: String,
    pub range_end: String,
    pub record_count: u64,
    pub first_seq: u64,
    pub last_seq: u64,
    pub batch_head_ids: Vec<String>,
    pub anchor_receipt_refs: Vec<String>, // e.g. "tsa:1:42", "log:abc:7"
    pub policy_pack_versions: Vec<String>, // git shas
    pub operator: String, // key_id of the signer
    pub created_at: String,
    pub signature: ManifestSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestSignature {
    pub key_id: String,
    pub algorithm: String,
    pub value: String, // hex(64)
}

/// Anchor receipt reference (mirrored from `cloakpipe-anchor` types).
///
/// Two variants:
/// - `tsa`: an RFC-3161 timestamp token over the batch head's
///   canonical bytes. Verifier checks the TSA signature.
/// - `log`: an inclusion proof + signed-tree-head from a transparency
///   log. Verifier checks both the log signature on the STH and the
///   inclusion proof linking the subject hash to the STH.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AnchorReceiptRef {
    Tsa {
        batch_id: String,
        subject_hash: Hex32,
        claimed_time: String,
        backend_ref: String,
        /// Hex-encoded DER blob of the RFC-3161 timestamp token.
        token_der: String,
        /// Hex-encoded Ed25519 public key of the TSA (so the verifier
        /// can check the token's signature offline).
        tsa_pubkey: String,
    },
    Log {
        batch_id: String,
        subject_hash: Hex32,
        claimed_time: String,
        log_index: u64,
        /// Hex-encoded signed-tree-head bytes.
        sth_bytes: String,
        /// Hex-encoded inclusion proof (sibling hashes, left/right
        /// tagged) linking subject_hash to sth_bytes' root.
        inclusion_proof: Vec<ProofStepRef>,
        /// Hex-encoded Ed25519 public key of the log.
        log_pubkey: String,
    },
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
        assert_eq!(BUNDLE_FORMAT_VERSION, 3);
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
            inclusion_proofs: vec![None],
            batch_heads: vec![],
            signer_public_keys: vec![],
            range_start: None,
            range_end: None,
            manifest: None,
            policy_packs: vec![],
            anchor_receipts: vec![],
        };
        let j = serde_json::to_string(&b).unwrap();
        let back: Bundle = serde_json::from_str(&j).unwrap();
        assert_eq!(back, b);
    }
}