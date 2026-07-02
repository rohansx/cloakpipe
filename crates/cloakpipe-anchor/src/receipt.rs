//! Anchor receipts — the wire format returned by an anchor backend.
//!
//! A receipt is what proves a batch head was anchored at-or-before
//! a given time. Three shapes today:
//!
//! - TSA receipt: an RFC-3161-style timestamp token over the batch
//!   head's canonical bytes. The TSA's Ed25519 signature is the
//!   receipt's authority.
//! - Log receipt: a signed tree head (STH) from a transparency log,
//!   plus an inclusion proof linking the subject hash to the STH's
//!   Merkle root. The log's Ed25519 signature on the STH is the
//!   receipt's authority.
//!
//! The [`AnchorReceipt`] enum tags which kind we got, so the
//! verifier can dispatch to the right verifier.
//!
//! All receipts are verified *offline* given the right public key
//! material. The verifier never has to talk to the anchor.

use crate::anchor::tsa::TsaToken;
use crate::batch::SignedBatchHead;
use crate::merkle::ProofPosition;
use ed25519_dalek::{Signature as DalekSig, Verifier as DalekVerifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A signed tree head (STH) — the log's signed commitment to a
/// specific Merkle root at a specific size.
///
/// ## Wire format
///
/// Hash and signature fields are stored as **lowercase hex strings**
/// in the JSON wire format (avoids serde's `[u8; 64]` derive-size
/// limit and keeps the format human-readable). The verifier
/// re-decodes hex on parse.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedTreeHead {
    pub log_id: String,
    pub tree_size: u64,
    pub root_hash: String, // hex(32)
    pub claimed_time: String,
    pub signature: String, // hex(64)
    pub pubkey: String,    // hex(32)
}

impl SignedTreeHead {
    pub fn signed_payload(
        log_id: &str,
        tree_size: u64,
        root_hash: &[u8; 32],
        claimed_time: &str,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64 + 32);
        buf.extend_from_slice(log_id.as_bytes());
        buf.push(0xff);
        buf.extend_from_slice(&tree_size.to_be_bytes());
        buf.push(0xff);
        buf.extend_from_slice(root_hash);
        buf.push(0xff);
        buf.extend_from_slice(claimed_time.as_bytes());
        buf
    }

    pub fn verify(&self) -> Result<(), String> {
        let pk = decode_hex_32(&self.pubkey)
            .ok_or_else(|| "bad pubkey hex".to_string())?;
        let sig_bytes = decode_hex_64(&self.signature)
            .ok_or_else(|| "bad signature hex".to_string())?;
        let root = decode_hex_32(&self.root_hash)
            .ok_or_else(|| "bad root_hash hex".to_string())?;
        let payload = Self::signed_payload(
            &self.log_id,
            self.tree_size,
            &root,
            &self.claimed_time,
        );
        let vk = VerifyingKey::from_bytes(&pk).map_err(|e| e.to_string())?;
        let sig = DalekSig::from_bytes(&sig_bytes);
        vk.verify(&payload, &sig).map_err(|e| e.to_string())
    }

    /// Convenience constructor for the producer.
    pub fn build(
        log_id: impl Into<String>,
        tree_size: u64,
        root_hash: [u8; 32],
        claimed_time: impl Into<String>,
        sig: [u8; 64],
        pubkey: [u8; 32],
    ) -> Self {
        Self {
            log_id: log_id.into(),
            tree_size,
            root_hash: hex_lower(&root_hash),
            claimed_time: claimed_time.into(),
            signature: hex_lower(&sig),
            pubkey: hex_lower(&pubkey),
        }
    }
}

/// One step in a log inclusion proof. The hash is hex-encoded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogProofStep {
    pub position: ProofPosition,
    pub hash: String, // hex(32)
}

impl LogProofStep {
    pub fn from_raw(position: ProofPosition, hash: [u8; 32]) -> Self {
        Self {
            position,
            hash: hex_lower(&hash),
        }
    }

    pub fn hash_bytes(&self) -> Option<[u8; 32]> {
        decode_hex_32(&self.hash)
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

fn decode_hex_64(s: &str) -> Option<[u8; 64]> {
    if s.len() != 128 {
        return None;
    }
    let mut out = [0u8; 64];
    for i in 0..64 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    /// RFC-3161 timestamp authority (TSA), plain or qualified.
    Rfc3161Tsa,
    /// Generic transparency-log inclusion proof (Rekor v2 /
    /// Trillian-Tessera shape).
    TransparencyLog,
}

impl BackendKind {
    pub fn tag(&self) -> &'static str {
        match self {
            BackendKind::Rfc3161Tsa => "rfc3161_tsa",
            BackendKind::TransparencyLog => "transparency_log",
        }
    }
}

/// What every anchor receipt carries in common: the hash of the
/// thing it anchors, the wall-clock time it was anchored at, and the
/// backend kind.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptEnvelope {
    /// SHA-256 of the canonical bytes of the batch head being
    /// anchored. Hex-encoded.
    pub subject_hash: String,
    /// The batch_id being anchored.
    pub batch_id: String,
    /// The wall-clock time the anchor backend claims it saw the
    /// submission. Format: RFC3339 UTC.
    pub claimed_time: String,
    /// The backend kind.
    pub backend: BackendKind,
    /// A backend-specific identifier — TSA's serial number, log's
    /// STH index, etc. — useful for audit trails.
    pub backend_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AnchorReceipt {
    Tsa {
        envelope: ReceiptEnvelope,
        token: TsaToken,
    },
    Log {
        envelope: ReceiptEnvelope,
        log_index: u64,
        signed_tree_head: SignedTreeHead,
        inclusion_proof: Vec<LogProofStep>,
    },
}

impl AnchorReceipt {
    pub fn envelope(&self) -> &ReceiptEnvelope {
        match self {
            AnchorReceipt::Tsa { envelope, .. } => envelope,
            AnchorReceipt::Log { envelope, .. } => envelope,
        }
    }

    pub fn backend(&self) -> BackendKind {
        self.envelope().backend
    }

    /// SHA-256 of the batch head's canonical bytes (hex). The anchor
    /// backend computes this at submit time.
    pub fn subject_hash_hex(&self) -> &str {
        &self.envelope().subject_hash
    }

    pub fn batch_id(&self) -> &str {
        &self.envelope().batch_id
    }
}

/// Compute the canonical subject hash for a batch head. Returns raw
/// bytes; the producer hex-encodes before placing in the receipt.
pub fn subject_hash_for(head: &SignedBatchHead) -> [u8; 32] {
    let bytes = serde_json::to_vec(head).expect("SignedBatchHead serializes");
    let mut h = Sha256::new();
    h.update(&bytes);
    let out = h.finalize();
    let mut out32 = [0u8; 32];
    out32.copy_from_slice(&out);
    out32
}

/// Convenience: hex-encode a SHA-256 hash.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        write!(s, "{:02x}", b).unwrap();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_kind_tags_are_stable() {
        assert_eq!(BackendKind::Rfc3161Tsa.tag(), "rfc3161_tsa");
        assert_eq!(BackendKind::TransparencyLog.tag(), "transparency_log");
    }
}