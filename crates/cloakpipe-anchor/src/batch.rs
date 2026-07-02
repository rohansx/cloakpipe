//! Signed batch head (anchor subject).
//!
//! Mirrored from `cloakpipe-verify::bundle::BatchHead` with one
//! change: this struct is what the anchor backend hashes and signs
//! over (the canonical byte form). The verifier reads it from the
//! bundle and re-hashes.
//!
//! ## Why mirrored (not shared)
//!
//! The verifier is standalone — it must not import this crate. The
//! producer (which is in `cloakpipe-ledger`) imports both sides and
//! bridges them; the anchor backend accepts this shape because the
//! producer hands it a serialized batch head (JSON bytes). The
//! verifier independently defines its own types. Round-trip
//! compatibility is enforced by [`subject_hash_for`] computing the
//! SHA-256 of `serde_json::to_vec(self)` — which both sides must
//! agree on.

use serde::{Deserialize, Serialize};

/// One batch head. `signature` is over the *unsigned* fields
/// (everything else in this struct), serialized as JSON. The
/// signature value is hex-encoded in the wire format.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedBatchHead {
    pub batch_id: String,
    pub key_id: String,
    pub algorithm: String,
    pub first_seq: u64,
    pub last_seq: u64,
    pub merkle_root: String,
    pub signed_time: Option<String>,
    pub signature: SignedBatchHeadSig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedBatchHeadSig {
    pub value: String, // hex(64)
}

/// The unsigned portion of a batch head. The producer signs this.
#[derive(Debug, Clone, Serialize)]
pub struct BatchHeadUnsigned<'a> {
    pub batch_id: &'a str,
    pub key_id: &'a str,
    pub algorithm: &'a str,
    pub first_seq: u64,
    pub last_seq: u64,
    pub merkle_root: &'a str,
    pub signed_time: &'a Option<String>,
}

impl<'a> From<&'a SignedBatchHead> for BatchHeadUnsigned<'a> {
    fn from(h: &'a SignedBatchHead) -> Self {
        Self {
            batch_id: &h.batch_id,
            key_id: &h.key_id,
            algorithm: &h.algorithm,
            first_seq: h.first_seq,
            last_seq: h.last_seq,
            merkle_root: &h.merkle_root,
            signed_time: &h.signed_time,
        }
    }
}

/// Convenience: build a `SignedBatchHead` from its unsigned parts and
/// a signature value (hex-encoded).
pub fn build_signed_batch_head(
    batch_id: impl Into<String>,
    key_id: impl Into<String>,
    algorithm: impl Into<String>,
    first_seq: u64,
    last_seq: u64,
    merkle_root: impl Into<String>,
    signed_time: Option<String>,
    signature_hex: impl Into<String>,
) -> SignedBatchHead {
    SignedBatchHead {
        batch_id: batch_id.into(),
        key_id: key_id.into(),
        algorithm: algorithm.into(),
        first_seq,
        last_seq,
        merkle_root: merkle_root.into(),
        signed_time,
        signature: SignedBatchHeadSig {
            value: signature_hex.into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_round_trip_json() {
        let sig_hex: String = std::iter::repeat('a').take(128).collect();
        let h = build_signed_batch_head(
            "b1",
            "k1",
            "ed25519",
            0,
            9,
            "0".repeat(64).as_str(),
            None,
            sig_hex,
        );
        let j = serde_json::to_string(&h).unwrap();
        let back: SignedBatchHead = serde_json::from_str(&j).unwrap();
        assert_eq!(h, back);
    }

    #[test]
    fn unsigned_view_excludes_signature() {
        let sig_hex: String = std::iter::repeat('7').take(128).collect();
        let h = build_signed_batch_head(
            "b1",
            "k1",
            "ed25519",
            0,
            9,
            "0".repeat(64).as_str(),
            None,
            sig_hex,
        );
        let u = BatchHeadUnsigned::from(&h);
        let j = serde_json::to_string(&u).unwrap();
        assert!(!j.contains("signature"));
        assert!(j.contains("\"batch_id\":\"b1\""));
    }
}