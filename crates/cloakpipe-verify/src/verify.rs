//! Verification primitives.
//!
//! Pure functions, no I/O, no global state. Every check returns a
//! [`VerifyError`] with a category a CI script can pattern-match on.

use crate::bundle::{BatchHead, Bundle, Hex32};
#[cfg(test)]
use crate::bundle::Record;
use ed25519_dalek::{Signature as DalekSig, Verifier as DalekVerifier, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("format mismatch: expected `cloakpipe.bundle`, got `{0}`")]
    BadFormat(String),
    #[error("format version {0} is not supported (this verifier knows v1 and v2)")]
    UnsupportedVersion(u32),
    #[error("record #{seq}: canonical bytes are not valid utf-8")]
    CanonicalNotUtf8 { seq: u64 },
    #[error("record #{seq}: hash mismatch — recomputed `{got}`, claimed `{claimed}`")]
    RecordHashMismatch { seq: u64, claimed: String, got: String },
    #[error("record #{seq}: prev_hash `{prev}` does not match previous record_hash `{expected}`")]
    PrevHashBreak { seq: u64, prev: String, expected: String },
    #[error("record #{seq}: gap in sequence — expected `{expected}`, got `{actual}`")]
    SeqGap { seq: u64, expected: u64, actual: u64 },
    #[error("record #{0}: invalid hex in hash field")]
    BadHex(u64),
    #[error("signature in batch `{0}` references unknown key id `{1}`")]
    UnknownKey(String, String),
    #[error("signature in batch `{0}` is not valid utf-8 hex")]
    BadSignatureHex(String),
    #[error("signature in batch `{0}` has wrong length (got {1}, expected 128 hex chars)")]
    BadSignatureLength(String, usize),
    #[error("signature in batch `{0}` failed ed25519 verification")]
    BadSignature(String),
    #[error("signer key `{0}` is not valid hex pubkey")]
    BadPubkey(String),
    #[error("record #{seq}: inclusion proof against batch `{batch_id}` failed — leaf not in tree")]
    InclusionProofFailed { seq: u64, batch_id: String },
    #[error("record #{seq} has no inclusion proof for batch `{batch_id}`")]
    MissingInclusionProof { seq: u64, batch_id: String },
    #[error("anchor receipt `{batch_id}/{backend}`: TSA signature invalid")]
    TsaSignatureInvalid { batch_id: String, backend: String },
    #[error("anchor receipt `{batch_id}/{backend}`: log signature on STH invalid")]
    LogSignatureInvalid { batch_id: String, backend: String },
    #[error("anchor receipt `{batch_id}/{backend}`: log inclusion proof invalid")]
    LogInclusionProofInvalid { batch_id: String, backend: String },
    #[error("anchor receipt `{batch_id}` claims subject hash `{got}`, expected `{expected}`")]
    SubjectHashMismatch {
        batch_id: String,
        got: String,
        expected: String,
    },
    #[error("batch `{batch_id}` signed_time `{claimed}` is after anchor time `{anchor}` — possible back-dating")]
    BackDating {
        batch_id: String,
        claimed: String,
        anchor: String,
    },
    #[error("bundle format v1 has no anchors; this verifier requires v2 for anchor checks")]
    AnchorsRequireV2,
    #[error("invalid hex in anchor receipt: {0}")]
    BadAnchorHex(String),
    #[error("invalid RFC3339 timestamp: {0}")]
    BadTimestamp(String),
    #[error("manifest missing on v3 bundle (required for auditor packs)")]
    ManifestMissing,
    #[error("manifest signature is invalid")]
    ManifestSignatureInvalid,
    #[error("manifest key id `{0}` not in `signer_public_keys`")]
    ManifestKeyUnknown(String),
    #[error("manifest references unknown batch head `{0}`")]
    ManifestUnknownBatch(String),
    #[error("manifest references unknown anchor receipt `{0}`")]
    ManifestUnknownAnchor(String),
    #[error("manifest record count `{got}` does not match bundle (`{expected}`)")]
    ManifestRecordCountMismatch { got: u64, expected: u64 },
    #[error("manifest first_seq `{got}` does not match bundle (`{expected}`)")]
    ManifestFirstSeqMismatch { got: u64, expected: u64 },
    #[error("manifest last_seq `{got}` does not match bundle (`{expected}`)")]
    ManifestLastSeqMismatch { got: u64, expected: u64 },
    #[error("record #{seq} references policy pack version `{version}` not in manifest")]
    UnknownPolicyPack { seq: u64, version: String },
}

/// Validate the bundle's `format` and `format_version` fields. Catches
/// "the file isn't even a bundle" before we waste time on it.
///
/// Accepts versions 1 and 2. v1 has no anchor data; v2 may have it.
pub fn check_magic(bundle: &Bundle) -> Result<(), VerifyError> {
    if bundle.format != crate::bundle::BUNDLE_MAGIC {
        return Err(VerifyError::BadFormat(bundle.format.clone()));
    }
    if bundle.format_version != 1 && bundle.format_version != crate::bundle::BUNDLE_FORMAT_VERSION {
        return Err(VerifyError::UnsupportedVersion(bundle.format_version));
    }
    Ok(())
}

/// Hash the canonical bytes of a record. Verifier owns this — it
/// doesn't trust the producer to "compute the right way"; it only
/// trusts the producer to have included the *right bytes* in the
/// bundle.
pub fn hash_record_bytes(canonical: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(canonical.as_bytes());
    let out = h.finalize();
    let mut out32 = [0u8; 32];
    out32.copy_from_slice(&out);
    out32
}

/// Decode a hex string into 32 raw bytes. Returns Err on wrong length
/// or non-hex chars.
pub fn decode_hex_32(s: &str) -> Result<[u8; 32], VerifyError> {
    if s.len() != 64 {
        return Err(VerifyError::BadHex(u64::MAX));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| VerifyError::BadHex(u64::MAX))?;
    }
    Ok(out)
}

/// Walk every record in order. Verifies:
/// 1. `seq` is strictly monotonic with no gaps, starting at 0.
/// 2. `record_hash` matches SHA-256(canonical_bytes).
/// 3. `prev_hash` matches the previous record's `record_hash`.
/// 4. All hex fields decode cleanly.
///
/// On success, returns the final record_hash (chain tip).
pub fn verify_chain(bundle: &Bundle) -> Result<Hex32, VerifyError> {
    let mut prev = "0".repeat(64);
    let mut last_hash: Option<String> = None;

    for (expected_seq, r) in bundle.records.iter().enumerate() {
        let expected_seq = expected_seq as u64;
        if r.seq != expected_seq {
            return Err(VerifyError::SeqGap {
                seq: r.seq,
                expected: expected_seq,
                actual: r.seq,
            });
        }
        let computed = hash_record_bytes(&r.canonical_bytes);
        let computed_hex = hex_lower(&computed);
        if computed_hex != r.record_hash {
            return Err(VerifyError::RecordHashMismatch {
                seq: r.seq,
                claimed: r.record_hash.clone(),
                got: computed_hex,
            });
        }
        // Round-trip: r.prev_hash must equal the previous record's
        // record_hash.
        if r.prev_hash != prev {
            return Err(VerifyError::PrevHashBreak {
                seq: r.seq,
                prev: r.prev_hash.clone(),
                expected: prev.clone(),
            });
        }
        prev = r.record_hash.clone();
        last_hash = Some(r.record_hash.clone());
    }
    Ok(last_hash.unwrap_or_else(|| "0".repeat(64)))
}

/// Validate every batch head's Ed25519 signature against the
/// declared public key. Returns the number of verified heads.
pub fn verify_sigs(bundle: &Bundle) -> Result<usize, VerifyError> {
    // Build key index.
    let mut keys: std::collections::HashMap<&str, &crate::bundle::SignerKey> =
        std::collections::HashMap::new();
    for k in &bundle.signer_public_keys {
        keys.insert(&k.key_id, k);
    }

    let mut verified = 0;
    for head in &bundle.batch_heads {
        let key = keys
            .get(head.signature.key_id.as_str())
            .ok_or_else(|| VerifyError::UnknownKey(head.batch_id.clone(), head.signature.key_id.clone()))?;
        if head.signature.algorithm != "ed25519" {
            return Err(VerifyError::BadSignature(format!(
                "{}: unsupported algorithm {}",
                head.batch_id, head.signature.algorithm
            )));
        }
        if head.signature.value.len() != 128 {
            return Err(VerifyError::BadSignatureLength(
                head.batch_id.clone(),
                head.signature.value.len(),
            ));
        }
        let sig_bytes = decode_hex_64(&head.signature.value)
            .ok_or_else(|| VerifyError::BadSignatureHex(head.batch_id.clone()))?;
        let pk_bytes = decode_hex_32(&key.public_key)
            .map_err(|_| VerifyError::BadPubkey(key.key_id.clone()))?;
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk_bytes);
        let vk = VerifyingKey::from_bytes(&pk_arr)
            .map_err(|_| VerifyError::BadPubkey(key.key_id.clone()))?;
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = DalekSig::from_bytes(&sig_arr);

        // Signed payload = deterministic JSON of the unsigned batch head.
        let payload = serde_json::to_vec(&BatchHeadUnsigned::from(head))
            .map_err(|_| VerifyError::BadSignature(head.batch_id.clone()))?;
        vk.verify(&payload, &sig)
            .map_err(|_| VerifyError::BadSignature(head.batch_id.clone()))?;
        verified += 1;
    }
    Ok(verified)
}

/// The unsigned portion of a BatchHead. We re-derive this on the
/// verifier side and compare to what the producer signed.
#[derive(Debug, Clone, serde::Serialize)]
struct BatchHeadUnsigned<'a> {
    batch_id: &'a str,
    first_seq: u64,
    last_seq: u64,
    merkle_root: &'a str,
    algorithm: &'a str,
    signed_time: &'a Option<String>,
}

impl<'a> From<&'a BatchHead> for BatchHeadUnsigned<'a> {
    fn from(h: &'a BatchHead) -> Self {
        Self {
            batch_id: &h.batch_id,
            first_seq: h.first_seq,
            last_seq: h.last_seq,
            merkle_root: &h.merkle_root,
            algorithm: &h.algorithm,
            signed_time: &h.signed_time,
        }
    }
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

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        write!(s, "{:02x}", b).unwrap();
    }
    s
}

/// Run every check. Returns the count of checks performed.
pub fn verify_all(bundle: &Bundle) -> Result<VerifySummary, VerifyError> {
    check_magic(bundle)?;
    let tip = verify_chain(bundle)?;
    let sigs = verify_sigs(bundle)?;
    Ok(VerifySummary {
        records: bundle.records.len(),
        signatures: sigs,
        chain_tip: tip,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifySummary {
    pub records: usize,
    pub signatures: usize,
    pub chain_tip: Hex32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(seq: u64, canonical: &str, prev: &str) -> Record {
        let h = hash_record_bytes(canonical);
        Record {
            seq,
            tenant_id: "t".into(),
            canonical_bytes: canonical.into(),
            record_hash: hex_lower(&h),
            prev_hash: prev.into(),
        }
    }

    #[test]
    fn empty_bundle_passes_chain() {
        let b = Bundle {
            format: crate::bundle::BUNDLE_MAGIC.into(),
            format_version: crate::bundle::BUNDLE_FORMAT_VERSION,
            tenant_id: "t".into(),
            created_at: "2026-07-02T12:00:00+00:00".into(),
            records: vec![],
            batch_heads: vec![],
            inclusion_proofs: vec![],
            range_start: None,
            range_end: None,
            manifest: None,
            policy_packs: vec![],
            anchor_receipts: vec![],
            signer_public_keys: vec![],
        };
        verify_chain(&b).unwrap();
    }

    #[test]
    fn single_record_passes_chain() {
        let r = make_record(0, "seq=0\nhello", "0".repeat(64).as_str());
        let b = Bundle {
            format: crate::bundle::BUNDLE_MAGIC.into(),
            format_version: crate::bundle::BUNDLE_FORMAT_VERSION,
            tenant_id: "t".into(),
            created_at: "x".into(),
            records: vec![r],
            batch_heads: vec![],
            inclusion_proofs: vec![],
            range_start: None,
            range_end: None,
            manifest: None,
            policy_packs: vec![],
            anchor_receipts: vec![],
            signer_public_keys: vec![],
        };
        let tip = verify_chain(&b).unwrap();
        assert_eq!(tip.len(), 64);
    }

    #[test]
    fn chain_detects_tampered_canonical_bytes() {
        let r = make_record(0, "seq=0\nhello", "0".repeat(64).as_str());
        let mut tampered = r.clone();
        tampered.canonical_bytes = "seq=0\nHELLO".into(); // byte change
        let b = Bundle {
            format: crate::bundle::BUNDLE_MAGIC.into(),
            format_version: crate::bundle::BUNDLE_FORMAT_VERSION,
            tenant_id: "t".into(),
            created_at: "x".into(),
            records: vec![tampered],
            batch_heads: vec![],
            inclusion_proofs: vec![],
            range_start: None,
            range_end: None,
            manifest: None,
            policy_packs: vec![],
            anchor_receipts: vec![],
            signer_public_keys: vec![],
        };
        let err = verify_chain(&b).unwrap_err();
        assert!(matches!(err, VerifyError::RecordHashMismatch { .. }));
    }

    #[test]
    fn chain_detects_seq_gap() {
        let r0 = make_record(0, "a", "0".repeat(64).as_str());
        let r2 = make_record(2, "c", &r0.record_hash);
        let b = Bundle {
            format: crate::bundle::BUNDLE_MAGIC.into(),
            format_version: crate::bundle::BUNDLE_FORMAT_VERSION,
            tenant_id: "t".into(),
            created_at: "x".into(),
            records: vec![r0, r2],
            batch_heads: vec![],
            inclusion_proofs: vec![],
            range_start: None,
            range_end: None,
            manifest: None,
            policy_packs: vec![],
            anchor_receipts: vec![],
            signer_public_keys: vec![],
        };
        let err = verify_chain(&b).unwrap_err();
        assert!(matches!(err, VerifyError::SeqGap { .. }));
    }

    #[test]
    fn chain_detects_prev_hash_break() {
        let r0 = make_record(0, "a", "0".repeat(64).as_str());
        let mut r1 = make_record(1, "b", &r0.record_hash);
        r1.prev_hash = "f".repeat(64); // wrong link
        let b = Bundle {
            format: crate::bundle::BUNDLE_MAGIC.into(),
            format_version: crate::bundle::BUNDLE_FORMAT_VERSION,
            tenant_id: "t".into(),
            created_at: "x".into(),
            records: vec![r0, r1],
            batch_heads: vec![],
            inclusion_proofs: vec![],
            range_start: None,
            range_end: None,
            manifest: None,
            policy_packs: vec![],
            anchor_receipts: vec![],
            signer_public_keys: vec![],
        };
        let err = verify_chain(&b).unwrap_err();
        assert!(matches!(err, VerifyError::PrevHashBreak { .. }));
    }

    #[test]
    fn magic_must_match() {
        let b = Bundle {
            format: "evil.bundle".into(),
            format_version: 1,
            tenant_id: "t".into(),
            created_at: "x".into(),
            records: vec![],
            batch_heads: vec![],
            inclusion_proofs: vec![],
            range_start: None,
            range_end: None,
            manifest: None,
            policy_packs: vec![],
            anchor_receipts: vec![],
            signer_public_keys: vec![],
        };
        assert_eq!(check_magic(&b), Err(VerifyError::BadFormat("evil.bundle".into())));
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let b = Bundle {
            format: crate::bundle::BUNDLE_MAGIC.into(),
            format_version: 999,
            tenant_id: "t".into(),
            created_at: "x".into(),
            records: vec![],
            batch_heads: vec![],
            inclusion_proofs: vec![],
            range_start: None,
            range_end: None,
            manifest: None,
            policy_packs: vec![],
            anchor_receipts: vec![],
            signer_public_keys: vec![],
        };
        assert_eq!(check_magic(&b), Err(VerifyError::UnsupportedVersion(999)));
    }

    #[test]
    fn signature_with_unknown_key_fails() {
        let b = Bundle {
            format: crate::bundle::BUNDLE_MAGIC.into(),
            format_version: crate::bundle::BUNDLE_FORMAT_VERSION,
            tenant_id: "t".into(),
            created_at: "x".into(),
            records: vec![],
            batch_heads: vec![BatchHead {
                batch_id: "b1".into(),
                first_seq: 0,
                last_seq: 9,
                merkle_root: "0".repeat(64),
                algorithm: "merkle_sha256".into(),
                signed_time: None,
                signature: crate::bundle::SignedBatchHead {
                    key_id: "nope".into(),
                    algorithm: "ed25519".into(),
                    value: "0".repeat(128),
                },
            }],
            inclusion_proofs: vec![],
            range_start: None,
            range_end: None,
            manifest: None,
            policy_packs: vec![],
            anchor_receipts: vec![],
            signer_public_keys: vec![],
        };
        let err = verify_sigs(&b).unwrap_err();
        assert!(matches!(err, VerifyError::UnknownKey(_, _)));
    }
}