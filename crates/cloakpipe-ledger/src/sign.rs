//! Signing — Ed25519 default, pluggable for ML-DSA-65 (ADR-004).
//!
//! Signing produces a [`SignedRecord`] that pairs a [`LedgerRecord`] with
//! a [`Signature`]. The verifier only needs the public key, the record,
//! and the signature.

use ed25519_dalek::{Signature as DalekSig, Signer as DalekSigner, SigningKey, VerifyingKey};
use thiserror::Error;

use crate::canonical::canonicalize;
use crate::record::LedgerRecord;

#[derive(Debug, Error, PartialEq)]
pub enum SignError {
    #[error("ed25519 signing failed: {0}")]
    Ed25519(String),
    #[error("ed25519 verification failed")]
    VerificationFailed,
}

/// A signature. Today only Ed25519; ML-DSA-65 will plug in via the same
/// enum with a new variant. Algorithms are explicitly enumerated — we never
/// accept an arbitrary algorithm string from a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signature {
    Ed25519 { pk: [u8; 32], sig: [u8; 64] },
}

impl Signature {
    pub fn algorithm(&self) -> &'static str {
        match self {
            Signature::Ed25519 { .. } => "ed25519",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SignedRecord {
    pub record: LedgerRecord,
    pub signature: Signature,
}

/// Pluggable signer trait. The default impl is [`Ed25519Signer`].
pub trait Signer: Send + Sync {
    fn sign(&self, record: &LedgerRecord) -> Signature;
    /// Sign an arbitrary byte payload. Used for manifest signing
    /// and other cross-cutting signatures that aren't tied to a
    /// record.
    fn sign_bytes(&self, payload: &[u8]) -> [u8; 64];
    fn public_key(&self) -> [u8; 32];
    fn algorithm(&self) -> &'static str;
}

pub struct Ed25519Signer {
    key: SigningKey,
}

impl Ed25519Signer {
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        let mut csprng = OsRng;
        let key = SigningKey::generate(&mut csprng);
        Self { key }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(bytes),
        }
    }
}

impl Signer for Ed25519Signer {
    fn sign(&self, record: &LedgerRecord) -> Signature {
        let bytes = canonicalize(record);
        let sig = self.key.sign(&bytes);
        let sig_bytes = sig.to_bytes();
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let pk = self.key.verifying_key().to_bytes();
        Signature::Ed25519 { pk, sig: sig_arr }
    }

    fn sign_bytes(&self, payload: &[u8]) -> [u8; 64] {
        let sig = self.key.sign(payload);
        let sig_bytes = sig.to_bytes();
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        sig_arr
    }

    fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    fn algorithm(&self) -> &'static str {
        "ed25519"
    }
}

/// Verify a signature against a record. Pure function — no I/O.
pub fn verify(record: &LedgerRecord, sig: &Signature) -> Result<(), SignError> {
    match sig {
        Signature::Ed25519 { pk, sig: sig_bytes } => {
            let vk = VerifyingKey::from_bytes(pk)
                .map_err(|e| SignError::Ed25519(e.to_string()))?;
            let dalek_sig = DalekSig::from_bytes(sig_bytes);
            let bytes = canonicalize(record);
            vk.verify_strict(&bytes, &dalek_sig)
                .map_err(|_| SignError::VerificationFailed)?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::*;
    use uuid::Uuid;

    fn record(seq: u64) -> LedgerRecord {
        RecordBuilder::new()
            .seq(seq)
            .tenant(Uuid::nil())
            .hop(Hop::LlmPrompt)
            .build()
            .unwrap()
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let s = Ed25519Signer::generate();
        let r = record(0);
        let sig = s.sign(&r);
        verify(&r, &sig).unwrap();
    }

    #[test]
    fn verify_rejects_tampered_record() {
        let s = Ed25519Signer::generate();
        let mut r = record(0);
        let sig = s.sign(&r);
        r.detections.push(Detection {
            entity_type: "PAN".into(),
            count: 1,
            detector: Detector::Regex,
        });
        assert_eq!(verify(&r, &sig), Err(SignError::VerificationFailed));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let s1 = Ed25519Signer::generate();
        let s2 = Ed25519Signer::generate();
        let r = record(0);
        let mut sig = s1.sign(&r);
        let Signature::Ed25519 { pk, .. } = &mut sig;
        *pk = s2.public_key();
        assert_eq!(verify(&r, &sig), Err(SignError::VerificationFailed));
    }

    #[test]
    fn algorithm_string_is_stable() {
        let s = Ed25519Signer::generate();
        let r = record(0);
        let sig = s.sign(&r);
        assert_eq!(sig.algorithm(), "ed25519");
    }

    #[test]
    fn deterministic_key_from_bytes() {
        let s1 = Ed25519Signer::from_bytes(&[7u8; 32]);
        let s2 = Ed25519Signer::from_bytes(&[7u8; 32]);
        assert_eq!(s1.public_key(), s2.public_key());
    }
}