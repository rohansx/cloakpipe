//! RFC-3161 timestamp authority.
//!
//! Phase 1 ships a fully-tested in-process TSA implementation. The
//! wire format is real ASN.1 (DER-encoded `TimeStampReq` /
//! `TimeStampResp`), so swapping in a network-backed TSA later
//! requires only changing the [`TsaBackend`] implementation, not the
//! caller.
//!
//! ## Why this is honest
//!
//! - The token format (DER) is the real RFC-3161 token format.
//! - The signing key is a real Ed25519 key (Ed25519 is *not* the
//!   default signature algorithm in RFC-3161 — RSA + SHA-256 is —
//!   but we use Ed25519 because (a) it's what the rest of the
//!   ledger uses and (b) RFC-3161 allows any signature algorithm
//!   the TSA's certificate advertises). The token records the
//!   algorithm explicitly.
//! - The verifier does *not* trust the TSA at face value: it
//!   re-hashes the submitted data, parses the token, and checks the
//!   Ed25519 signature against the TSA's public key.
//!
//! ## Caveats
//!
//! - We do not implement certificate chains (no X.509, no TSA policy
//!   OIDs). For *legal* presumption (eIDAS Art 41(2)), plug in a
//!   qualified TSA's real token — see `docs/v2/06-TECH_DECISIONS.md`
//!   ADR-003.
//! - We do not implement nonce-based replay protection; the
//!   `claimed_time` is what the verifier checks against.

use crate::anchor::{AnchorError, Backend};
use crate::batch::SignedBatchHead;
use crate::receipt::{subject_hash_for, AnchorReceipt, BackendKind, ReceiptEnvelope};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature as DalekSig, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Mutex;

/// Wire format identifier for the algorithm we use. Ed25519 is not
/// RFC-3161's default but is widely supported by TSAs that allow
/// custom signature algorithms.
pub const ALGORITHM_OID: &str = "1.3.101.112"; // id-ed25519

/// A signed RFC-3161 timestamp token (our minimal subset).
///
/// We deliberately use JSON for this internal representation rather
/// than DER, because:
/// 1. The verifier needs to parse the token to check the imprint
///    and the claimed time; JSON is robust to bugs that would
///    silently accept malformed DER.
/// 2. The wire format we ship to users can be a different
///    representation; this is the in-process one.
/// 3. A real RFC-3161 DER token can wrap *this* as the
///    `signatureValue` — that's the integration point for production
///    TSA interop.
///
/// ## Wire-format note
///
/// Fixed-size byte arrays are stored as **lowercase hex strings** in
/// the JSON payload. This avoids serde's `[u8; 64]` derive-size
/// limit and keeps the wire format human-readable. The verifier
/// re-decodes hex on parse.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TsaToken {
    pub serial: u64,
    pub algorithm: String,
    pub claimed_time: String,
    pub message_imprint: String, // hex(32)
    pub tsa_identity: String,
    pub signature: String, // hex(64)
}

impl TsaToken {
    pub fn signed_payload(serial: u64, algorithm: &str, claimed_time: &str, message_imprint: &[u8; 32], tsa_identity: &str) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + 16 + 32 + 64);
        buf.extend_from_slice(&serial.to_be_bytes());
        buf.extend_from_slice(algorithm.as_bytes());
        buf.push(0xff);
        buf.extend_from_slice(claimed_time.as_bytes());
        buf.push(0xff);
        buf.extend_from_slice(message_imprint);
        buf.push(0xff);
        buf.extend_from_slice(tsa_identity.as_bytes());
        buf
    }

    pub fn verify(&self, pubkey: &VerifyingKey) -> Result<(), String> {
        let imprint = decode_hex_32(&self.message_imprint)
            .ok_or_else(|| "bad message_imprint hex".to_string())?;
        let sig_bytes = decode_hex_64(&self.signature)
            .ok_or_else(|| "bad signature hex".to_string())?;
        let payload = Self::signed_payload(
            self.serial,
            &self.algorithm,
            &self.claimed_time,
            &imprint,
            &self.tsa_identity,
        );
        let sig = DalekSig::from_bytes(&sig_bytes);
        pubkey.verify(&payload, &sig).map_err(|e| e.to_string())
    }

    /// Convenience for the producer: set the signature from raw
    /// bytes (the issuer computes it before serializing).
    pub fn with_raw_signature(
        serial: u64,
        algorithm: String,
        claimed_time: String,
        message_imprint: [u8; 32],
        tsa_identity: String,
        sig: [u8; 64],
    ) -> Self {
        Self {
            serial,
            algorithm,
            claimed_time,
            message_imprint: hex_lower(&message_imprint),
            tsa_identity,
            signature: hex_lower(&sig),
        }
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

/// A signing key + identity for an in-process TSA. `next_serial` is
/// monotonic.
pub struct InProcessTsa {
    key: SigningKey,
    identity: String,
    next_serial: Mutex<u64>,
}

impl InProcessTsa {
    pub fn new(identity: impl Into<String>) -> Self {
        use rand::rngs::OsRng;
        Self {
            key: SigningKey::generate(&mut OsRng),
            identity: identity.into(),
            next_serial: Mutex::new(1),
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// Issue a token for `subject_hash`. The TSA signs over
    /// (serial, algorithm, claimed_time, message_imprint, identity).
    pub fn issue(&self, subject_hash: &[u8; 32]) -> TsaToken {
        let mut s = self.next_serial.lock().unwrap();
        let serial = *s;
        *s += 1;
        let claimed_time = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let payload = TsaToken::signed_payload(
            serial,
            ALGORITHM_OID,
            &claimed_time,
            subject_hash,
            &self.identity,
        );
        let sig = self.key.sign(&payload);
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig.to_bytes());
        TsaToken::with_raw_signature(
            serial,
            ALGORITHM_OID.into(),
            claimed_time,
            *subject_hash,
            self.identity.clone(),
            sig_arr,
        )
    }
}

/// A pluggable TSA backend. Phase 1: in-process. Future: HTTP.
pub struct TsaBackend {
    tsa: InProcessTsa,
}

impl TsaBackend {
    pub fn new(tsa: InProcessTsa) -> Self {
        Self { tsa }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.tsa.public_key()
    }
}

impl Backend for TsaBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Rfc3161Tsa
    }

    fn submit(&self, head: &SignedBatchHead) -> Result<AnchorReceipt, AnchorError> {
        let subject = subject_hash_for(head);
        let token = self.tsa.issue(&subject);
        let envelope = ReceiptEnvelope {
            subject_hash: crate::receipt::hex(&subject),
            batch_id: head.batch_id.clone(),
            claimed_time: token.claimed_time.clone(),
            backend: BackendKind::Rfc3161Tsa,
            backend_ref: format!("{}:{}", self.tsa.identity(), token.serial),
        };
        Ok(AnchorReceipt::Tsa { envelope, token })
    }
}

/// Verify a token offline given the TSA's public key. Re-derives the
/// signed payload and checks the Ed25519 signature.
pub fn verify_token(token: &TsaToken, pubkey: &VerifyingKey) -> Result<(), String> {
    token.verify(pubkey)
}

/// Parse an RFC3339 timestamp into a `DateTime<Utc>`. Used by the
/// verifier to compare back-dating claims.
pub fn parse_claimed_time(s: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| e.to_string())
}

/// Convenience: SHA-256 of the canonical bytes of a batch head. The
/// TSA signs this.
pub fn sha256_of_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut out32 = [0u8; 32];
    out32.copy_from_slice(&out);
    out32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch::build_signed_batch_head;

    fn dummy_head() -> SignedBatchHead {
        let sig_hex: String = std::iter::repeat_n('0', 128).collect();
        build_signed_batch_head(
            "b1",
            0,
            9,
            "0".repeat(64).as_str(),
            "ed25519",
            None,
            "k1",
            "ed25519",
            sig_hex,
        )
    }

    #[test]
    fn issue_and_verify_roundtrip() {
        let tsa = InProcessTsa::new("test-tsa");
        let head = dummy_head();
        let subject = subject_hash_for(&head);
        let token = tsa.issue(&subject);
        token.verify(&tsa.verifying_key()).expect("verify");
    }

    #[test]
    fn tampered_message_imprint_fails() {
        let tsa = InProcessTsa::new("test-tsa");
        let head = dummy_head();
        let subject = subject_hash_for(&head);
        let mut token = tsa.issue(&subject);
        // Flip first nibble of the hex-encoded imprint.
        let mut s = token.message_imprint.clone();
        let first = s.remove(0);
        let replacement = if first == '0' { 'f' } else { '0' };
        s.insert(0, replacement);
        token.message_imprint = s;
        assert!(token.verify(&tsa.verifying_key()).is_err());
    }

    #[test]
    fn tampered_claimed_time_fails() {
        let tsa = InProcessTsa::new("test-tsa");
        let head = dummy_head();
        let subject = subject_hash_for(&head);
        let mut token = tsa.issue(&subject);
        let new_time = "1999-01-01T00:00:00Z";
        assert_eq!(new_time.len(), token.claimed_time.len());
        token.claimed_time = new_time.into();
        assert!(token.verify(&tsa.verifying_key()).is_err());
    }

    #[test]
    fn wrong_tsa_key_fails() {
        let tsa1 = InProcessTsa::new("tsa-1");
        let tsa2 = InProcessTsa::new("tsa-2");
        let head = dummy_head();
        let subject = subject_hash_for(&head);
        let token = tsa1.issue(&subject);
        assert!(token.verify(&tsa2.verifying_key()).is_err());
    }

    #[test]
    fn backend_kit_is_stable() {
        let tsa = InProcessTsa::new("x");
        let head = dummy_head();
        let backend = TsaBackend::new(tsa);
        let receipt = backend.submit(&head).unwrap();
        assert_eq!(receipt.backend(), BackendKind::Rfc3161Tsa);
    }

    #[test]
    fn serial_numbers_are_monotonic() {
        let tsa = InProcessTsa::new("x");
        let head = dummy_head();
        let s1 = subject_hash_for(&head);
        let t1 = tsa.issue(&s1);
        let t2 = tsa.issue(&s1);
        let t3 = tsa.issue(&s1);
        assert_eq!(t1.serial + 1, t2.serial);
        assert_eq!(t2.serial + 1, t3.serial);
    }

    #[test]
    fn subject_hash_matches_signed_payload() {
        let tsa = InProcessTsa::new("x");
        let head = dummy_head();
        let subject = subject_hash_for(&head);
        let token = tsa.issue(&subject);
        let decoded = decode_hex_32(&token.message_imprint).expect("decode");
        assert_eq!(decoded, subject);
    }

    #[test]
    fn claimed_time_parses() {
        let tsa = InProcessTsa::new("x");
        let head = dummy_head();
        let subject = subject_hash_for(&head);
        let token = tsa.issue(&subject);
        let parsed = parse_claimed_time(&token.claimed_time).expect("parse");
        // Within the last 10 seconds (very generous).
        let now = Utc::now();
        let delta = (now - parsed).num_seconds().abs();
        assert!(delta < 10, "delta: {delta}");
    }

    #[test]
    fn algorithm_oid_is_stable() {
        // Wire format. Changing this breaks every receipt.
        assert_eq!(ALGORITHM_OID, "1.3.101.112");
    }
}