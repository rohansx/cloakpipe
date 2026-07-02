//! Hash-chain logic.
//!
//! `record_hash = SHA-256(canonical(record) with prev_hash wired in)`.
//! `prev_hash` for `seq == 0` is [`GENESIS_HASH`] (32 zero bytes).

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::canonical::canonicalize;
use crate::record::LedgerRecord;

/// The hash of the record before the first one. All zeros is the simplest
/// choice and the standard convention.
pub const GENESIS_HASH: [u8; 32] = [0u8; 32];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChainLinkError {
    #[error("record's seq does not match expected {expected}, got {actual}")]
    SeqMismatch { expected: u64, actual: u64 },
    #[error("record's prev_hash does not match predecessor record_hash")]
    PrevHashMismatch,
}

/// Computes and writes `prev_hash` + `record_hash` into a mutable record.
///
/// Returns the new `record_hash`.
pub fn link_and_hash(prev: &[u8; 32], record: &mut LedgerRecord) -> [u8; 32] {
    record.prev_hash = *prev;
    record.record_hash = compute_hash(record);
    record.record_hash
}

/// Computes the record hash without mutating.
pub fn compute_hash(record: &LedgerRecord) -> [u8; 32] {
    let bytes = canonicalize(record);
    let mut h = Sha256::new();
    h.update(&bytes);
    let out = h.finalize();
    let mut out32 = [0u8; 32];
    out32.copy_from_slice(&out);
    out32
}

/// Validates a chain of records in order. Returns the final record_hash on
/// success.
pub fn verify_chain(records: &[LedgerRecord]) -> Result<[u8; 32], ChainLinkError> {
    let mut prev = GENESIS_HASH;
    for (expected_seq, r) in records.iter().enumerate() {
        let expected_seq = expected_seq as u64;
        if r.seq != expected_seq {
            return Err(ChainLinkError::SeqMismatch {
                expected: expected_seq,
                actual: r.seq,
            });
        }
        if r.prev_hash != prev {
            return Err(ChainLinkError::PrevHashMismatch);
        }
        let h = compute_hash(r);
        if h != r.record_hash {
            return Err(ChainLinkError::PrevHashMismatch);
        }
        prev = h;
    }
    Ok(prev)
}

/// Public alias used by the lib root.
pub fn hash_record(r: &LedgerRecord) -> [u8; 32] {
    compute_hash(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::*;
    use uuid::Uuid;

    fn make(seq: u64) -> LedgerRecord {
        RecordBuilder::new()
            .seq(seq)
            .tenant(Uuid::nil())
            .hop(Hop::LlmPrompt)
            .build()
            .unwrap()
    }

    #[test]
    fn first_record_prev_hash_is_genesis() {
        let r = make(0);
        assert_eq!(r.prev_hash, GENESIS_HASH);
    }

    #[test]
    fn linking_produces_chain() {
        let mut r0 = make(0);
        let h0 = link_and_hash(&GENESIS_HASH, &mut r0);
        assert_eq!(r0.prev_hash, GENESIS_HASH);
        assert_eq!(r0.record_hash, h0);

        let mut r1 = make(1);
        let h1 = link_and_hash(&h0, &mut r1);
        assert_eq!(r1.prev_hash, h0);
        assert_ne!(h0, h1);
    }

    #[test]
    fn verify_chain_accepts_valid_chain() {
        let mut rs = Vec::new();
        let mut prev = GENESIS_HASH;
        for i in 0..5 {
            let mut r = make(i);
            link_and_hash(&prev, &mut r);
            prev = r.record_hash;
            rs.push(r);
        }
        let tail = verify_chain(&rs).unwrap();
        assert_eq!(tail, prev);
    }

    #[test]
    fn verify_chain_rejects_gap() {
        let mut rs = Vec::new();
        let mut prev = GENESIS_HASH;
        for i in 0..3 {
            let mut r = make(i);
            link_and_hash(&prev, &mut r);
            prev = r.record_hash;
            rs.push(r);
        }
        // Skip seq 3; append seq 4.
        let mut r4 = make(4);
        link_and_hash(&prev, &mut r4);
        rs.push(r4);
        let err = verify_chain(&rs).unwrap_err();
        assert_eq!(err, ChainLinkError::SeqMismatch { expected: 3, actual: 4 });
    }

    #[test]
    fn verify_chain_rejects_tamper() {
        let mut rs = Vec::new();
        let mut prev = GENESIS_HASH;
        for i in 0..3 {
            let mut r = make(i);
            link_and_hash(&prev, &mut r);
            prev = r.record_hash;
            rs.push(r);
        }
        // Tamper: change one byte of an intermediate record's record_hash.
        rs[1].record_hash[0] ^= 0x01;
        // That makes record_hash mismatch prev_hash of rs[2] AND mismatch
        // its own canonical bytes.
        assert_eq!(verify_chain(&rs).unwrap_err(), ChainLinkError::PrevHashMismatch);
    }

    #[test]
    fn verify_chain_rejects_wrong_prev_link() {
        let mut rs = Vec::new();
        let mut prev = GENESIS_HASH;
        for i in 0..3 {
            let mut r = make(i);
            link_and_hash(&prev, &mut r);
            prev = r.record_hash;
            rs.push(r);
        }
        // Re-link rs[2] but with a stale prev — its hash no longer matches.
        let mut stale = [0u8; 32];
        stale[31] = 0x42;
        link_and_hash(&stale, &mut rs[2]);
        assert_eq!(verify_chain(&rs).unwrap_err(), ChainLinkError::PrevHashMismatch);
    }
}