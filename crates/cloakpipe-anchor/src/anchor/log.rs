//! Transparency-log anchor backend.
//!
//! Phase 1 implementation: an in-process log that emulates the
//! shape of Rekor v2 / Trillian-Tessera (an append-only Merkle tree
//! of submitted hashes, signed tree heads).
//!
//! ## Why this matters
//!
//! The verifier must be able to confirm an inclusion proof *offline*
//! against a signed tree head. The wire format we ship (a Merkle
//! root + Ed25519 signature over the STH + sibling hashes for
//! inclusion) is exactly what production logs expose. Swapping in a
//! real Rekor v2 endpoint is a matter of replacing the in-process
//! state with an HTTP client; the receipt shape doesn't change.
//!
//! ## Honest disclosure
//!
//! This is **not** a Rekor v2 client. Rekor v2 has its own
//! protobuf-defined submission/inclusion APIs, which we have not
//! implemented here. The shapes are compatible at the level a
//! future integration would target.

use crate::anchor::AnchorError;
use crate::batch::SignedBatchHead;
use crate::merkle::{leaf_hash, MerkleTree};
use crate::receipt::{
    subject_hash_for, AnchorReceipt, BackendKind, LogProofStep, ReceiptEnvelope, SignedTreeHead,
};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use std::sync::Mutex;

/// The in-process log. Append-only.
pub struct LogBackend {
    key: SigningKey,
    log_id: String,
    state: Mutex<LogState>,
}

struct LogState {
    leaves: Vec<[u8; 32]>,
    next_index: u64,
}

impl LogBackend {
    pub fn new(log_id: impl Into<String>) -> Self {
        let mut csprng = OsRng;
        Self {
            key: SigningKey::generate(&mut csprng),
            log_id: log_id.into(),
            state: Mutex::new(LogState {
                leaves: Vec::new(),
                next_index: 0,
            }),
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        
        self.key.verifying_key().to_bytes()
    }

    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        
        self.key.verifying_key()
    }

    /// The current STH. Builds a Merkle tree over all leaves and
    /// signs the root + size + time.
    pub fn current_sth(&self) -> Result<SignedTreeHead, AnchorError> {
        let state = self.state.lock().unwrap();
        let tree = MerkleTree::from_hashed_leaves(state.leaves.clone());
        let root = tree.root();
        let size = state.leaves.len() as u64;
        let claimed_time = chrono::Utc::now()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let pubkey = self.public_key();
        let payload = SignedTreeHead::signed_payload(&self.log_id, size, &root, &claimed_time);
        let sig = self.key.sign(&payload);
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig.to_bytes());
        Ok(SignedTreeHead::build(
            self.log_id.clone(),
            size,
            root,
            claimed_time,
            sig_arr,
            pubkey,
        ))
    }

    /// Submit a batch head. Returns a receipt with an inclusion proof
    /// for the new leaf.
    pub fn submit(&self, head: &SignedBatchHead) -> Result<AnchorReceipt, AnchorError> {
        let subject = subject_hash_for(head);
        let mut state = self.state.lock().unwrap();
        let leaf = leaf_hash(&subject);
        let index = state.next_index;
        state.leaves.push(leaf);
        state.next_index += 1;
        let tree = MerkleTree::from_hashed_leaves(state.leaves.clone());
        let proof = tree.inclusion_proof(index as usize);
        let claimed_time = chrono::Utc::now()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let root = tree.root();
        let size = state.leaves.len() as u64;
        let pubkey = self.public_key();
        let payload = SignedTreeHead::signed_payload(&self.log_id, size, &root, &claimed_time);
        let sig = self.key.sign(&payload);
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig.to_bytes());
        let sth = SignedTreeHead::build(
            self.log_id.clone(),
            size,
            root,
            claimed_time.clone(),
            sig_arr,
            pubkey,
        );

        let inclusion_proof: Vec<LogProofStep> = proof
            .steps
            .into_iter()
            .map(|s| LogProofStep::from_raw(s.position, s.hash))
            .collect();

        let envelope = ReceiptEnvelope {
            subject_hash: hex_lower(&subject),
            batch_id: head.batch_id.clone(),
            claimed_time: sth.claimed_time.clone(),
            backend: BackendKind::TransparencyLog,
            backend_ref: format!("{}:{}", self.log_id, index),
        };
        Ok(AnchorReceipt::Log {
            envelope,
            log_index: index,
            signed_tree_head: sth,
            inclusion_proof,
        })
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

// Required for the public re-exports to compile even if unused.
#[allow(dead_code)]
fn _force_use() {}