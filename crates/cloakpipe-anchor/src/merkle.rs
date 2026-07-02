//! Merkle tree over record hashes.
//!
//! Pure SHA-256, no external deps. Domain-separated (the leaf hash
//! prefixes leaves with `0x00`, the node hash prefixes internal
//! concatenations with `0x01`) so an attacker can't present a leaf
//! as an internal node.
//!
//! Inclusion proofs: for a tree of `n` leaves, a proof for leaf `i`
//! is the list of sibling hashes needed to reconstruct the root from
//! `leaves[i]`. Length `O(log n)`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain tag for leaf nodes.
const LEAF_PREFIX: u8 = 0x00;
/// Domain tag for internal nodes.
const NODE_PREFIX: u8 = 0x01;

/// SHA-256 of a leaf: `H(0x00 || value)`.
pub fn leaf_hash(value: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([LEAF_PREFIX]);
    h.update(value);
    let out = h.finalize();
    let mut out32 = [0u8; 32];
    out32.copy_from_slice(&out);
    out32
}

/// SHA-256 of an internal node: `H(0x01 || left || right)`.
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([NODE_PREFIX]);
    h.update(left);
    h.update(right);
    let out = h.finalize();
    let mut out32 = [0u8; 32];
    out32.copy_from_slice(&out);
    out32
}

/// A sibling-hash step in an inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofStep {
    /// The sibling's position: `Left` means the sibling is the left
    /// child of our parent (we're the right child); `Right` means the
    /// sibling is the right child (we're the left child).
    pub position: ProofPosition,
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProofPosition {
    Left,
    Right,
}

/// Inclusion proof for one leaf in a tree of `total_leaves`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    pub leaf_index: usize,
    pub total_leaves: usize,
    pub steps: Vec<ProofStep>,
}

/// A Merkle tree. Construction is `O(n)`; root computation is `O(n)`;
/// inclusion proof generation is `O(log n)`; verification is `O(log n)`.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// `levels[0]` is the leaves; `levels[levels.len()-1]` is the root.
    levels: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    /// Build a tree from raw leaf values. Each value is hashed once
    /// with the leaf-prefix before insertion.
    pub fn from_leaves(leaves: &[Vec<u8>]) -> Self {
        let level0: Vec<[u8; 32]> = leaves.iter().map(|v| leaf_hash(v)).collect();
        Self::from_hashed_leaves(level0)
    }

    /// Build a tree from pre-hashed leaves (the input is already
    /// hashed — useful when the leaves are existing record hashes).
    /// If `hashed_leaves` is non-empty, we still apply the leaf-prefix
    /// domain tag during internal hashing, because tree construction
    /// uses `node_hash`. But if the leaves are already
    /// domain-separated `leaf_hash` outputs, the caller should pass
    /// them through `from_leaves` to get the right behavior. Here we
    /// do NOT re-apply the leaf prefix — the input is taken as-is.
    pub fn from_hashed_leaves(hashed_leaves: Vec<[u8; 32]>) -> Self {
        if hashed_leaves.is_empty() {
            // Empty tree: a single zero hash. A bundle with zero
            // records has a defined root (it must, otherwise the
            // verifier can't reason about it).
            return Self {
                levels: vec![vec![[0u8; 32]]],
            };
        }
        let mut levels = vec![hashed_leaves];
        while levels.last().unwrap().len() > 1 {
            let prev = levels.last().unwrap();
            let mut next = Vec::with_capacity(prev.len().div_ceil(2));
            let mut i = 0;
            while i < prev.len() {
                let left = prev[i];
                let right = if i + 1 < prev.len() { prev[i + 1] } else { left };
                next.push(node_hash(&left, &right));
                i += 2;
            }
            levels.push(next);
        }
        Self { levels }
    }

    pub fn root(&self) -> [u8; 32] {
        self.levels.last().unwrap()[0]
    }

    pub fn leaf_count(&self) -> usize {
        self.levels[0].len()
    }

    /// Build an inclusion proof for `index`. Panics if index is out
    /// of range. The proof is `O(log n)`.
    pub fn inclusion_proof(&self, index: usize) -> InclusionProof {
        let total = self.leaf_count();
        assert!(index < total, "leaf index {index} out of range {total}");
        let mut steps = Vec::new();
        let mut idx = index;
        for level in 0..self.levels.len() - 1 {
            let cur = &self.levels[level];
            let sibling_idx = if idx.is_multiple_of(2) { idx + 1 } else { idx - 1 };
            let sibling = if sibling_idx < cur.len() {
                cur[sibling_idx]
            } else {
                // Odd leaf count: the last leaf has no sibling at
                // this level and is duplicated upward by the tree
                // builder. The "sibling" is the leaf itself.
                cur[idx]
            };
            let position = if idx.is_multiple_of(2) {
                ProofPosition::Right
            } else {
                ProofPosition::Left
            };
            steps.push(ProofStep { position, hash: sibling });
            idx /= 2;
        }
        InclusionProof {
            leaf_index: index,
            total_leaves: total,
            steps,
        }
    }
}

/// Verify an inclusion proof against a known root. `leaf` is the
/// original (un-hashed) value; the verifier re-applies the leaf
/// prefix.
pub fn verify_inclusion(root: &[u8; 32], leaf: &[u8], proof: &InclusionProof) -> bool {
    let mut cur = leaf_hash(leaf);
    for step in &proof.steps {
        cur = match step.position {
            ProofPosition::Left => node_hash(&step.hash, &cur),
            ProofPosition::Right => node_hash(&cur, &step.hash),
        };
    }
    &cur == root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8; 32]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn empty_tree_has_zero_root() {
        let t = MerkleTree::from_leaves(&[]);
        assert_eq!(t.root(), [0u8; 32]);
    }

    #[test]
    fn single_leaf_root_is_leaf_hash() {
        let t = MerkleTree::from_leaves(&[b"only".to_vec()]);
        assert_eq!(t.root(), leaf_hash(b"only"));
    }

    #[test]
    fn two_leaf_root_is_node_hash() {
        let t = MerkleTree::from_leaves(&[b"a".to_vec(), b"b".to_vec()]);
        let l0 = leaf_hash(b"a");
        let l1 = leaf_hash(b"b");
        assert_eq!(t.root(), node_hash(&l0, &l1));
    }

    #[test]
    fn root_changes_when_leaf_changes() {
        let t1 = MerkleTree::from_leaves(&[b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
        let t2 = MerkleTree::from_leaves(&[b"a".to_vec(), b"X".to_vec(), b"c".to_vec()]);
        assert_ne!(t1.root(), t2.root());
    }

    #[test]
    fn inclusion_proof_verifies_for_every_leaf() {
        let leaves: Vec<Vec<u8>> = (0..16).map(|i| format!("leaf-{i}").into_bytes()).collect();
        let t = MerkleTree::from_leaves(&leaves);
        let root = t.root();
        for (i, leaf) in leaves.iter().enumerate() {
            let p = t.inclusion_proof(i);
            assert!(
                verify_inclusion(&root, leaf, &p),
                "proof failed for leaf {i}"
            );
        }
    }

    #[test]
    fn inclusion_proof_rejects_wrong_leaf() {
        let leaves: Vec<Vec<u8>> = (0..4).map(|i| format!("leaf-{i}").into_bytes()).collect();
        let t = MerkleTree::from_leaves(&leaves);
        let root = t.root();
        let p = t.inclusion_proof(2);
        // Wrong leaf value should fail.
        assert!(!verify_inclusion(&root, b"wrong", &p));
    }

    #[test]
    fn inclusion_proof_rejects_tampered_step() {
        let leaves: Vec<Vec<u8>> = (0..4).map(|i| format!("leaf-{i}").into_bytes()).collect();
        let t = MerkleTree::from_leaves(&leaves);
        let root = t.root();
        let mut p = t.inclusion_proof(0);
        if let Some(s) = p.steps.first_mut() {
            s.hash[0] ^= 0xff;
        }
        assert!(!verify_inclusion(&root, &leaves[0], &p));
    }

    #[test]
    fn domain_separation_blocks_leaf_as_node() {
        // A leaf hash and an internal hash collide only if their
        // prefixes were ignored. Verify they're distinct.
        let l = leaf_hash(b"x");
        let n = node_hash(&leaf_hash(b"a"), &leaf_hash(b"b"));
        assert_ne!(l, n);
    }

    #[test]
    fn handles_odd_leaf_counts() {
        let leaves: Vec<Vec<u8>> = (0..5).map(|i| format!("L{i}").into_bytes()).collect();
        let t = MerkleTree::from_leaves(&leaves);
        let root = t.root();
        for (i, leaf) in leaves.iter().enumerate() {
            let p = t.inclusion_proof(i);
            assert!(verify_inclusion(&root, leaf, &p), "leaf {i}");
        }
    }

    #[test]
    fn proof_length_is_log_n() {
        let n = 1024;
        let leaves: Vec<Vec<u8>> = (0..n).map(|i| format!("L{i}").into_bytes()).collect();
        let t = MerkleTree::from_leaves(&leaves);
        for i in [0, 7, 511, 1023] {
            let p = t.inclusion_proof(i);
            // log2(1024) = 10 levels of proof steps.
            assert_eq!(p.steps.len(), 10, "leaf {i}: proof len {}", p.steps.len());
        }
    }

    #[test]
    fn hex_helper() {
        // Smoke test the helper used in other test files.
        assert_eq!(hex(&[0u8; 32]).len(), 64);
    }
}