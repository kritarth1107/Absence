//! Membership and non-membership proofs for Sparse Merkle Trees
//!
//! A membership proof demonstrates that a key exists in the tree.
//! A non-membership (absence) proof demonstrates that a key does NOT exist.
//!
//! Both proofs consist of sibling hashes along the path from leaf to root,
//! allowing verification against a known root hash.

use crate::smt::{default_hash, NodeHash, SparseMerkleTree, TREE_DEPTH};
use crate::FactId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Errors that can occur during proof verification.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProofError {
    #[error("proof has wrong number of siblings: expected {expected}, got {got}")]
    WrongSiblingCount { expected: usize, got: usize },

    #[error("computed root does not match expected root")]
    RootMismatch,

    #[error("non-membership proof invalid: leaf is not empty")]
    LeafNotEmpty,

    #[error("membership proof invalid: leaf is empty")]
    LeafEmpty,
}

/// A membership proof for a fact ID.
///
/// Proves that a fact ID IS in the tree by providing sibling hashes
/// from leaf to root.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MembershipProof {
    pub fact_id: [u8; 32],
    pub siblings: Vec<NodeHash>,
}

impl MembershipProof {
    /// Generate a membership proof for a fact ID in the tree.
    /// Returns None if the fact is not in the tree.
    pub fn generate(tree: &SparseMerkleTree, fact_id: &FactId) -> Option<Self> {
        if !tree.contains(fact_id) {
            return None;
        }

        let siblings = Self::collect_siblings(tree, fact_id);

        Some(Self {
            fact_id: *fact_id.as_bytes(),
            siblings,
        })
    }

    /// Collect sibling hashes along the path from leaf to root.
    fn collect_siblings(tree: &SparseMerkleTree, fact_id: &FactId) -> Vec<NodeHash> {
        (0..TREE_DEPTH)
            .map(|depth| tree.get_sibling_hash(fact_id, depth))
            .collect()
    }

    /// Verify this proof against an expected root hash.
    pub fn verify(&self, expected_root: &NodeHash) -> Result<(), ProofError> {
        if self.siblings.len() != TREE_DEPTH {
            return Err(ProofError::WrongSiblingCount {
                expected: TREE_DEPTH,
                got: self.siblings.len(),
            });
        }

        let fact_id = FactId::from_bytes(self.fact_id);
        let leaf_hash = Self::compute_leaf_hash(&fact_id);
        let computed_root = compute_root_from_path(&fact_id, leaf_hash, &self.siblings);

        if &computed_root != expected_root {
            return Err(ProofError::RootMismatch);
        }

        Ok(())
    }

    /// Compute leaf hash for a present fact.
    fn compute_leaf_hash(fact_id: &FactId) -> NodeHash {
        Sha256::digest(fact_id.as_bytes()).into()
    }

    /// Get the fact ID this proof is for.
    pub fn fact_id(&self) -> FactId {
        FactId::from_bytes(self.fact_id)
    }
}

/// A non-membership (absence) proof for a fact ID.
///
/// Proves that a fact ID is NOT in the tree by providing sibling hashes
/// that, when combined with an EMPTY leaf hash, produce the root.
///
/// This is the PRIMARY feature of the Absence library.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NonMembershipProof {
    pub fact_id: [u8; 32],
    pub siblings: Vec<NodeHash>,
}

impl NonMembershipProof {
    /// Generate a non-membership (absence) proof for a fact ID.
    /// Returns None if the fact IS in the tree (cannot prove absence).
    pub fn generate(tree: &SparseMerkleTree, fact_id: &FactId) -> Option<Self> {
        if tree.contains(fact_id) {
            return None;
        }

        let siblings: Vec<NodeHash> = (0..TREE_DEPTH)
            .map(|depth| tree.get_sibling_hash(fact_id, depth))
            .collect();

        Some(Self {
            fact_id: *fact_id.as_bytes(),
            siblings,
        })
    }

    /// Verify this non-membership proof against an expected root hash.
    ///
    /// Verifies that the path from an EMPTY leaf to the root produces
    /// the expected root hash, proving the fact is absent.
    pub fn verify(&self, expected_root: &NodeHash) -> Result<(), ProofError> {
        if self.siblings.len() != TREE_DEPTH {
            return Err(ProofError::WrongSiblingCount {
                expected: TREE_DEPTH,
                got: self.siblings.len(),
            });
        }

        let fact_id = FactId::from_bytes(self.fact_id);
        let empty_leaf_hash = *default_hash(0);
        let computed_root = compute_root_from_path(&fact_id, empty_leaf_hash, &self.siblings);

        if &computed_root != expected_root {
            return Err(ProofError::RootMismatch);
        }

        Ok(())
    }

    /// Get the fact ID this proof is for.
    pub fn fact_id(&self) -> FactId {
        FactId::from_bytes(self.fact_id)
    }
}

/// Compute root from a leaf hash and sibling path.
fn compute_root_from_path(
    fact_id: &FactId,
    leaf_hash: NodeHash,
    siblings: &[NodeHash],
) -> NodeHash {
    let mut current = leaf_hash;

    for (depth, sibling) in siblings.iter().enumerate() {
        let bit = fact_id.bit(TREE_DEPTH - 1 - depth);
        current = if bit {
            hash_pair(sibling, &current)
        } else {
            hash_pair(&current, sibling)
        };
    }

    current
}

/// Helper to hash two nodes.
fn hash_pair(left: &NodeHash, right: &NodeHash) -> NodeHash {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_membership_proof_generation() {
        let mut tree = SparseMerkleTree::new();
        let fact = FactId::from_json_value(&json!({"key": "value"}));

        assert!(MembershipProof::generate(&tree, &fact).is_none());

        tree.insert(&fact);
        let proof = MembershipProof::generate(&tree, &fact);
        assert!(proof.is_some());

        let proof = proof.unwrap();
        assert_eq!(proof.siblings.len(), TREE_DEPTH);
    }

    #[test]
    fn test_membership_proof_verification() {
        let mut tree = SparseMerkleTree::new();
        let fact = FactId::from_json_value(&json!({"test": 123}));
        tree.insert(&fact);

        let proof = MembershipProof::generate(&tree, &fact).unwrap();
        let root = *tree.root();

        assert!(proof.verify(&root).is_ok());
    }

    #[test]
    fn test_membership_proof_fails_wrong_root() {
        let mut tree = SparseMerkleTree::new();
        let fact = FactId::from_json_value(&json!({"test": 456}));
        tree.insert(&fact);

        let proof = MembershipProof::generate(&tree, &fact).unwrap();
        let wrong_root = [0u8; 32];

        assert_eq!(proof.verify(&wrong_root), Err(ProofError::RootMismatch));
    }

    #[test]
    fn test_membership_proof_multiple_facts() {
        let mut tree = SparseMerkleTree::new();
        let facts: Vec<_> = (0..5)
            .map(|i| FactId::from_json_value(&json!({"index": i})))
            .collect();

        for fact in &facts {
            tree.insert(fact);
        }

        let root = *tree.root();

        for fact in &facts {
            let proof = MembershipProof::generate(&tree, fact).unwrap();
            assert!(proof.verify(&root).is_ok());
        }
    }

    #[test]
    fn test_membership_proof_serialization() {
        let mut tree = SparseMerkleTree::new();
        let fact = FactId::from_json_value(&json!({"serialization": "test"}));
        tree.insert(&fact);

        let proof = MembershipProof::generate(&tree, &fact).unwrap();
        let json = serde_json::to_string(&proof).unwrap();
        let restored: MembershipProof = serde_json::from_str(&json).unwrap();

        assert!(restored.verify(tree.root()).is_ok());
    }

    // ============= NON-MEMBERSHIP (ABSENCE) PROOF TESTS =============

    #[test]
    fn test_absence_proof_generation_empty_tree() {
        let tree = SparseMerkleTree::new();
        let fact = FactId::from_json_value(&json!({"absent": true}));

        let proof = NonMembershipProof::generate(&tree, &fact);
        assert!(proof.is_some());

        let proof = proof.unwrap();
        assert_eq!(proof.siblings.len(), TREE_DEPTH);
    }

    #[test]
    fn test_absence_proof_generation_non_empty_tree() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(&FactId::from_json_value(&json!({"present": 1})));
        tree.insert(&FactId::from_json_value(&json!({"present": 2})));

        let absent = FactId::from_json_value(&json!({"absent": true}));
        let proof = NonMembershipProof::generate(&tree, &absent);
        assert!(proof.is_some());
    }

    #[test]
    fn test_absence_proof_fails_for_present_fact() {
        let mut tree = SparseMerkleTree::new();
        let fact = FactId::from_json_value(&json!({"present": true}));
        tree.insert(&fact);

        let proof = NonMembershipProof::generate(&tree, &fact);
        assert!(proof.is_none());
    }

    #[test]
    fn test_absence_proof_verification_empty_tree() {
        let tree = SparseMerkleTree::new();
        let fact = FactId::from_json_value(&json!({"missing": "key"}));

        let proof = NonMembershipProof::generate(&tree, &fact).unwrap();
        let root = *tree.root();

        assert!(proof.verify(&root).is_ok());
    }

    #[test]
    fn test_absence_proof_verification_with_other_facts() {
        let mut tree = SparseMerkleTree::new();
        for i in 0..10 {
            tree.insert(&FactId::from_json_value(&json!({"existing": i})));
        }

        let absent = FactId::from_json_value(&json!({"definitely_not_here": true}));
        let proof = NonMembershipProof::generate(&tree, &absent).unwrap();
        let root = *tree.root();

        assert!(proof.verify(&root).is_ok());
    }

    #[test]
    fn test_absence_proof_fails_wrong_root() {
        let tree = SparseMerkleTree::new();
        let fact = FactId::from_json_value(&json!({"test": "absence"}));

        let proof = NonMembershipProof::generate(&tree, &fact).unwrap();
        let wrong_root = [0xFFu8; 32];

        assert_eq!(proof.verify(&wrong_root), Err(ProofError::RootMismatch));
    }

    #[test]
    fn test_absence_proof_serialization() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(&FactId::from_json_value(&json!({"other": "fact"})));

        let absent = FactId::from_json_value(&json!({"absent": "fact"}));
        let proof = NonMembershipProof::generate(&tree, &absent).unwrap();

        let json = serde_json::to_string(&proof).unwrap();
        let restored: NonMembershipProof = serde_json::from_str(&json).unwrap();

        assert!(restored.verify(tree.root()).is_ok());
    }

    #[test]
    fn test_absence_proof_invalid_after_insertion() {
        let mut tree = SparseMerkleTree::new();
        let fact = FactId::from_json_value(&json!({"will_be_added": true}));

        let proof = NonMembershipProof::generate(&tree, &fact).unwrap();
        let old_root = *tree.root();

        assert!(proof.verify(&old_root).is_ok());

        tree.insert(&fact);
        let new_root = *tree.root();

        assert_eq!(proof.verify(&new_root), Err(ProofError::RootMismatch));
    }

    #[test]
    fn test_membership_vs_absence_mutually_exclusive() {
        let mut tree = SparseMerkleTree::new();
        let fact = FactId::from_json_value(&json!({"test": "fact"}));

        assert!(MembershipProof::generate(&tree, &fact).is_none());
        assert!(NonMembershipProof::generate(&tree, &fact).is_some());

        tree.insert(&fact);

        assert!(MembershipProof::generate(&tree, &fact).is_some());
        assert!(NonMembershipProof::generate(&tree, &fact).is_none());
    }

    #[test]
    fn test_proof_pinned_to_root() {
        let mut tree = SparseMerkleTree::new();
        let fact_a = FactId::from_json_value(&json!({"a": 1}));
        tree.insert(&fact_a);
        let root_v1 = *tree.root();

        let absent_b = FactId::from_json_value(&json!({"b": 2}));
        let absence_proof_b = NonMembershipProof::generate(&tree, &absent_b).unwrap();

        assert!(absence_proof_b.verify(&root_v1).is_ok());

        tree.insert(&absent_b);
        let root_v2 = *tree.root();

        assert!(absence_proof_b.verify(&root_v1).is_ok());
        assert!(absence_proof_b.verify(&root_v2).is_err());
    }
}
