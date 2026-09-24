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
        let computed_root = Self::compute_root(&fact_id, leaf_hash, &self.siblings);

        if &computed_root != expected_root {
            return Err(ProofError::RootMismatch);
        }

        Ok(())
    }

    /// Compute leaf hash for a present fact.
    fn compute_leaf_hash(fact_id: &FactId) -> NodeHash {
        Sha256::digest(fact_id.as_bytes()).into()
    }

    /// Compute root from leaf hash and siblings.
    fn compute_root(fact_id: &FactId, leaf_hash: NodeHash, siblings: &[NodeHash]) -> NodeHash {
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

    /// Get the fact ID this proof is for.
    pub fn fact_id(&self) -> FactId {
        FactId::from_bytes(self.fact_id)
    }
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
        
        assert_eq!(
            proof.verify(&wrong_root),
            Err(ProofError::RootMismatch)
        );
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
}
