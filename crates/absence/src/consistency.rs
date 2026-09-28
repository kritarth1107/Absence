//! Append-only consistency proofs between two roots
//!
//! A [`ConsistencyProof`] shows that a newer root was obtained from an older
//! root purely by *adding* facts — nothing was removed or rewritten.
//!
//! The proof is a sequence of absence proofs, one per added fact. Starting
//! from the old root, the verifier checks each fact is absent from the current
//! root, then recomputes the root with that leaf set to present (reusing the
//! same sibling path). If the final root equals the new root, the new tree is
//! exactly `old ∪ added`, so every fact present at the old root is still
//! present at the new root.

use crate::proof::{compute_root_from_path, NonMembershipProof, ProofError};
use crate::smt::{NodeHash, SparseMerkleTree};
use crate::store::Checkpoint;
use crate::FactId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors from building or verifying a consistency proof.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConsistencyError {
    #[error("fact at index {index} is already present (cannot append)")]
    AlreadyPresent { index: usize },

    #[error("proof old_root does not match the expected old root")]
    OldRootMismatch,

    #[error("proof new_root does not match the expected new root")]
    NewRootMismatch,

    #[error("step {index} failed: {source}")]
    Step { index: usize, source: ProofError },

    #[error("replayed root does not match the claimed new root")]
    FinalRootMismatch,

    #[error("fact count delta mismatch: checkpoints differ by {expected}, proof adds {got}")]
    FactCountMismatch { expected: u64, got: u64 },
}

/// Proof that `new_root` is an append-only extension of `old_root`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsistencyProof {
    pub old_root: NodeHash,
    pub new_root: NodeHash,
    /// One absence proof per appended fact, in insertion order. Each proof is
    /// taken against the root produced by the previous step.
    pub steps: Vec<NonMembershipProof>,
}

impl ConsistencyProof {
    /// Build a proof that appending `added` to `old` yields the new root.
    ///
    /// `old` is not modified; the extension is computed on a clone.
    pub fn generate(old: &SparseMerkleTree, added: &[FactId]) -> Result<Self, ConsistencyError> {
        let mut tree = old.clone();
        let old_root = *tree.root();
        let mut steps = Vec::with_capacity(added.len());

        for (index, fact) in added.iter().enumerate() {
            let step = NonMembershipProof::generate(&tree, fact)
                .ok_or(ConsistencyError::AlreadyPresent { index })?;
            tree.insert(fact);
            steps.push(step);
        }

        Ok(Self {
            old_root,
            new_root: *tree.root(),
            steps,
        })
    }

    /// Replay the proof starting from its own `old_root` and check it ends at
    /// its own `new_root`.
    pub fn verify_self(&self) -> Result<(), ConsistencyError> {
        let mut current = self.old_root;
        for (index, step) in self.steps.iter().enumerate() {
            step.verify(&current)
                .map_err(|source| ConsistencyError::Step { index, source })?;
            let fact = step.fact_id();
            let leaf = SparseMerkleTree::leaf_hash(&fact);
            current = compute_root_from_path(&fact, leaf, &step.siblings);
        }
        if current != self.new_root {
            return Err(ConsistencyError::FinalRootMismatch);
        }
        Ok(())
    }

    /// Verify the proof links the two expected roots.
    pub fn verify(
        &self,
        expected_old: &NodeHash,
        expected_new: &NodeHash,
    ) -> Result<(), ConsistencyError> {
        if &self.old_root != expected_old {
            return Err(ConsistencyError::OldRootMismatch);
        }
        if &self.new_root != expected_new {
            return Err(ConsistencyError::NewRootMismatch);
        }
        self.verify_self()
    }

    /// Verify the proof links two checkpoints, including the fact-count delta.
    pub fn verify_checkpoints(
        &self,
        from: &Checkpoint,
        to: &Checkpoint,
    ) -> Result<(), ConsistencyError> {
        let expected = to.fact_count.saturating_sub(from.fact_count);
        let got = self.steps.len() as u64;
        if to.fact_count < from.fact_count || expected != got {
            return Err(ConsistencyError::FactCountMismatch { expected, got });
        }
        self.verify(&from.root, &to.root)
    }

    /// The appended fact IDs, in insertion order.
    pub fn added_facts(&self) -> Vec<FactId> {
        self.steps.iter().map(NonMembershipProof::fact_id).collect()
    }

    /// Number of appended facts.
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// True if the proof appends nothing (old and new roots must be equal).
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fid(v: serde_json::Value) -> FactId {
        FactId::from_json_value(&v)
    }

    #[test]
    fn test_generate_and_verify() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(&fid(json!({"a": 1})));
        let added = vec![fid(json!({"b": 2})), fid(json!({"c": 3}))];

        let proof = ConsistencyProof::generate(&tree, &added).unwrap();
        let mut expected = tree.clone();
        for f in &added {
            expected.insert(f);
        }

        assert_eq!(proof.old_root, *tree.root());
        assert_eq!(proof.new_root, *expected.root());
        assert!(proof.verify(tree.root(), expected.root()).is_ok());
        assert_eq!(proof.added_facts(), added);
    }

    #[test]
    fn test_empty_extension() {
        let tree = SparseMerkleTree::new();
        let proof = ConsistencyProof::generate(&tree, &[]).unwrap();
        assert!(proof.is_empty());
        assert_eq!(proof.old_root, proof.new_root);
        assert!(proof.verify_self().is_ok());
    }

    #[test]
    fn test_rejects_already_present() {
        let mut tree = SparseMerkleTree::new();
        let a = fid(json!({"a": 1}));
        tree.insert(&a);
        assert_eq!(
            ConsistencyProof::generate(&tree, &[fid(json!({"b": 1})), a]),
            Err(ConsistencyError::AlreadyPresent { index: 1 })
        );
    }

    #[test]
    fn test_rejects_duplicate_in_batch() {
        let tree = SparseMerkleTree::new();
        let b = fid(json!({"b": 1}));
        assert_eq!(
            ConsistencyProof::generate(&tree, &[b, b]),
            Err(ConsistencyError::AlreadyPresent { index: 1 })
        );
    }

    #[test]
    fn test_serde_roundtrip() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(&fid(json!({"seed": 1})));
        let proof =
            ConsistencyProof::generate(&tree, &[fid(json!({"new": 2})), fid(json!({"new": 3}))])
                .unwrap();

        let json = serde_json::to_string(&proof).unwrap();
        let back: ConsistencyProof = serde_json::from_str(&json).unwrap();
        assert_eq!(back, proof);
        assert!(back.verify_self().is_ok());
    }
}
