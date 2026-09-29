//! Interval absence proofs across contiguous epoch ranges.
//!
//! An [`IntervalAbsenceProof`] demonstrates that a fact was continuously absent
//! from epoch `from_epoch` through `to_epoch`. This is more powerful than a
//! single-epoch absence proof: it shows the fact was never recorded during
//! an entire time window, not just at one snapshot.
//!
//! # Design
//!
//! The proof combines three pieces of evidence:
//!
//! 1. **Absence at start**: A non-membership proof showing the fact was absent
//!    at `from_epoch`'s checkpoint root.
//!
//! 2. **Append-only consistency**: A [`ConsistencyProof`] showing the store
//!    advanced append-only from `from_epoch` to `to_epoch` (no deletions or
//!    rewrites occurred).
//!
//! 3. **Not in added set**: The fact ID is not among the facts added between
//!    the two epochs (derived from the consistency proof's steps).
//!
//! If all three hold, the fact was absent at the start and never added during
//! the interval, so it remained absent throughout.
//!
//! # Verification
//!
//! Verifiers check:
//! - The absence proof verifies against `from_checkpoint.root`
//! - The consistency proof verifies between the two checkpoints
//! - The fact ID is NOT in `consistency_proof.added_facts()`
//!
//! # Example
//!
//! ```ignore
//! use absence::{AbsenceStore, FactId, IntervalAbsenceProof};
//! use serde_json::json;
//!
//! let mut store = AbsenceStore::new();
//!
//! // Day 1: record some facts
//! store.record_json(&json!({"user": "alice"})).unwrap();
//! store.checkpoint(); // epoch 0
//!
//! // Day 2: add more facts
//! store.record_json(&json!({"user": "bob"})).unwrap();
//! store.checkpoint(); // epoch 1
//!
//! // Prove "eve" was absent throughout epochs 0-1
//! let eve = FactId::from_json_value(&json!({"user": "eve"}));
//! let proof = store.prove_absent_interval(&eve, 0, 1).unwrap();
//!
//! // Verify continuous absence
//! let cp0 = store.checkpoint_at(0).unwrap();
//! let cp1 = store.checkpoint_at(1).unwrap();
//! proof.verify_checkpoints(cp0, cp1).unwrap();
//! ```
//!
//! The `prove_absent_interval` method handles constructing the absence and
//! consistency proofs internally. For lower-level control, you can construct
//! an [`IntervalAbsenceProof`] manually from its components.

use crate::consistency::{ConsistencyError, ConsistencyProof};
use crate::proof::{NonMembershipProof, ProofError};
use crate::smt::NodeHash;
use crate::store::Checkpoint;
use crate::FactId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors from building or verifying an interval absence proof.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IntervalError {
    #[error("fact is present at from_epoch (cannot prove interval absence)")]
    PresentAtStart,

    #[error("fact was added during the interval at step {step}")]
    AddedDuringInterval { step: usize },

    #[error("absence proof at from_epoch is invalid: {0}")]
    AbsenceInvalid(#[from] ProofError),

    #[error("consistency proof is invalid: {0}")]
    ConsistencyInvalid(#[from] ConsistencyError),

    #[error("from_epoch ({from}) must be <= to_epoch ({to})")]
    InvalidEpochRange { from: u64, to: u64 },

    #[error("proof from_epoch {proof} does not match expected {expected}")]
    FromEpochMismatch { proof: u64, expected: u64 },

    #[error("proof to_epoch {proof} does not match expected {expected}")]
    ToEpochMismatch { proof: u64, expected: u64 },
}

/// Proof that a fact was continuously absent across a contiguous epoch range.
///
/// Contains:
/// - The queried fact ID
/// - Epoch range `[from_epoch, to_epoch]`
/// - Checkpoint roots at both epochs
/// - Absence proof at `from_epoch`
/// - Consistency proof from `from_epoch` to `to_epoch`
///
/// The verifier confirms:
/// 1. Absence proof is valid against `from_root`
/// 2. Consistency proof links `from_root` to `to_root` (append-only)
/// 3. The fact ID is NOT among the added facts in the consistency proof
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntervalAbsenceProof {
    /// The fact ID proven to be continuously absent.
    pub fact_id: [u8; 32],
    /// Starting epoch of the interval.
    pub from_epoch: u64,
    /// Ending epoch of the interval.
    pub to_epoch: u64,
    /// Checkpoint root at from_epoch.
    pub from_root: NodeHash,
    /// Checkpoint root at to_epoch.
    pub to_root: NodeHash,
    /// Non-membership proof at from_epoch.
    pub absence_proof: NonMembershipProof,
    /// Consistency proof showing append-only advancement.
    pub consistency_proof: ConsistencyProof,
}

impl IntervalAbsenceProof {
    /// Create a new interval absence proof.
    ///
    /// The caller must ensure:
    /// - `absence_proof` proves the fact absent at `from_checkpoint`
    /// - `consistency_proof` links `from_checkpoint` to `to_checkpoint`
    /// - The fact was not added during the interval
    pub fn new(
        fact_id: &FactId,
        from_checkpoint: &Checkpoint,
        to_checkpoint: &Checkpoint,
        absence_proof: NonMembershipProof,
        consistency_proof: ConsistencyProof,
    ) -> Result<Self, IntervalError> {
        if from_checkpoint.epoch > to_checkpoint.epoch {
            return Err(IntervalError::InvalidEpochRange {
                from: from_checkpoint.epoch,
                to: to_checkpoint.epoch,
            });
        }

        let proof = Self {
            fact_id: *fact_id.as_bytes(),
            from_epoch: from_checkpoint.epoch,
            to_epoch: to_checkpoint.epoch,
            from_root: from_checkpoint.root,
            to_root: to_checkpoint.root,
            absence_proof,
            consistency_proof,
        };

        proof.verify_self()?;
        Ok(proof)
    }

    /// Get the fact ID this proof is for.
    pub fn fact_id(&self) -> FactId {
        FactId::from_bytes(self.fact_id)
    }

    /// Verify the proof is internally consistent.
    ///
    /// Checks:
    /// 1. Absence proof is valid against from_root
    /// 2. Consistency proof links from_root to to_root
    /// 3. Fact ID is not among added facts
    pub fn verify_self(&self) -> Result<(), IntervalError> {
        self.absence_proof.verify(&self.from_root)?;

        self.consistency_proof
            .verify(&self.from_root, &self.to_root)?;

        let fact_id = self.fact_id();
        for (step, added) in self.consistency_proof.added_facts().iter().enumerate() {
            if added == &fact_id {
                return Err(IntervalError::AddedDuringInterval { step });
            }
        }

        Ok(())
    }

    /// Verify the proof against two explicit roots.
    pub fn verify(&self, from_root: &NodeHash, to_root: &NodeHash) -> Result<(), IntervalError> {
        if &self.from_root != from_root {
            return Err(IntervalError::ConsistencyInvalid(
                ConsistencyError::OldRootMismatch,
            ));
        }
        if &self.to_root != to_root {
            return Err(IntervalError::ConsistencyInvalid(
                ConsistencyError::NewRootMismatch,
            ));
        }
        self.verify_self()
    }

    /// Verify the proof against two checkpoints.
    ///
    /// Checks epoch numbers and roots match, plus internal verification.
    pub fn verify_checkpoints(
        &self,
        from: &Checkpoint,
        to: &Checkpoint,
    ) -> Result<(), IntervalError> {
        if self.from_epoch != from.epoch {
            return Err(IntervalError::FromEpochMismatch {
                proof: self.from_epoch,
                expected: from.epoch,
            });
        }
        if self.to_epoch != to.epoch {
            return Err(IntervalError::ToEpochMismatch {
                proof: self.to_epoch,
                expected: to.epoch,
            });
        }
        self.verify(&from.root, &to.root)
    }

    /// Number of facts added during the interval.
    pub fn facts_added_count(&self) -> usize {
        self.consistency_proof.len()
    }

    /// The epoch span of this proof.
    pub fn epoch_span(&self) -> u64 {
        self.to_epoch.saturating_sub(self.from_epoch)
    }

    /// True if from_epoch == to_epoch (single-epoch proof).
    pub fn is_single_epoch(&self) -> bool {
        self.from_epoch == self.to_epoch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AbsenceStore;
    use serde_json::json;

    fn fid(v: serde_json::Value) -> FactId {
        FactId::from_json_value(&v)
    }

    #[test]
    fn test_interval_absence_basic() {
        let mut store = AbsenceStore::new();

        store.record_json(&json!({"a": 1})).unwrap();
        store.checkpoint(); // epoch 0

        store.record_json(&json!({"b": 2})).unwrap();
        store.checkpoint(); // epoch 1

        let absent = fid(json!({"absent": true}));
        let cp0 = *store.checkpoint_at(0).unwrap();
        let cp1 = *store.checkpoint_at(1).unwrap();

        let mut tree = crate::SparseMerkleTree::new();
        tree.insert(&fid(json!({"a": 1})));
        let absence_at_0 = NonMembershipProof::generate(&tree, &absent).unwrap();

        let consistency = ConsistencyProof::generate(&tree, &[fid(json!({"b": 2}))]).unwrap();

        let proof =
            IntervalAbsenceProof::new(&absent, &cp0, &cp1, absence_at_0, consistency).unwrap();

        assert_eq!(proof.from_epoch, 0);
        assert_eq!(proof.to_epoch, 1);
        assert_eq!(proof.facts_added_count(), 1);
        assert!(!proof.is_single_epoch());
        assert!(proof.verify_checkpoints(&cp0, &cp1).is_ok());
    }

    #[test]
    fn test_interval_absence_same_epoch() {
        let mut store = AbsenceStore::new();
        store.record_json(&json!({"a": 1})).unwrap();
        store.checkpoint(); // epoch 0

        let absent = fid(json!({"absent": true}));
        let cp0 = *store.checkpoint_at(0).unwrap();

        let mut tree = crate::SparseMerkleTree::new();
        tree.insert(&fid(json!({"a": 1})));
        let absence_at_0 = NonMembershipProof::generate(&tree, &absent).unwrap();
        let consistency = ConsistencyProof::generate(&tree, &[]).unwrap();

        let proof =
            IntervalAbsenceProof::new(&absent, &cp0, &cp0, absence_at_0, consistency).unwrap();

        assert!(proof.is_single_epoch());
        assert_eq!(proof.epoch_span(), 0);
        assert!(proof.verify_checkpoints(&cp0, &cp0).is_ok());
    }

    #[test]
    fn test_interval_absence_fails_if_added() {
        let mut store = AbsenceStore::new();
        store.record_json(&json!({"a": 1})).unwrap();
        store.checkpoint(); // epoch 0

        let will_add = fid(json!({"will_add": true}));
        store.record(&will_add).unwrap();
        store.checkpoint(); // epoch 1

        let cp0 = *store.checkpoint_at(0).unwrap();
        let cp1 = *store.checkpoint_at(1).unwrap();

        let mut tree = crate::SparseMerkleTree::new();
        tree.insert(&fid(json!({"a": 1})));
        let absence_at_0 = NonMembershipProof::generate(&tree, &will_add).unwrap();
        let consistency = ConsistencyProof::generate(&tree, &[will_add]).unwrap();

        let result = IntervalAbsenceProof::new(&will_add, &cp0, &cp1, absence_at_0, consistency);

        assert!(matches!(
            result,
            Err(IntervalError::AddedDuringInterval { step: 0 })
        ));
    }

    #[test]
    fn test_interval_absence_invalid_epoch_range() {
        let cp1 = Checkpoint {
            epoch: 1,
            root: [0; 32],
            fact_count: 1,
            unix_ts: 0,
        };
        let cp0 = Checkpoint {
            epoch: 0,
            root: [0; 32],
            fact_count: 0,
            unix_ts: 0,
        };

        let absent = fid(json!({"absent": true}));
        let tree = crate::SparseMerkleTree::new();
        let absence = NonMembershipProof::generate(&tree, &absent).unwrap();
        let consistency = ConsistencyProof::generate(&tree, &[]).unwrap();

        let result = IntervalAbsenceProof::new(&absent, &cp1, &cp0, absence, consistency);

        assert!(matches!(
            result,
            Err(IntervalError::InvalidEpochRange { from: 1, to: 0 })
        ));
    }

    #[test]
    fn test_interval_absence_serde_roundtrip() {
        let mut store = AbsenceStore::new();
        store.record_json(&json!({"a": 1})).unwrap();
        store.checkpoint();
        store.record_json(&json!({"b": 2})).unwrap();
        store.checkpoint();

        let absent = fid(json!({"absent": true}));
        let cp0 = *store.checkpoint_at(0).unwrap();
        let cp1 = *store.checkpoint_at(1).unwrap();

        let mut tree = crate::SparseMerkleTree::new();
        tree.insert(&fid(json!({"a": 1})));
        let absence_at_0 = NonMembershipProof::generate(&tree, &absent).unwrap();
        let consistency = ConsistencyProof::generate(&tree, &[fid(json!({"b": 2}))]).unwrap();

        let proof =
            IntervalAbsenceProof::new(&absent, &cp0, &cp1, absence_at_0, consistency).unwrap();

        let json = serde_json::to_string_pretty(&proof).unwrap();
        let restored: IntervalAbsenceProof = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.from_epoch, proof.from_epoch);
        assert_eq!(restored.to_epoch, proof.to_epoch);
        assert!(restored.verify_checkpoints(&cp0, &cp1).is_ok());
    }

    #[test]
    fn test_interval_absence_epoch_mismatch() {
        let mut store = AbsenceStore::new();
        store.record_json(&json!({"a": 1})).unwrap();
        store.checkpoint();
        store.record_json(&json!({"b": 2})).unwrap();
        store.checkpoint();

        let absent = fid(json!({"absent": true}));
        let cp0 = *store.checkpoint_at(0).unwrap();
        let cp1 = *store.checkpoint_at(1).unwrap();

        let mut tree = crate::SparseMerkleTree::new();
        tree.insert(&fid(json!({"a": 1})));
        let absence_at_0 = NonMembershipProof::generate(&tree, &absent).unwrap();
        let consistency = ConsistencyProof::generate(&tree, &[fid(json!({"b": 2}))]).unwrap();

        let proof =
            IntervalAbsenceProof::new(&absent, &cp0, &cp1, absence_at_0, consistency).unwrap();

        let wrong_cp = Checkpoint {
            epoch: 5,
            root: cp0.root,
            fact_count: cp0.fact_count,
            unix_ts: cp0.unix_ts,
        };

        assert!(matches!(
            proof.verify_checkpoints(&wrong_cp, &cp1),
            Err(IntervalError::FromEpochMismatch {
                proof: 0,
                expected: 5
            })
        ));
    }
}
