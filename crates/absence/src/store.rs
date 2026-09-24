//! AbsenceStore: High-level API for the Sparse Merkle Tree
//!
//! Provides a user-friendly interface for:
//! - Recording facts (inserting into the tree)
//! - Generating absence proofs (proving a fact was never recorded)
//! - Generating presence proofs (proving a fact was recorded)
//! - Verifying proofs against pinned roots

use crate::proof::{MembershipProof, NonMembershipProof, ProofError};
use crate::smt::{NodeHash, SparseMerkleTree};
use crate::FactId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors that can occur in AbsenceStore operations.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("fact is already recorded")]
    AlreadyRecorded,

    #[error("fact is not recorded (cannot prove presence)")]
    NotRecorded,

    #[error("fact is recorded (cannot prove absence)")]
    FactPresent,

    #[error("proof verification failed: {0}")]
    ProofError(#[from] ProofError),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

/// A commitment to the current state of the store.
/// 
/// This is the root hash that proofs are verified against.
/// Publish this commitment; verifiers use it to check proofs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {
    pub root: [u8; 32],
    pub fact_count: usize,
}

impl Commitment {
    /// Get the root hash as a hex string.
    pub fn root_hex(&self) -> String {
        hex::encode(self.root)
    }
}

/// High-level API for managing a set of committed facts with absence proofs.
/// 
/// # Example
/// 
/// ```
/// use absence::AbsenceStore;
/// use serde_json::json;
/// 
/// let mut store = AbsenceStore::new();
/// 
/// // Record some facts
/// store.record_json(&json!({"user": "alice", "secret": "password123"})).unwrap();
/// 
/// // Get commitment (publish this)
/// let commitment = store.commitment();
/// 
/// // Prove a different secret was NEVER recorded
/// let other_secret = json!({"user": "alice", "secret": "other_password"});
/// let proof = store.prove_absent_json(&other_secret).unwrap();
/// 
/// // Verifier can check the proof against the published commitment
/// assert!(AbsenceStore::verify_absent(&proof, &commitment.root).is_ok());
/// ```
#[derive(Clone, Debug)]
pub struct AbsenceStore {
    tree: SparseMerkleTree,
}

impl Default for AbsenceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl AbsenceStore {
    /// Create a new empty store.
    pub fn new() -> Self {
        Self {
            tree: SparseMerkleTree::new(),
        }
    }

    /// Get the current commitment (root hash + fact count).
    pub fn commitment(&self) -> Commitment {
        Commitment {
            root: *self.tree.root(),
            fact_count: self.tree.len(),
        }
    }

    /// Get the current root hash.
    pub fn root(&self) -> &NodeHash {
        self.tree.root()
    }

    /// Get the number of recorded facts.
    pub fn len(&self) -> usize {
        self.tree.len()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    /// Record a fact by its ID.
    /// Returns the fact ID if newly recorded.
    pub fn record(&mut self, fact_id: &FactId) -> Result<(), StoreError> {
        if !self.tree.insert(fact_id) {
            return Err(StoreError::AlreadyRecorded);
        }
        Ok(())
    }

    /// Record a fact from a JSON value.
    pub fn record_json(&mut self, value: &serde_json::Value) -> Result<FactId, StoreError> {
        let fact_id = FactId::from_json_value(value);
        self.record(&fact_id)?;
        Ok(fact_id)
    }

    /// Record a fact from a serializable value.
    pub fn record_value<T: Serialize>(&mut self, value: &T) -> Result<FactId, StoreError> {
        let fact_id = FactId::from_value(value)?;
        self.record(&fact_id)?;
        Ok(fact_id)
    }

    /// Check if a fact has been recorded.
    pub fn contains(&self, fact_id: &FactId) -> bool {
        self.tree.contains(fact_id)
    }

    /// Prove that a fact is ABSENT (not recorded).
    /// This is the primary feature of Absence.
    pub fn prove_absent(&self, fact_id: &FactId) -> Result<NonMembershipProof, StoreError> {
        NonMembershipProof::generate(&self.tree, fact_id).ok_or(StoreError::FactPresent)
    }

    /// Prove absence for a JSON value.
    pub fn prove_absent_json(
        &self,
        value: &serde_json::Value,
    ) -> Result<NonMembershipProof, StoreError> {
        let fact_id = FactId::from_json_value(value);
        self.prove_absent(&fact_id)
    }

    /// Prove that a fact IS recorded (present).
    pub fn prove_present(&self, fact_id: &FactId) -> Result<MembershipProof, StoreError> {
        MembershipProof::generate(&self.tree, fact_id).ok_or(StoreError::NotRecorded)
    }

    /// Prove presence for a JSON value.
    pub fn prove_present_json(
        &self,
        value: &serde_json::Value,
    ) -> Result<MembershipProof, StoreError> {
        let fact_id = FactId::from_json_value(value);
        self.prove_present(&fact_id)
    }

    /// Verify an absence proof against a root hash.
    /// This is a static method - verifiers don't need the full store.
    pub fn verify_absent(proof: &NonMembershipProof, root: &NodeHash) -> Result<(), ProofError> {
        proof.verify(root)
    }

    /// Verify a presence proof against a root hash.
    /// This is a static method - verifiers don't need the full store.
    pub fn verify_present(proof: &MembershipProof, root: &NodeHash) -> Result<(), ProofError> {
        proof.verify(root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_empty_store() {
        let store = AbsenceStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_record_fact() {
        let mut store = AbsenceStore::new();
        let fact_id = store.record_json(&json!({"test": "value"})).unwrap();
        
        assert!(!store.is_empty());
        assert_eq!(store.len(), 1);
        assert!(store.contains(&fact_id));
    }

    #[test]
    fn test_duplicate_record_fails() {
        let mut store = AbsenceStore::new();
        let value = json!({"duplicate": "test"});
        
        assert!(store.record_json(&value).is_ok());
        assert!(matches!(
            store.record_json(&value),
            Err(StoreError::AlreadyRecorded)
        ));
    }

    #[test]
    fn test_commitment() {
        let mut store = AbsenceStore::new();
        let c1 = store.commitment();
        assert_eq!(c1.fact_count, 0);
        
        store.record_json(&json!({"fact": 1})).unwrap();
        let c2 = store.commitment();
        assert_eq!(c2.fact_count, 1);
        assert_ne!(c1.root, c2.root);
    }

    #[test]
    fn test_prove_absent_empty_store() {
        let store = AbsenceStore::new();
        let fact = FactId::from_json_value(&json!({"any": "fact"}));
        
        let proof = store.prove_absent(&fact).unwrap();
        assert!(AbsenceStore::verify_absent(&proof, store.root()).is_ok());
    }

    #[test]
    fn test_prove_absent_non_empty_store() {
        let mut store = AbsenceStore::new();
        store.record_json(&json!({"recorded": 1})).unwrap();
        store.record_json(&json!({"recorded": 2})).unwrap();
        
        let absent = FactId::from_json_value(&json!({"not_recorded": true}));
        let proof = store.prove_absent(&absent).unwrap();
        
        assert!(AbsenceStore::verify_absent(&proof, store.root()).is_ok());
    }

    #[test]
    fn test_prove_absent_fails_for_present() {
        let mut store = AbsenceStore::new();
        let fact_id = store.record_json(&json!({"present": true})).unwrap();
        
        assert!(matches!(
            store.prove_absent(&fact_id),
            Err(StoreError::FactPresent)
        ));
    }

    #[test]
    fn test_prove_present() {
        let mut store = AbsenceStore::new();
        let fact_id = store.record_json(&json!({"present": "fact"})).unwrap();
        
        let proof = store.prove_present(&fact_id).unwrap();
        assert!(AbsenceStore::verify_present(&proof, store.root()).is_ok());
    }

    #[test]
    fn test_prove_present_fails_for_absent() {
        let store = AbsenceStore::new();
        let fact = FactId::from_json_value(&json!({"absent": true}));
        
        assert!(matches!(
            store.prove_present(&fact),
            Err(StoreError::NotRecorded)
        ));
    }

    #[test]
    fn test_verify_with_wrong_root() {
        let store = AbsenceStore::new();
        let fact = FactId::from_json_value(&json!({"test": 123}));
        let proof = store.prove_absent(&fact).unwrap();
        
        let wrong_root = [0xFFu8; 32];
        assert!(AbsenceStore::verify_absent(&proof, &wrong_root).is_err());
    }

    #[test]
    fn test_proof_pinned_to_commitment() {
        let mut store = AbsenceStore::new();
        let fact = FactId::from_json_value(&json!({"will_add": true}));
        
        let proof_before = store.prove_absent(&fact).unwrap();
        let root_before = *store.root();
        
        store.record(&fact).unwrap();
        let root_after = *store.root();
        
        assert!(AbsenceStore::verify_absent(&proof_before, &root_before).is_ok());
        assert!(AbsenceStore::verify_absent(&proof_before, &root_after).is_err());
    }

    #[test]
    fn test_record_value_serializable() {
        #[derive(Serialize)]
        struct TestStruct {
            name: String,
            value: i32,
        }
        
        let mut store = AbsenceStore::new();
        let data = TestStruct {
            name: "test".to_string(),
            value: 42,
        };
        
        let fact_id = store.record_value(&data).unwrap();
        assert!(store.contains(&fact_id));
    }

    #[test]
    fn test_absence_store_workflow() {
        let mut store = AbsenceStore::new();
        
        store.record_json(&json!({"user": "alice", "action": "login"})).unwrap();
        store.record_json(&json!({"user": "bob", "action": "login"})).unwrap();
        
        let commitment = store.commitment();
        
        let never_happened = json!({"user": "alice", "action": "delete_all"});
        let proof = store.prove_absent_json(&never_happened).unwrap();
        
        assert!(AbsenceStore::verify_absent(&proof, &commitment.root).is_ok());
        
        let happened = json!({"user": "alice", "action": "login"});
        assert!(store.prove_absent_json(&happened).is_err());
    }

    #[test]
    fn test_commitment_hex() {
        let store = AbsenceStore::new();
        let commitment = store.commitment();
        
        let hex = commitment.root_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
