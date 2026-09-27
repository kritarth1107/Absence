//! WitnessBundle: portable package of signed checkpoints and proofs.
//!
//! A [`WitnessBundle`] packages a [`SignedCheckpoint`] with one or more
//! absence proofs for transport. Verifiers can check all proofs against
//! the signed root in one operation.

use crate::compact::CompactProof;
use crate::keys::VerifierKey;
use crate::proof::NonMembershipProof;
use crate::signed::{SignedCheckpoint, SignedError};
use crate::store::Checkpoint;
use crate::SignerKey;
use serde::{Deserialize, Serialize};

/// A portable package containing a signed checkpoint and absence proofs.
///
/// WitnessBundle is designed for transport: it contains everything a verifier
/// needs to check one or more absence claims against a cryptographically
/// attested root.
///
/// # Example
///
/// ```
/// use absence::{AbsenceStore, SignerKey, WitnessBundle};
/// use serde_json::json;
///
/// let mut store = AbsenceStore::new();
/// store.record_json(&json!({"recorded": true})).unwrap();
/// let checkpoint = store.checkpoint();
///
/// let signer = SignerKey::generate();
/// let verifier = signer.verifier();
///
/// let absent_facts = vec![
///     json!({"missing": 1}),
///     json!({"missing": 2}),
/// ];
/// let proofs = store.prove_absent_batch_json(&absent_facts).unwrap();
///
/// let bundle = WitnessBundle::new(&checkpoint, &signer, proofs);
/// assert!(bundle.verify_all(&verifier).is_ok());
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WitnessBundle {
    /// The signed checkpoint attesting to the root.
    pub signed_checkpoint: SignedCheckpoint,
    /// One or more absence proofs to verify.
    pub proofs: Vec<NonMembershipProof>,
}

impl WitnessBundle {
    /// Create a new bundle with the given proofs.
    pub fn new(checkpoint: &Checkpoint, signer: &SignerKey, proofs: Vec<NonMembershipProof>) -> Self {
        Self {
            signed_checkpoint: SignedCheckpoint::sign(checkpoint, signer),
            proofs,
        }
    }

    /// Create a bundle from an existing signed checkpoint.
    pub fn from_signed(signed_checkpoint: SignedCheckpoint, proofs: Vec<NonMembershipProof>) -> Self {
        Self {
            signed_checkpoint,
            proofs,
        }
    }

    /// Add a proof to the bundle.
    pub fn add_proof(&mut self, proof: NonMembershipProof) {
        self.proofs.push(proof);
    }

    /// Verify the signed checkpoint and all proofs.
    ///
    /// Returns `Ok(())` if:
    /// 1. The checkpoint signature is valid against the verifier key
    /// 2. All absence proofs are valid against the checkpoint's root
    ///
    /// Returns an error on the first failure.
    pub fn verify_all(&self, verifier: &VerifierKey) -> Result<(), SignedError> {
        self.signed_checkpoint.verify(verifier)?;

        let root = &self.signed_checkpoint.checkpoint.root;
        for proof in &self.proofs {
            proof.verify(root)?;
        }
        Ok(())
    }

    /// Verify just the signature (not the proofs).
    pub fn verify_signature(&self, verifier: &VerifierKey) -> Result<(), SignedError> {
        self.signed_checkpoint.verify(verifier)
    }

    /// Get the checkpoint from the bundle.
    pub fn checkpoint(&self) -> &Checkpoint {
        &self.signed_checkpoint.checkpoint
    }

    /// Get the number of proofs in the bundle.
    pub fn proof_count(&self) -> usize {
        self.proofs.len()
    }

    /// Check if the bundle has no proofs.
    pub fn is_empty(&self) -> bool {
        self.proofs.is_empty()
    }

    /// Get all fact IDs from the proofs.
    pub fn fact_ids(&self) -> Vec<crate::FactId> {
        self.proofs.iter().map(|p| p.fact_id()).collect()
    }

    /// Encode all proofs to compact hex format.
    ///
    /// Returns a vector of hex strings, one per proof.
    pub fn proofs_to_compact_hex(&self) -> Vec<String> {
        self.proofs
            .iter()
            .map(CompactProof::encode_absence_hex)
            .collect()
    }

    /// Convert the bundle to a JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Parse a bundle from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

/// Compact wire format for a WitnessBundle.
///
/// This format is more compact than JSON but still human-readable (hex).
/// Format:
/// - Line 1: signed checkpoint JSON (one line)
/// - Line 2+: one compact proof hex per line
#[derive(Clone, Debug)]
pub struct CompactBundle {
    /// Signed checkpoint as JSON (one line).
    pub checkpoint_json: String,
    /// Proofs as compact hex strings.
    pub proof_hexes: Vec<String>,
}

impl CompactBundle {
    /// Encode a WitnessBundle to compact format.
    pub fn encode(bundle: &WitnessBundle) -> Result<Self, serde_json::Error> {
        let checkpoint_json = serde_json::to_string(&bundle.signed_checkpoint)?;
        let proof_hexes = bundle.proofs_to_compact_hex();
        Ok(Self {
            checkpoint_json,
            proof_hexes,
        })
    }

    /// Decode a CompactBundle back to a WitnessBundle.
    pub fn decode(&self) -> Result<WitnessBundle, BundleDecodeError> {
        let signed_checkpoint: SignedCheckpoint = serde_json::from_str(&self.checkpoint_json)?;
        let mut proofs = Vec::with_capacity(self.proof_hexes.len());
        for (i, hex) in self.proof_hexes.iter().enumerate() {
            let proof = CompactProof::decode_absence_hex(hex).map_err(|e| {
                BundleDecodeError::ProofDecode {
                    index: i,
                    message: e.to_string(),
                }
            })?;
            proofs.push(proof);
        }
        Ok(WitnessBundle {
            signed_checkpoint,
            proofs,
        })
    }

    /// Serialize to a multi-line string.
    pub fn to_wire_format(&self) -> String {
        let mut out = self.checkpoint_json.clone();
        for hex in &self.proof_hexes {
            out.push('\n');
            out.push_str(hex);
        }
        out
    }

    /// Parse from a multi-line string.
    pub fn parse(s: &str) -> Result<Self, BundleDecodeError> {
        let mut lines = s.lines();
        let checkpoint_json = lines
            .next()
            .ok_or(BundleDecodeError::EmptyInput)?
            .to_string();
        let proof_hexes: Vec<String> = lines.map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
        Ok(Self {
            checkpoint_json,
            proof_hexes,
        })
    }
}

/// Errors from bundle decoding.
#[derive(Debug, thiserror::Error)]
pub enum BundleDecodeError {
    #[error("empty input")]
    EmptyInput,

    #[error("JSON decode error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("proof at index {index} decode failed: {message}")]
    ProofDecode { index: usize, message: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AbsenceStore;
    use serde_json::json;

    fn make_test_bundle() -> (WitnessBundle, SignerKey) {
        let mut store = AbsenceStore::new();
        store.record_json(&json!({"recorded": true})).unwrap();
        let checkpoint = store.checkpoint();

        let signer = SignerKey::generate();

        let absent_facts = vec![json!({"missing": 1}), json!({"missing": 2})];
        let proofs = store.prove_absent_batch_json(&absent_facts).unwrap();

        let bundle = WitnessBundle::new(&checkpoint, &signer, proofs);
        (bundle, signer)
    }

    #[test]
    fn test_bundle_verify_all() {
        let (bundle, signer) = make_test_bundle();
        let verifier = signer.verifier();
        assert!(bundle.verify_all(&verifier).is_ok());
    }

    #[test]
    fn test_bundle_wrong_key() {
        let (bundle, _signer) = make_test_bundle();
        let wrong_verifier = SignerKey::generate().verifier();
        assert!(bundle.verify_all(&wrong_verifier).is_err());
    }

    #[test]
    fn test_bundle_serde() {
        let (bundle, signer) = make_test_bundle();
        let verifier = signer.verifier();

        let json = bundle.to_json().unwrap();
        let restored = WitnessBundle::from_json(&json).unwrap();

        assert!(restored.verify_all(&verifier).is_ok());
        assert_eq!(bundle.proof_count(), restored.proof_count());
    }

    #[test]
    fn test_bundle_accessors() {
        let (bundle, _signer) = make_test_bundle();

        assert_eq!(bundle.proof_count(), 2);
        assert!(!bundle.is_empty());
        assert_eq!(bundle.fact_ids().len(), 2);
    }

    #[test]
    fn test_bundle_add_proof() {
        let mut store = AbsenceStore::new();
        store.record_json(&json!({"recorded": true})).unwrap();
        let checkpoint = store.checkpoint();

        let signer = SignerKey::generate();
        let verifier = signer.verifier();

        let proof1 = store
            .prove_absent_json(&json!({"missing": 1}))
            .unwrap();
        let proof2 = store
            .prove_absent_json(&json!({"missing": 2}))
            .unwrap();

        let mut bundle = WitnessBundle::new(&checkpoint, &signer, vec![proof1]);
        assert_eq!(bundle.proof_count(), 1);

        bundle.add_proof(proof2);
        assert_eq!(bundle.proof_count(), 2);
        assert!(bundle.verify_all(&verifier).is_ok());
    }

    #[test]
    fn test_bundle_from_signed() {
        let mut store = AbsenceStore::new();
        store.record_json(&json!({"recorded": true})).unwrap();
        let checkpoint = store.checkpoint();

        let signer = SignerKey::generate();
        let verifier = signer.verifier();

        let signed = SignedCheckpoint::sign(&checkpoint, &signer);
        let proofs = store
            .prove_absent_batch_json(&[json!({"missing": 1})])
            .unwrap();

        let bundle = WitnessBundle::from_signed(signed, proofs);
        assert!(bundle.verify_all(&verifier).is_ok());
    }

    #[test]
    fn test_compact_bundle_roundtrip() {
        let (bundle, signer) = make_test_bundle();
        let verifier = signer.verifier();

        let compact = CompactBundle::encode(&bundle).unwrap();
        let wire = compact.to_wire_format();
        let restored_compact = CompactBundle::parse(&wire).unwrap();
        let restored = restored_compact.decode().unwrap();

        assert!(restored.verify_all(&verifier).is_ok());
        assert_eq!(bundle.proof_count(), restored.proof_count());
    }

    #[test]
    fn test_compact_proofs_hex() {
        let (bundle, _signer) = make_test_bundle();
        let hexes = bundle.proofs_to_compact_hex();
        assert_eq!(hexes.len(), 2);
        for hex in hexes {
            assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }
}
