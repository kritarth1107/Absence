//! Signed checkpoints and root attestation for trustless verification.
//!
//! A [`SignedCheckpoint`] wraps a [`Checkpoint`] with an Ed25519 signature
//! over a domain-separated canonical message, allowing a verifier to trust
//! a published checkpoint without trusting the store operator.
//!
//! # Domain Separation
//!
//! The canonical message format is:
//! ```text
//! absence.v1.signed-checkpoint\n
//! epoch:<epoch>\n
//! root:<root_hex>\n
//! fact_count:<fact_count>\n
//! unix_ts:<unix_ts>\n
//! ```
//!
//! This ensures signatures cannot be replayed across different contexts.

use crate::keys::{SignerKey, VerifierKey};
use crate::proof::{MembershipProof, NonMembershipProof, ProofError};
use crate::store::Checkpoint;
use ed25519_dalek::{Signature, Signer, Verifier};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Domain separator for signed checkpoint messages.
pub const SIGNED_CHECKPOINT_DOMAIN: &str = "absence.v1.signed-checkpoint";

/// Length of an Ed25519 signature in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// Errors from signing and verification operations.
#[derive(Debug, Error)]
pub enum SignedError {
    #[error("signature verification failed")]
    SignatureInvalid,

    #[error("invalid signature length: expected {expected}, got {got}")]
    InvalidSignatureLength { expected: usize, got: usize },

    #[error("invalid hex: {0}")]
    HexDecode(#[from] hex::FromHexError),

    #[error("merkle proof verification failed: {0}")]
    ProofInvalid(#[from] ProofError),
}

/// A checkpoint with an Ed25519 signature for trustless verification.
///
/// The signature is over a canonical, domain-separated message derived from
/// the checkpoint fields. Verifiers can check the signature against an
/// expected [`VerifierKey`] without trusting the store operator.
///
/// # Example
///
/// ```
/// use absence::{AbsenceStore, SignerKey, SignedCheckpoint};
///
/// let mut store = AbsenceStore::new();
/// store.record_json(&serde_json::json!({"fact": 1})).unwrap();
/// let checkpoint = store.checkpoint();
///
/// let signer = SignerKey::generate();
/// let signed = SignedCheckpoint::sign(&checkpoint, &signer);
///
/// // Verifier trusts only the public key
/// let verifier = signer.verifier();
/// assert!(signed.verify(&verifier).is_ok());
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedCheckpoint {
    /// The underlying checkpoint data.
    pub checkpoint: Checkpoint,
    /// Ed25519 signature over the canonical message (hex-encoded).
    pub signature: String,
    /// Public key that created this signature (hex-encoded).
    pub signer_public_key: String,
}

impl SignedCheckpoint {
    /// Sign a checkpoint with the given signing key.
    ///
    /// Creates a canonical message from the checkpoint and signs it using
    /// the Ed25519 signing key.
    pub fn sign(checkpoint: &Checkpoint, signer: &SignerKey) -> Self {
        let message = Self::canonical_message(checkpoint);
        let signature = signer.signing_key().sign(message.as_bytes());

        Self {
            checkpoint: *checkpoint,
            signature: hex::encode(signature.to_bytes()),
            signer_public_key: signer.verifier().to_hex(),
        }
    }

    /// Verify the signature against the given verifier key.
    ///
    /// Returns `Ok(())` if the signature is valid for the checkpoint data
    /// and was created by the holder of the corresponding signing key.
    pub fn verify(&self, verifier: &VerifierKey) -> Result<(), SignedError> {
        let signature_bytes = hex::decode(&self.signature)?;
        if signature_bytes.len() != SIGNATURE_LEN {
            return Err(SignedError::InvalidSignatureLength {
                expected: SIGNATURE_LEN,
                got: signature_bytes.len(),
            });
        }

        let mut sig_arr = [0u8; SIGNATURE_LEN];
        sig_arr.copy_from_slice(&signature_bytes);
        let signature = Signature::from_bytes(&sig_arr);

        let message = Self::canonical_message(&self.checkpoint);
        verifier
            .verifying_key()
            .verify(message.as_bytes(), &signature)
            .map_err(|_| SignedError::SignatureInvalid)
    }

    /// Verify the signature matches the embedded public key.
    ///
    /// This is a convenience method when the verifier key is not known
    /// ahead of time — it extracts the key from the signed checkpoint.
    /// Note: this only proves internal consistency, not trust!
    pub fn verify_self_consistent(&self) -> Result<VerifierKey, SignedError> {
        let verifier = VerifierKey::from_hex(&self.signer_public_key)
            .map_err(|_| SignedError::SignatureInvalid)?;
        self.verify(&verifier)?;
        Ok(verifier)
    }

    /// Build the canonical message for signing/verification.
    ///
    /// Format:
    /// ```text
    /// absence.v1.signed-checkpoint
    /// epoch:<epoch>
    /// root:<root_hex>
    /// fact_count:<fact_count>
    /// unix_ts:<unix_ts>
    /// ```
    pub fn canonical_message(checkpoint: &Checkpoint) -> String {
        format!(
            "{}\nepoch:{}\nroot:{}\nfact_count:{}\nunix_ts:{}\n",
            SIGNED_CHECKPOINT_DOMAIN,
            checkpoint.epoch,
            hex::encode(checkpoint.root),
            checkpoint.fact_count,
            checkpoint.unix_ts,
        )
    }

    /// Get the signature as raw bytes.
    pub fn signature_bytes(&self) -> Result<[u8; SIGNATURE_LEN], SignedError> {
        let bytes = hex::decode(&self.signature)?;
        if bytes.len() != SIGNATURE_LEN {
            return Err(SignedError::InvalidSignatureLength {
                expected: SIGNATURE_LEN,
                got: bytes.len(),
            });
        }
        let mut arr = [0u8; SIGNATURE_LEN];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }

    /// Get the signer's public key.
    pub fn signer_verifier(&self) -> Result<VerifierKey, SignedError> {
        VerifierKey::from_hex(&self.signer_public_key).map_err(|_| SignedError::SignatureInvalid)
    }
}

/// Sign a checkpoint and return the signed version.
///
/// Convenience function that wraps [`SignedCheckpoint::sign`].
pub fn sign_checkpoint(checkpoint: &Checkpoint, signer: &SignerKey) -> SignedCheckpoint {
    SignedCheckpoint::sign(checkpoint, signer)
}

/// Verify a signed checkpoint against a verifier key.
///
/// Convenience function that wraps [`SignedCheckpoint::verify`].
pub fn verify_signed_checkpoint(
    signed: &SignedCheckpoint,
    verifier: &VerifierKey,
) -> Result<(), SignedError> {
    signed.verify(verifier)
}

/// A root attestation binds an absence or membership proof to a signed checkpoint.
///
/// This allows a verifier to trust both:
/// 1. The Merkle proof is valid against the checkpoint's root
/// 2. The checkpoint root was signed by a trusted key
///
/// # Example
///
/// ```
/// use absence::{AbsenceStore, SignerKey, RootAttestation};
/// use serde_json::json;
///
/// let mut store = AbsenceStore::new();
/// store.record_json(&json!({"recorded": true})).unwrap();
/// let checkpoint = store.checkpoint();
///
/// let signer = SignerKey::generate();
/// let absent_fact = json!({"absent": true});
/// let proof = store.prove_absent_json(&absent_fact).unwrap();
///
/// let attestation = RootAttestation::attest_absent(&proof, &checkpoint, &signer);
///
/// // Verifier checks both proof and signature
/// let verifier = signer.verifier();
/// assert!(attestation.verify_absent(&verifier).is_ok());
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RootAttestation {
    /// The signed checkpoint that attests to the root.
    pub signed_checkpoint: SignedCheckpoint,
    /// The absence proof (if attesting absence).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub absence_proof: Option<NonMembershipProof>,
    /// The membership proof (if attesting membership).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub membership_proof: Option<MembershipProof>,
}

impl RootAttestation {
    /// Create an attestation for an absence (non-membership) proof.
    pub fn attest_absent(
        proof: &NonMembershipProof,
        checkpoint: &Checkpoint,
        signer: &SignerKey,
    ) -> Self {
        Self {
            signed_checkpoint: SignedCheckpoint::sign(checkpoint, signer),
            absence_proof: Some(proof.clone()),
            membership_proof: None,
        }
    }

    /// Create an attestation for a membership (presence) proof.
    pub fn attest_present(
        proof: &MembershipProof,
        checkpoint: &Checkpoint,
        signer: &SignerKey,
    ) -> Self {
        Self {
            signed_checkpoint: SignedCheckpoint::sign(checkpoint, signer),
            absence_proof: None,
            membership_proof: Some(proof.clone()),
        }
    }

    /// Verify the attestation as an absence proof.
    ///
    /// Checks:
    /// 1. The checkpoint signature is valid against the verifier key
    /// 2. The absence proof is valid against the checkpoint's root
    ///
    /// Returns an error if either check fails or no absence proof is present.
    pub fn verify_absent(&self, verifier: &VerifierKey) -> Result<(), SignedError> {
        self.signed_checkpoint.verify(verifier)?;

        let proof = self
            .absence_proof
            .as_ref()
            .ok_or(SignedError::SignatureInvalid)?;
        proof.verify(&self.signed_checkpoint.checkpoint.root)?;
        Ok(())
    }

    /// Verify the attestation as a membership proof.
    ///
    /// Checks:
    /// 1. The checkpoint signature is valid against the verifier key
    /// 2. The membership proof is valid against the checkpoint's root
    ///
    /// Returns an error if either check fails or no membership proof is present.
    pub fn verify_present(&self, verifier: &VerifierKey) -> Result<(), SignedError> {
        self.signed_checkpoint.verify(verifier)?;

        let proof = self
            .membership_proof
            .as_ref()
            .ok_or(SignedError::SignatureInvalid)?;
        proof.verify(&self.signed_checkpoint.checkpoint.root)?;
        Ok(())
    }

    /// Get the checkpoint this attestation is bound to.
    pub fn checkpoint(&self) -> &Checkpoint {
        &self.signed_checkpoint.checkpoint
    }

    /// Get the fact ID from the proof (absence or membership).
    pub fn fact_id(&self) -> Option<crate::FactId> {
        if let Some(ref p) = self.absence_proof {
            Some(p.fact_id())
        } else {
            self.membership_proof.as_ref().map(|p| p.fact_id())
        }
    }
}

/// Verify an attested absence proof.
///
/// Convenience function that wraps [`RootAttestation::verify_absent`].
pub fn verify_attested_absent(
    attestation: &RootAttestation,
    verifier: &VerifierKey,
) -> Result<(), SignedError> {
    attestation.verify_absent(verifier)
}

/// Verify an attested membership proof.
///
/// Convenience function that wraps [`RootAttestation::verify_present`].
pub fn verify_attested_present(
    attestation: &RootAttestation,
    verifier: &VerifierKey,
) -> Result<(), SignedError> {
    attestation.verify_present(verifier)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AbsenceStore;
    use serde_json::json;

    fn make_test_checkpoint() -> Checkpoint {
        let mut store = AbsenceStore::new();
        store.record_json(&json!({"test": "data"})).unwrap();
        store.checkpoint()
    }

    #[test]
    fn test_sign_and_verify() {
        let checkpoint = make_test_checkpoint();
        let signer = SignerKey::generate();
        let verifier = signer.verifier();

        let signed = SignedCheckpoint::sign(&checkpoint, &signer);
        assert!(signed.verify(&verifier).is_ok());
    }

    #[test]
    fn test_canonical_message_format() {
        let checkpoint = Checkpoint {
            epoch: 42,
            root: [0xAB; 32],
            fact_count: 100,
            unix_ts: 1700000000,
        };
        let msg = SignedCheckpoint::canonical_message(&checkpoint);
        assert!(msg.starts_with("absence.v1.signed-checkpoint\n"));
        assert!(msg.contains("epoch:42\n"));
        assert!(msg.contains(&format!("root:{}\n", hex::encode([0xAB; 32]))));
        assert!(msg.contains("fact_count:100\n"));
        assert!(msg.contains("unix_ts:1700000000\n"));
    }

    #[test]
    fn test_wrong_key_fails() {
        let checkpoint = make_test_checkpoint();
        let signer = SignerKey::generate();
        let wrong_verifier = SignerKey::generate().verifier();

        let signed = SignedCheckpoint::sign(&checkpoint, &signer);
        assert!(matches!(
            signed.verify(&wrong_verifier),
            Err(SignedError::SignatureInvalid)
        ));
    }

    #[test]
    fn test_tampered_checkpoint_fails() {
        let checkpoint = make_test_checkpoint();
        let signer = SignerKey::generate();
        let verifier = signer.verifier();

        let mut signed = SignedCheckpoint::sign(&checkpoint, &signer);
        signed.checkpoint.epoch += 1; // tamper
        assert!(signed.verify(&verifier).is_err());
    }

    #[test]
    fn test_tampered_root_fails() {
        let checkpoint = make_test_checkpoint();
        let signer = SignerKey::generate();
        let verifier = signer.verifier();

        let mut signed = SignedCheckpoint::sign(&checkpoint, &signer);
        signed.checkpoint.root[0] ^= 0xFF; // tamper
        assert!(signed.verify(&verifier).is_err());
    }

    #[test]
    fn test_verify_self_consistent() {
        let checkpoint = make_test_checkpoint();
        let signer = SignerKey::generate();

        let signed = SignedCheckpoint::sign(&checkpoint, &signer);
        let extracted = signed.verify_self_consistent().unwrap();
        assert_eq!(extracted.to_hex(), signer.verifier().to_hex());
    }

    #[test]
    fn test_signed_checkpoint_serde() {
        let checkpoint = make_test_checkpoint();
        let signer = SignerKey::generate();
        let verifier = signer.verifier();

        let signed = SignedCheckpoint::sign(&checkpoint, &signer);
        let json = serde_json::to_string_pretty(&signed).unwrap();
        let restored: SignedCheckpoint = serde_json::from_str(&json).unwrap();

        assert!(restored.verify(&verifier).is_ok());
        assert_eq!(signed.checkpoint, restored.checkpoint);
    }

    #[test]
    fn test_convenience_functions() {
        let checkpoint = make_test_checkpoint();
        let signer = SignerKey::generate();
        let verifier = signer.verifier();

        let signed = sign_checkpoint(&checkpoint, &signer);
        assert!(verify_signed_checkpoint(&signed, &verifier).is_ok());
    }

    #[test]
    fn test_signature_bytes() {
        let checkpoint = make_test_checkpoint();
        let signer = SignerKey::generate();

        let signed = SignedCheckpoint::sign(&checkpoint, &signer);
        let bytes = signed.signature_bytes().unwrap();
        assert_eq!(bytes.len(), SIGNATURE_LEN);
    }

    #[test]
    fn test_signer_verifier_extraction() {
        let checkpoint = make_test_checkpoint();
        let signer = SignerKey::generate();

        let signed = SignedCheckpoint::sign(&checkpoint, &signer);
        let extracted = signed.signer_verifier().unwrap();
        assert_eq!(extracted.to_hex(), signer.verifier().to_hex());
    }

    // ============= ROOT ATTESTATION TESTS =============

    #[test]
    fn test_attestation_absent() {
        let mut store = AbsenceStore::new();
        store.record_json(&json!({"recorded": true})).unwrap();
        let checkpoint = store.checkpoint();

        let signer = SignerKey::generate();
        let verifier = signer.verifier();

        let absent = crate::FactId::from_json_value(&json!({"absent": true}));
        let proof = store.prove_absent(&absent).unwrap();

        let attestation = RootAttestation::attest_absent(&proof, &checkpoint, &signer);
        assert!(attestation.verify_absent(&verifier).is_ok());
    }

    #[test]
    fn test_attestation_present() {
        let mut store = AbsenceStore::new();
        let fact_id = store.record_json(&json!({"recorded": true})).unwrap();
        let checkpoint = store.checkpoint();

        let signer = SignerKey::generate();
        let verifier = signer.verifier();

        let proof = store.prove_present(&fact_id).unwrap();

        let attestation = RootAttestation::attest_present(&proof, &checkpoint, &signer);
        assert!(attestation.verify_present(&verifier).is_ok());
    }

    #[test]
    fn test_attestation_wrong_key() {
        let mut store = AbsenceStore::new();
        store.record_json(&json!({"recorded": true})).unwrap();
        let checkpoint = store.checkpoint();

        let signer = SignerKey::generate();
        let wrong_verifier = SignerKey::generate().verifier();

        let absent = crate::FactId::from_json_value(&json!({"absent": true}));
        let proof = store.prove_absent(&absent).unwrap();

        let attestation = RootAttestation::attest_absent(&proof, &checkpoint, &signer);
        assert!(attestation.verify_absent(&wrong_verifier).is_err());
    }

    #[test]
    fn test_attestation_tampered_root() {
        let mut store = AbsenceStore::new();
        store.record_json(&json!({"recorded": true})).unwrap();
        let checkpoint = store.checkpoint();

        let signer = SignerKey::generate();
        let verifier = signer.verifier();

        let absent = crate::FactId::from_json_value(&json!({"absent": true}));
        let proof = store.prove_absent(&absent).unwrap();

        let mut attestation = RootAttestation::attest_absent(&proof, &checkpoint, &signer);
        attestation.signed_checkpoint.checkpoint.root[0] ^= 0xFF;

        // Signature check fails (root was signed, then tampered)
        assert!(attestation.verify_absent(&verifier).is_err());
    }

    #[test]
    fn test_attestation_serde() {
        let mut store = AbsenceStore::new();
        store.record_json(&json!({"recorded": true})).unwrap();
        let checkpoint = store.checkpoint();

        let signer = SignerKey::generate();
        let verifier = signer.verifier();

        let absent = crate::FactId::from_json_value(&json!({"absent": true}));
        let proof = store.prove_absent(&absent).unwrap();

        let attestation = RootAttestation::attest_absent(&proof, &checkpoint, &signer);
        let json_str = serde_json::to_string_pretty(&attestation).unwrap();
        let restored: RootAttestation = serde_json::from_str(&json_str).unwrap();

        assert!(restored.verify_absent(&verifier).is_ok());
    }

    #[test]
    fn test_attestation_fact_id() {
        let mut store = AbsenceStore::new();
        store.record_json(&json!({"recorded": true})).unwrap();
        let checkpoint = store.checkpoint();

        let signer = SignerKey::generate();

        let absent = crate::FactId::from_json_value(&json!({"absent": true}));
        let proof = store.prove_absent(&absent).unwrap();

        let attestation = RootAttestation::attest_absent(&proof, &checkpoint, &signer);
        let extracted = attestation.fact_id().unwrap();
        assert_eq!(extracted.to_hex(), absent.to_hex());
    }

    #[test]
    fn test_verify_attested_convenience() {
        let mut store = AbsenceStore::new();
        store.record_json(&json!({"recorded": true})).unwrap();
        let checkpoint = store.checkpoint();

        let signer = SignerKey::generate();
        let verifier = signer.verifier();

        let absent = crate::FactId::from_json_value(&json!({"absent": true}));
        let proof = store.prove_absent(&absent).unwrap();

        let attestation = RootAttestation::attest_absent(&proof, &checkpoint, &signer);
        assert!(verify_attested_absent(&attestation, &verifier).is_ok());
    }
}
