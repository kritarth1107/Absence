//! Integration tests for signed checkpoints and attestations.

use absence::{
    AbsenceStore, RootAttestation, SignedCheckpoint, SignerKey, VerifierKey, WitnessBundle,
};
use serde_json::json;

#[test]
fn test_full_signing_workflow() {
    let mut store = AbsenceStore::new();
    
    store.record_json(&json!({"user": "alice", "action": "login"})).unwrap();
    store.record_json(&json!({"user": "bob", "action": "login"})).unwrap();
    
    let signer = SignerKey::generate();
    let verifier = signer.verifier();
    
    let signed = store.checkpoint_signed(&signer);
    
    assert!(signed.verify(&verifier).is_ok());
    assert_eq!(signed.checkpoint.epoch, 0);
    assert_eq!(signed.checkpoint.fact_count, 2);
    
    let absent_fact = json!({"user": "eve", "action": "login"});
    let proof = store.prove_absent_json(&absent_fact).unwrap();
    
    assert!(AbsenceStore::verify_absent(&proof, &signed.checkpoint.root).is_ok());
}

#[test]
fn test_attestation_round_trip() {
    let mut store = AbsenceStore::new();
    store.record_json(&json!({"recorded": true})).unwrap();
    let checkpoint = store.checkpoint();
    
    let signer = SignerKey::generate();
    let verifier = signer.verifier();
    
    let absent_fact = json!({"absent": true});
    let proof = store.prove_absent_json(&absent_fact).unwrap();
    
    let attestation = RootAttestation::attest_absent(&proof, &checkpoint, &signer);
    
    let json_str = serde_json::to_string(&attestation).unwrap();
    let restored: RootAttestation = serde_json::from_str(&json_str).unwrap();
    
    assert!(restored.verify_absent(&verifier).is_ok());
    
    let wrong_verifier = SignerKey::generate().verifier();
    assert!(restored.verify_absent(&wrong_verifier).is_err());
}

#[test]
fn test_witness_bundle_round_trip() {
    let mut store = AbsenceStore::new();
    store.record_json(&json!({"recorded": true})).unwrap();
    let checkpoint = store.checkpoint();
    
    let signer = SignerKey::generate();
    let verifier = signer.verifier();
    
    let absent_facts = vec![
        json!({"missing": 1}),
        json!({"missing": 2}),
        json!({"missing": 3}),
    ];
    let proofs = store.prove_absent_batch_json(&absent_facts).unwrap();
    
    let bundle = WitnessBundle::new(&checkpoint, &signer, proofs);
    
    let json_str = serde_json::to_string(&bundle).unwrap();
    let restored: WitnessBundle = serde_json::from_str(&json_str).unwrap();
    
    assert!(restored.verify_all(&verifier).is_ok());
    assert_eq!(restored.proof_count(), 3);
}

#[test]
fn test_tampered_root_detected() {
    let mut store = AbsenceStore::new();
    store.record_json(&json!({"fact": 1})).unwrap();
    let checkpoint = store.checkpoint();
    
    let signer = SignerKey::generate();
    let verifier = signer.verifier();
    
    let mut signed = SignedCheckpoint::sign(&checkpoint, &signer);
    
    assert!(signed.verify(&verifier).is_ok());
    
    signed.checkpoint.root[0] ^= 0xFF;
    
    assert!(signed.verify(&verifier).is_err());
}

#[test]
fn test_wrong_key_detected() {
    let mut store = AbsenceStore::new();
    store.record_json(&json!({"fact": 1})).unwrap();
    let checkpoint = store.checkpoint();
    
    let signer = SignerKey::generate();
    let wrong_verifier = SignerKey::generate().verifier();
    
    let signed = SignedCheckpoint::sign(&checkpoint, &signer);
    
    assert!(signed.verify(&wrong_verifier).is_err());
}

#[test]
fn test_key_persistence() {
    let signer = SignerKey::generate();
    let secret_hex = signer.to_hex();
    let public_hex = signer.verifier().to_hex();
    
    let restored_signer = SignerKey::from_hex(&secret_hex).unwrap();
    let restored_verifier = VerifierKey::from_hex(&public_hex).unwrap();
    
    assert_eq!(restored_signer.to_hex(), secret_hex);
    assert_eq!(restored_verifier.to_hex(), public_hex);
    assert_eq!(restored_signer.verifier().to_hex(), public_hex);
}

#[test]
fn test_store_signed_checkpoint_tracking() {
    let mut store = AbsenceStore::new();
    store.record_json(&json!({"fact": 1})).unwrap();
    
    let signer = SignerKey::generate();
    let verifier = signer.verifier();
    
    assert!(store.signed_checkpoints().is_empty());
    
    let _signed = store.checkpoint_signed(&signer);
    
    assert_eq!(store.signed_checkpoints().len(), 1);
    assert!(store.signed_checkpoint_at(0).is_some());
    
    store.record_json(&json!({"fact": 2})).unwrap();
    let _signed2 = store.checkpoint_signed(&signer);
    
    assert_eq!(store.signed_checkpoints().len(), 2);
    assert!(store.signed_checkpoint_at(1).is_some());
    
    assert!(store.signed_checkpoint_at(0).unwrap().verify(&verifier).is_ok());
    assert!(store.signed_checkpoint_at(1).unwrap().verify(&verifier).is_ok());
}

#[test]
fn test_presence_attestation() {
    let mut store = AbsenceStore::new();
    let fact_id = store.record_json(&json!({"recorded": true})).unwrap();
    let checkpoint = store.checkpoint();
    
    let signer = SignerKey::generate();
    let verifier = signer.verifier();
    
    let proof = store.prove_present(&fact_id).unwrap();
    
    let attestation = RootAttestation::attest_present(&proof, &checkpoint, &signer);
    
    assert!(attestation.verify_present(&verifier).is_ok());
    assert!(attestation.verify_absent(&verifier).is_err());
}

#[test]
fn test_multiple_epochs_signed() {
    let mut store = AbsenceStore::new();
    let signer = SignerKey::generate();
    let verifier = signer.verifier();
    
    store.record_json(&json!({"epoch": 0})).unwrap();
    let signed0 = store.checkpoint_signed(&signer);
    
    store.record_json(&json!({"epoch": 1})).unwrap();
    let signed1 = store.checkpoint_signed(&signer);
    
    store.record_json(&json!({"epoch": 2})).unwrap();
    let signed2 = store.checkpoint_signed(&signer);
    
    assert_eq!(signed0.checkpoint.fact_count, 1);
    assert_eq!(signed1.checkpoint.fact_count, 2);
    assert_eq!(signed2.checkpoint.fact_count, 3);
    
    for signed in [&signed0, &signed1, &signed2] {
        assert!(signed.verify(&verifier).is_ok());
    }
    
    let absent_in_all = json!({"never_recorded": true});
    let proof = store.prove_absent_json(&absent_in_all).unwrap();
    
    assert!(proof.verify(&signed2.checkpoint.root).is_ok());
    
    assert_ne!(signed0.checkpoint.root, signed1.checkpoint.root);
    assert_ne!(signed1.checkpoint.root, signed2.checkpoint.root);
}
