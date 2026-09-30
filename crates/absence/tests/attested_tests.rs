//! Integration tests for attested proofs (v0.6.0)

use absence::{AbsenceStore, AttestedConsistency, AttestedInterval, FactId, SignerKey};
use serde_json::json;

fn fid(v: serde_json::Value) -> FactId {
    FactId::from_json_value(&v)
}

// ============= ATTESTED CONSISTENCY TESTS =============

#[test]
fn attested_consistency_basic() {
    let mut store = AbsenceStore::new();
    store.record_json(&json!({"day": 1})).unwrap();
    let signer = SignerKey::generate();
    let _cp0 = store.checkpoint_signed(&signer);

    store.record_json(&json!({"day": 2})).unwrap();
    let _cp1 = store.checkpoint_signed(&signer);

    let attested = store.attest_consistency(0, 1, &signer).unwrap();
    let verifier = signer.verifier();

    assert!(attested.verify(&verifier).is_ok());
    assert_eq!(attested.facts_added(), 1);
    assert_eq!(attested.old_checkpoint().epoch, 0);
    assert_eq!(attested.new_checkpoint().epoch, 1);
}

#[test]
fn attested_consistency_multi_epoch() {
    let mut store = AbsenceStore::new();
    let signer = SignerKey::generate();

    for i in 0..5 {
        store.record_json(&json!({"epoch": i})).unwrap();
        store.checkpoint_signed(&signer);
    }

    let attested = store.attest_consistency(1, 4, &signer).unwrap();
    let verifier = signer.verifier();

    assert!(attested.verify(&verifier).is_ok());
    assert_eq!(attested.facts_added(), 3);
    assert_eq!(attested.old_checkpoint().epoch, 1);
    assert_eq!(attested.new_checkpoint().epoch, 4);
}

#[test]
fn attested_consistency_wrong_key_fails() {
    let mut store = AbsenceStore::new();
    store.record_json(&json!({"day": 1})).unwrap();
    let signer = SignerKey::generate();
    let _cp0 = store.checkpoint_signed(&signer);

    store.record_json(&json!({"day": 2})).unwrap();
    let _cp1 = store.checkpoint_signed(&signer);

    let attested = store.attest_consistency(0, 1, &signer).unwrap();
    let wrong_verifier = SignerKey::generate().verifier();

    assert!(attested.verify(&wrong_verifier).is_err());
}

#[test]
fn attested_consistency_tampered_old_checkpoint_fails() {
    let mut store = AbsenceStore::new();
    store.record_json(&json!({"day": 1})).unwrap();
    let signer = SignerKey::generate();
    let _cp0 = store.checkpoint_signed(&signer);

    store.record_json(&json!({"day": 2})).unwrap();
    let _cp1 = store.checkpoint_signed(&signer);

    let mut attested = store.attest_consistency(0, 1, &signer).unwrap();
    let verifier = signer.verifier();

    attested.old_signed.checkpoint.epoch = 99;
    assert!(attested.verify(&verifier).is_err());
}

#[test]
fn attested_consistency_tampered_new_checkpoint_fails() {
    let mut store = AbsenceStore::new();
    store.record_json(&json!({"day": 1})).unwrap();
    let signer = SignerKey::generate();
    let _cp0 = store.checkpoint_signed(&signer);

    store.record_json(&json!({"day": 2})).unwrap();
    let _cp1 = store.checkpoint_signed(&signer);

    let mut attested = store.attest_consistency(0, 1, &signer).unwrap();
    let verifier = signer.verifier();

    attested.new_signed.checkpoint.root[0] ^= 0xFF;
    assert!(attested.verify(&verifier).is_err());
}

#[test]
fn attested_consistency_swapped_checkpoints_fail() {
    let mut store = AbsenceStore::new();
    store.record_json(&json!({"day": 1})).unwrap();
    let signer = SignerKey::generate();
    let cp0 = store.checkpoint();

    store.record_json(&json!({"day": 2})).unwrap();
    let cp1 = store.checkpoint();

    let interval_proof = store.prove_absent_interval(&fid(json!({"absent": true})), 0, 1).unwrap();
    
    let wrong_attested = AttestedConsistency::attest(
        &cp1,
        &cp0,
        interval_proof.consistency_proof.clone(),
        &signer,
    );
    let verifier = signer.verifier();

    assert!(wrong_attested.verify(&verifier).is_err());
}

#[test]
fn attested_consistency_serde_roundtrip() {
    let mut store = AbsenceStore::new();
    store.record_json(&json!({"day": 1})).unwrap();
    let signer = SignerKey::generate();
    let _cp0 = store.checkpoint_signed(&signer);

    store.record_json(&json!({"day": 2})).unwrap();
    let _cp1 = store.checkpoint_signed(&signer);

    let attested = store.attest_consistency(0, 1, &signer).unwrap();
    let verifier = signer.verifier();

    let json_str = serde_json::to_string_pretty(&attested).unwrap();
    let restored: AttestedConsistency = serde_json::from_str(&json_str).unwrap();

    assert!(restored.verify(&verifier).is_ok());
    assert_eq!(restored.facts_added(), attested.facts_added());
}

#[test]
fn attested_consistency_self_consistent() {
    let mut store = AbsenceStore::new();
    store.record_json(&json!({"day": 1})).unwrap();
    let signer = SignerKey::generate();
    let _cp0 = store.checkpoint_signed(&signer);

    store.record_json(&json!({"day": 2})).unwrap();
    let _cp1 = store.checkpoint_signed(&signer);

    let attested = store.attest_consistency(0, 1, &signer).unwrap();
    let extracted = attested.verify_self_consistent().unwrap();
    
    assert_eq!(extracted.to_hex(), signer.verifier().to_hex());
}

// ============= ATTESTED INTERVAL TESTS =============

#[test]
fn attested_interval_basic() {
    let mut store = AbsenceStore::new();
    store.record_json(&json!({"day": 1})).unwrap();
    let signer = SignerKey::generate();
    let _cp0 = store.checkpoint_signed(&signer);

    store.record_json(&json!({"day": 2})).unwrap();
    let _cp1 = store.checkpoint_signed(&signer);

    let absent = fid(json!({"never_added": true}));
    let attested = store.attest_interval_absent(&absent, 0, 1, &signer).unwrap();
    let verifier = signer.verifier();

    assert!(attested.verify(&verifier).is_ok());
    assert_eq!(attested.fact_id().to_hex(), absent.to_hex());
    assert_eq!(attested.from_checkpoint().epoch, 0);
    assert_eq!(attested.to_checkpoint().epoch, 1);
}

#[test]
fn attested_interval_multi_epoch() {
    let mut store = AbsenceStore::new();
    let signer = SignerKey::generate();

    for i in 0..5 {
        store.record_json(&json!({"epoch": i})).unwrap();
        store.checkpoint_signed(&signer);
    }

    let absent = fid(json!({"never_added": true}));
    let attested = store.attest_interval_absent(&absent, 1, 4, &signer).unwrap();
    let verifier = signer.verifier();

    assert!(attested.verify(&verifier).is_ok());
    assert_eq!(attested.facts_added_count(), 3);
    assert_eq!(attested.epoch_span(), 3);
}

#[test]
fn attested_interval_wrong_key_fails() {
    let mut store = AbsenceStore::new();
    store.record_json(&json!({"day": 1})).unwrap();
    let signer = SignerKey::generate();
    let _cp0 = store.checkpoint_signed(&signer);

    store.record_json(&json!({"day": 2})).unwrap();
    let _cp1 = store.checkpoint_signed(&signer);

    let absent = fid(json!({"never_added": true}));
    let attested = store.attest_interval_absent(&absent, 0, 1, &signer).unwrap();
    let wrong_verifier = SignerKey::generate().verifier();

    assert!(attested.verify(&wrong_verifier).is_err());
}

#[test]
fn attested_interval_tampered_from_checkpoint_fails() {
    let mut store = AbsenceStore::new();
    store.record_json(&json!({"day": 1})).unwrap();
    let signer = SignerKey::generate();
    let _cp0 = store.checkpoint_signed(&signer);

    store.record_json(&json!({"day": 2})).unwrap();
    let _cp1 = store.checkpoint_signed(&signer);

    let absent = fid(json!({"never_added": true}));
    let mut attested = store.attest_interval_absent(&absent, 0, 1, &signer).unwrap();
    let verifier = signer.verifier();

    attested.from_signed.checkpoint.root[0] ^= 0xFF;
    assert!(attested.verify(&verifier).is_err());
}

#[test]
fn attested_interval_tampered_to_checkpoint_fails() {
    let mut store = AbsenceStore::new();
    store.record_json(&json!({"day": 1})).unwrap();
    let signer = SignerKey::generate();
    let _cp0 = store.checkpoint_signed(&signer);

    store.record_json(&json!({"day": 2})).unwrap();
    let _cp1 = store.checkpoint_signed(&signer);

    let absent = fid(json!({"never_added": true}));
    let mut attested = store.attest_interval_absent(&absent, 0, 1, &signer).unwrap();
    let verifier = signer.verifier();

    attested.to_signed.checkpoint.epoch = 99;
    assert!(attested.verify(&verifier).is_err());
}

#[test]
fn attested_interval_tampered_proof_fails() {
    let mut store = AbsenceStore::new();
    store.record_json(&json!({"day": 1})).unwrap();
    let signer = SignerKey::generate();
    let _cp0 = store.checkpoint_signed(&signer);

    store.record_json(&json!({"day": 2})).unwrap();
    let _cp1 = store.checkpoint_signed(&signer);

    let absent = fid(json!({"never_added": true}));
    let mut attested = store.attest_interval_absent(&absent, 0, 1, &signer).unwrap();
    let verifier = signer.verifier();

    attested.interval_proof.from_root[0] ^= 0xFF;
    assert!(attested.verify(&verifier).is_err());
}

#[test]
fn attested_interval_fact_added_during_interval_fails() {
    let mut store = AbsenceStore::new();
    store.record_json(&json!({"day": 1})).unwrap();
    let signer = SignerKey::generate();
    let _cp0 = store.checkpoint_signed(&signer);

    let will_add = fid(json!({"will_add": true}));
    store.record(&will_add).unwrap();
    store.checkpoint_signed(&signer);

    let result = store.attest_interval_absent(&will_add, 0, 1, &signer);
    assert!(result.is_err());
}

#[test]
fn attested_interval_serde_roundtrip() {
    let mut store = AbsenceStore::new();
    store.record_json(&json!({"day": 1})).unwrap();
    let signer = SignerKey::generate();
    let _cp0 = store.checkpoint_signed(&signer);

    store.record_json(&json!({"day": 2})).unwrap();
    let _cp1 = store.checkpoint_signed(&signer);

    let absent = fid(json!({"never_added": true}));
    let attested = store.attest_interval_absent(&absent, 0, 1, &signer).unwrap();
    let verifier = signer.verifier();

    let json_str = serde_json::to_string_pretty(&attested).unwrap();
    let restored: AttestedInterval = serde_json::from_str(&json_str).unwrap();

    assert!(restored.verify(&verifier).is_ok());
    assert_eq!(restored.fact_id().to_hex(), absent.to_hex());
}

#[test]
fn attested_interval_self_consistent() {
    let mut store = AbsenceStore::new();
    store.record_json(&json!({"day": 1})).unwrap();
    let signer = SignerKey::generate();
    let _cp0 = store.checkpoint_signed(&signer);

    store.record_json(&json!({"day": 2})).unwrap();
    let _cp1 = store.checkpoint_signed(&signer);

    let absent = fid(json!({"never_added": true}));
    let attested = store.attest_interval_absent(&absent, 0, 1, &signer).unwrap();
    let extracted = attested.verify_self_consistent().unwrap();
    
    assert_eq!(extracted.to_hex(), signer.verifier().to_hex());
}

#[test]
fn attested_interval_json_variant() {
    let mut store = AbsenceStore::new();
    store.record_json(&json!({"day": 1})).unwrap();
    let signer = SignerKey::generate();
    let _cp0 = store.checkpoint_signed(&signer);

    store.record_json(&json!({"day": 2})).unwrap();
    let _cp1 = store.checkpoint_signed(&signer);

    let attested = store
        .attest_interval_absent_json(&json!({"never_added": true}), 0, 1, &signer)
        .unwrap();
    let verifier = signer.verifier();

    assert!(attested.verify(&verifier).is_ok());
}

// ============= MIXED SIGNER TESTS =============

#[test]
fn attested_consistency_different_signers_detected() {
    let mut store = AbsenceStore::new();
    store.record_json(&json!({"day": 1})).unwrap();
    let cp0 = store.checkpoint();

    store.record_json(&json!({"day": 2})).unwrap();
    let cp1 = store.checkpoint();

    let signer1 = SignerKey::generate();
    let signer2 = SignerKey::generate();
    
    let interval_proof = store.prove_absent_interval(&fid(json!({"absent": true})), 0, 1).unwrap();

    let old_signed = absence::SignedCheckpoint::sign(&cp0, &signer1);
    let new_signed = absence::SignedCheckpoint::sign(&cp1, &signer2);

    let attested = AttestedConsistency::from_signed(
        old_signed,
        new_signed,
        interval_proof.consistency_proof,
    );

    assert!(attested.verify(&signer1.verifier()).is_err());
    assert!(attested.verify(&signer2.verifier()).is_err());
}

#[test]
fn attested_interval_different_signers_detected() {
    let mut store = AbsenceStore::new();
    store.record_json(&json!({"day": 1})).unwrap();
    let cp0 = store.checkpoint();

    store.record_json(&json!({"day": 2})).unwrap();
    let cp1 = store.checkpoint();

    let signer1 = SignerKey::generate();
    let signer2 = SignerKey::generate();
    
    let absent = fid(json!({"absent": true}));
    let interval_proof = store.prove_absent_interval(&absent, 0, 1).unwrap();

    let from_signed = absence::SignedCheckpoint::sign(&cp0, &signer1);
    let to_signed = absence::SignedCheckpoint::sign(&cp1, &signer2);

    let attested = AttestedInterval::from_signed(
        from_signed,
        to_signed,
        interval_proof,
    );

    assert!(attested.verify(&signer1.verifier()).is_err());
    assert!(attested.verify(&signer2.verifier()).is_err());
}
