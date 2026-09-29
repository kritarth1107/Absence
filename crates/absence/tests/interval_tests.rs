//! Integration tests for interval absence proofs (v0.5.0)

use absence::{AbsenceStore, FactId, IntervalAbsenceProof, IntervalError, StoreError};
use serde_json::json;

fn fid(v: serde_json::Value) -> FactId {
    FactId::from_json_value(&v)
}

#[test]
fn interval_absence_basic() {
    let mut store = AbsenceStore::new();

    store.record_json(&json!({"a": 1})).unwrap();
    store.checkpoint(); // epoch 0

    store.record_json(&json!({"b": 2})).unwrap();
    store.checkpoint(); // epoch 1

    store.record_json(&json!({"c": 3})).unwrap();
    store.checkpoint(); // epoch 2

    let absent = fid(json!({"never_added": true}));
    let proof = store.prove_absent_interval(&absent, 0, 2).unwrap();

    assert_eq!(proof.from_epoch, 0);
    assert_eq!(proof.to_epoch, 2);
    assert_eq!(proof.facts_added_count(), 2);
    assert!(!proof.is_single_epoch());

    let cp0 = store.checkpoint_at(0).unwrap();
    let cp2 = store.checkpoint_at(2).unwrap();
    proof.verify_checkpoints(cp0, cp2).unwrap();
}

#[test]
fn interval_absence_single_epoch() {
    let mut store = AbsenceStore::new();
    store.record_json(&json!({"a": 1})).unwrap();
    store.checkpoint(); // epoch 0

    let absent = fid(json!({"absent": true}));
    let proof = store.prove_absent_interval(&absent, 0, 0).unwrap();

    assert!(proof.is_single_epoch());
    assert_eq!(proof.epoch_span(), 0);
    assert_eq!(proof.facts_added_count(), 0);

    let cp0 = store.checkpoint_at(0).unwrap();
    proof.verify_checkpoints(cp0, cp0).unwrap();
}

#[test]
fn interval_absence_fails_if_present_at_start() {
    let mut store = AbsenceStore::new();

    let present = fid(json!({"present": true}));
    store.record(&present).unwrap();
    store.checkpoint(); // epoch 0

    store.record_json(&json!({"b": 2})).unwrap();
    store.checkpoint(); // epoch 1

    match store.prove_absent_interval(&present, 0, 1) {
        Err(StoreError::IntervalError(IntervalError::PresentAtStart)) => {}
        other => panic!("expected PresentAtStart, got {:?}", other),
    }
}

#[test]
fn interval_absence_fails_if_added_during_interval() {
    let mut store = AbsenceStore::new();

    store.record_json(&json!({"a": 1})).unwrap();
    store.checkpoint(); // epoch 0

    let will_add = fid(json!({"will_add": true}));
    store.record(&will_add).unwrap();
    store.checkpoint(); // epoch 1

    match store.prove_absent_interval(&will_add, 0, 1) {
        Err(StoreError::IntervalError(IntervalError::AddedDuringInterval { step: 0 })) => {}
        other => panic!("expected AddedDuringInterval, got {:?}", other),
    }
}

#[test]
fn interval_absence_invalid_epoch_range() {
    let mut store = AbsenceStore::new();
    store.record_json(&json!({"a": 1})).unwrap();
    store.checkpoint(); // epoch 0
    store.record_json(&json!({"b": 2})).unwrap();
    store.checkpoint(); // epoch 1

    let absent = fid(json!({"absent": true}));
    match store.prove_absent_interval(&absent, 1, 0) {
        Err(StoreError::IntervalError(IntervalError::InvalidEpochRange { from: 1, to: 0 })) => {}
        other => panic!("expected InvalidEpochRange, got {:?}", other),
    }
}

#[test]
fn interval_absence_unknown_epoch() {
    let mut store = AbsenceStore::new();
    store.record_json(&json!({"a": 1})).unwrap();
    store.checkpoint(); // epoch 0

    let absent = fid(json!({"absent": true}));

    match store.prove_absent_interval(&absent, 99, 100) {
        Err(StoreError::UnknownEpoch(99)) => {}
        other => panic!("expected UnknownEpoch(99), got {:?}", other),
    }

    match store.prove_absent_interval(&absent, 0, 100) {
        Err(StoreError::UnknownEpoch(100)) => {}
        other => panic!("expected UnknownEpoch(100), got {:?}", other),
    }
}

#[test]
fn interval_absence_json_variant() {
    let mut store = AbsenceStore::new();
    store.record_json(&json!({"a": 1})).unwrap();
    store.checkpoint();
    store.record_json(&json!({"b": 2})).unwrap();
    store.checkpoint();

    let proof = store
        .prove_absent_interval_json(&json!({"absent": true}), 0, 1)
        .unwrap();

    let cp0 = store.checkpoint_at(0).unwrap();
    let cp1 = store.checkpoint_at(1).unwrap();
    proof.verify_checkpoints(cp0, cp1).unwrap();
}

#[test]
fn interval_absence_serde_roundtrip() {
    let mut store = AbsenceStore::new();
    store.record_json(&json!({"a": 1})).unwrap();
    store.checkpoint();
    store.record_json(&json!({"b": 2})).unwrap();
    store.checkpoint();
    store.record_json(&json!({"c": 3})).unwrap();
    store.checkpoint();

    let absent = fid(json!({"absent": true}));
    let proof = store.prove_absent_interval(&absent, 0, 2).unwrap();

    let json_str = serde_json::to_string_pretty(&proof).unwrap();
    let restored: IntervalAbsenceProof = serde_json::from_str(&json_str).unwrap();

    let cp0 = store.checkpoint_at(0).unwrap();
    let cp2 = store.checkpoint_at(2).unwrap();
    restored.verify_checkpoints(cp0, cp2).unwrap();

    assert_eq!(restored.from_epoch, proof.from_epoch);
    assert_eq!(restored.to_epoch, proof.to_epoch);
    assert_eq!(restored.fact_id, proof.fact_id);
}

#[test]
fn interval_absence_verify_via_store() {
    let mut store = AbsenceStore::new();
    store.record_json(&json!({"a": 1})).unwrap();
    store.checkpoint();
    store.record_json(&json!({"b": 2})).unwrap();
    store.checkpoint();

    let absent = fid(json!({"absent": true}));
    let proof = store.prove_absent_interval(&absent, 0, 1).unwrap();

    store
        .verify_interval_absence_between_epochs(&proof, 0, 1)
        .unwrap();
}

#[test]
fn interval_absence_verify_static() {
    let mut store = AbsenceStore::new();
    store.record_json(&json!({"a": 1})).unwrap();
    store.checkpoint();
    store.record_json(&json!({"b": 2})).unwrap();
    store.checkpoint();

    let absent = fid(json!({"absent": true}));
    let proof = store.prove_absent_interval(&absent, 0, 1).unwrap();

    let cp0 = *store.checkpoint_at(0).unwrap();
    let cp1 = *store.checkpoint_at(1).unwrap();

    AbsenceStore::verify_interval_absence(&proof, &cp0, &cp1).unwrap();
}

#[test]
fn interval_absence_large_span() {
    let mut store = AbsenceStore::new();

    for i in 0..10 {
        store.record_json(&json!({"epoch": i})).unwrap();
        store.checkpoint();
    }

    let absent = fid(json!({"never_added": true}));
    let proof = store.prove_absent_interval(&absent, 0, 9).unwrap();

    assert_eq!(proof.from_epoch, 0);
    assert_eq!(proof.to_epoch, 9);
    assert_eq!(proof.facts_added_count(), 9);
    assert_eq!(proof.epoch_span(), 9);

    let cp0 = store.checkpoint_at(0).unwrap();
    let cp9 = store.checkpoint_at(9).unwrap();
    proof.verify_checkpoints(cp0, cp9).unwrap();
}

#[test]
fn interval_absence_middle_span() {
    let mut store = AbsenceStore::new();

    for i in 0..5 {
        store.record_json(&json!({"epoch": i})).unwrap();
        store.checkpoint();
    }

    let absent = fid(json!({"never_added": true}));
    let proof = store.prove_absent_interval(&absent, 2, 4).unwrap();

    assert_eq!(proof.from_epoch, 2);
    assert_eq!(proof.to_epoch, 4);
    assert_eq!(proof.facts_added_count(), 2);

    let cp2 = store.checkpoint_at(2).unwrap();
    let cp4 = store.checkpoint_at(4).unwrap();
    proof.verify_checkpoints(cp2, cp4).unwrap();
}

#[test]
fn interval_absence_fact_history_required() {
    let mut store = AbsenceStore::new();
    store.record_json(&json!({"a": 1})).unwrap();
    store.checkpoint();
    store.record_json(&json!({"b": 2})).unwrap();
    store.checkpoint();

    store.set_fact_history(vec![]);

    let absent = fid(json!({"absent": true}));
    match store.prove_absent_interval(&absent, 0, 1) {
        Err(StoreError::NoFactHistory) => {}
        other => panic!("expected NoFactHistory, got {:?}", other),
    }
}

#[test]
fn interval_absence_with_restored_history() {
    let mut store = AbsenceStore::new();
    let fact_a = store.record_json(&json!({"a": 1})).unwrap();
    let cp0 = store.checkpoint();
    let fact_b = store.record_json(&json!({"b": 2})).unwrap();
    let cp1 = store.checkpoint();

    let mut restored = AbsenceStore::new();
    restored.record(&fact_a).unwrap();
    restored.record(&fact_b).unwrap();
    restored.set_checkpoint_history(vec![cp0, cp1]);
    restored.set_fact_history(vec![fact_a, fact_b]);

    let absent = fid(json!({"absent": true}));
    let proof = restored.prove_absent_interval(&absent, 0, 1).unwrap();

    proof.verify_checkpoints(&cp0, &cp1).unwrap();
}

#[test]
fn interval_absence_epoch_mismatch_rejected() {
    let mut store = AbsenceStore::new();
    store.record_json(&json!({"a": 1})).unwrap();
    store.checkpoint();
    store.record_json(&json!({"b": 2})).unwrap();
    store.checkpoint();

    let absent = fid(json!({"absent": true}));
    let proof = store.prove_absent_interval(&absent, 0, 1).unwrap();

    let wrong_cp = absence::Checkpoint {
        epoch: 5,
        root: store.checkpoint_at(0).unwrap().root,
        fact_count: 1,
        unix_ts: 0,
    };

    match proof.verify_checkpoints(&wrong_cp, store.checkpoint_at(1).unwrap()) {
        Err(IntervalError::FromEpochMismatch {
            proof: 0,
            expected: 5,
        }) => {}
        other => panic!("expected FromEpochMismatch, got {:?}", other),
    }
}
