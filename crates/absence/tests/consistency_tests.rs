//! Integration tests for append-only consistency proofs.

use absence::{AbsenceStore, ConsistencyError, ConsistencyProof, FactId, StoreError};
use serde_json::json;

fn facts(prefix: &str, n: usize) -> Vec<FactId> {
    (0..n)
        .map(|i| FactId::from_json_value(&json!({ "k": prefix, "i": i })))
        .collect()
}

#[test]
fn proof_links_two_epochs() {
    let mut store = AbsenceStore::new();
    store.record_batch_with_proof(&facts("seed", 5)).unwrap();
    store.checkpoint();

    let proof = store.record_batch_with_proof(&facts("next", 7)).unwrap();
    store.checkpoint();

    assert_eq!(proof.len(), 7);
    assert!(store
        .verify_consistency_between_epochs(&proof, 0, 1)
        .is_ok());
}

#[test]
fn old_facts_remain_present_after_extension() {
    let mut store = AbsenceStore::new();
    let seed = facts("seed", 4);
    store.record_batch_with_proof(&seed).unwrap();
    let old_root = *store.root();
    let membership: Vec<_> = seed
        .iter()
        .map(|f| store.prove_present(f).unwrap())
        .collect();

    let proof = store.record_batch_with_proof(&facts("more", 3)).unwrap();
    AbsenceStore::verify_consistency(&proof, &old_root, store.root()).unwrap();

    for (f, old) in seed.iter().zip(&membership) {
        assert!(AbsenceStore::verify_present(old, &old_root).is_ok());
        let fresh = store.prove_present(f).unwrap();
        assert!(AbsenceStore::verify_present(&fresh, store.root()).is_ok());
    }
}

#[test]
fn chained_proofs_compose() {
    let mut store = AbsenceStore::new();
    let r0 = *store.root();
    let p1 = store.record_batch_with_proof(&facts("a", 3)).unwrap();
    let r1 = *store.root();
    let p2 = store.record_batch_with_proof(&facts("b", 2)).unwrap();
    let r2 = *store.root();

    p1.verify(&r0, &r1).unwrap();
    p2.verify(&r1, &r2).unwrap();
    assert!(matches!(
        p2.verify(&r0, &r2),
        Err(ConsistencyError::OldRootMismatch)
    ));
}

#[test]
fn tampered_step_is_rejected() {
    let mut store = AbsenceStore::new();
    store.record_batch_with_proof(&facts("s", 2)).unwrap();
    let mut proof = store.record_batch_with_proof(&facts("t", 3)).unwrap();

    proof.steps[1].siblings[10][0] ^= 0x01;
    assert!(matches!(
        proof.verify_self(),
        Err(ConsistencyError::Step { index: 1, .. })
    ));
}

#[test]
fn dropped_step_is_rejected() {
    let mut store = AbsenceStore::new();
    let mut proof = store.record_batch_with_proof(&facts("x", 3)).unwrap();
    proof.steps.pop();
    assert_eq!(
        proof.verify_self(),
        Err(ConsistencyError::FinalRootMismatch)
    );
}

#[test]
fn forged_removal_cannot_be_proven() {
    let mut old = AbsenceStore::new();
    let all = facts("f", 3);
    old.record_batch_with_proof(&all).unwrap();
    let mut shrunk = AbsenceStore::new();
    shrunk.record_batch_with_proof(&all[..2]).unwrap();

    let attempt = ConsistencyProof {
        old_root: *old.root(),
        new_root: *shrunk.root(),
        steps: vec![],
    };
    assert_eq!(
        attempt.verify_self(),
        Err(ConsistencyError::FinalRootMismatch)
    );
}

#[test]
fn fact_count_delta_is_checked() {
    let mut store = AbsenceStore::new();
    store.checkpoint();
    let proof = store.record_batch_with_proof(&facts("c", 2)).unwrap();
    store.checkpoint();

    let cps = store.checkpoints().to_vec();
    let mut lying = cps[1];
    lying.fact_count = 5;
    assert!(matches!(
        proof.verify_checkpoints(&cps[0], &lying),
        Err(ConsistencyError::FactCountMismatch {
            expected: 5,
            got: 2
        })
    ));

    let mut empty_proof = proof.clone();
    empty_proof.steps.clear();
    assert!(empty_proof.verify_checkpoints(&cps[0], &cps[1]).is_err());
}

#[test]
fn batch_is_all_or_nothing() {
    let mut store = AbsenceStore::new();
    let dup = FactId::from_json_value(&json!({"dup": true}));
    store.record(&dup).unwrap();
    let root = *store.root();

    let batch = vec![FactId::from_json_value(&json!({"new": 1})), dup];
    assert!(matches!(
        store.record_batch_with_proof(&batch),
        Err(StoreError::Consistency(ConsistencyError::AlreadyPresent {
            index: 1
        }))
    ));
    assert_eq!(store.root(), &root);
    assert_eq!(store.len(), 1);
}

#[test]
fn unknown_epoch_errors() {
    let mut store = AbsenceStore::new();
    let proof = store.record_batch_with_proof(&facts("u", 1)).unwrap();
    assert!(matches!(
        store.verify_consistency_between_epochs(&proof, 0, 1),
        Err(StoreError::UnknownEpoch(0))
    ));
}

#[test]
fn json_roundtrip() {
    let mut store = AbsenceStore::new();
    store.record_batch_with_proof(&facts("j", 2)).unwrap();
    let old = *store.root();
    let proof = store.record_batch_with_proof(&facts("k", 2)).unwrap();

    let s = serde_json::to_string(&proof).unwrap();
    let back: ConsistencyProof = serde_json::from_str(&s).unwrap();
    assert_eq!(back, proof);
    back.verify(&old, store.root()).unwrap();
}

#[test]
fn empty_to_empty_is_consistent() {
    let store = AbsenceStore::new();
    let proof = ConsistencyProof::generate(&absence::SparseMerkleTree::new(), &[]).unwrap();
    assert!(proof.is_empty());
    assert_eq!(proof.old_root, proof.new_root);
    assert_eq!(proof.old_root, *store.root());
    assert!(proof.verify_self().is_ok());
}

#[test]
fn large_batch_consistency() {
    let mut store = AbsenceStore::new();
    let batch = facts("large", 100);
    let proof = store.record_batch_with_proof(&batch).unwrap();
    assert_eq!(proof.len(), 100);
    assert!(proof.verify_self().is_ok());
    assert_eq!(proof.added_facts(), batch);
}
