//! Epoch checkpoints, batch absence proofs, and CompactProof demo
//!
//! Run with: cargo run -p absence --example epoch_batch

use absence::{AbsenceStore, CompactProof, FactId};
use serde_json::json;

fn main() {
    println!("=== Absence v0.2.0: Epochs, Batch, CompactProof ===");
    println!();

    let mut store = AbsenceStore::new();

    // Record some facts
    for fact in &[
        json!({"user": "alice", "action": "login"}),
        json!({"user": "bob", "action": "login"}),
    ] {
        let id = store.record_json(fact).unwrap();
        println!("recorded {} -> {}", fact, id);
    }

    // Epoch 0 checkpoint
    let cp0 = store.checkpoint();
    println!();
    println!(
        "checkpoint epoch {}: root={} facts={}",
        cp0.epoch,
        cp0.root_hex(),
        cp0.fact_count
    );

    // Batch-prove several absences against current root
    let missing = vec![
        json!({"user": "alice", "action": "delete_all"}),
        json!({"user": "eve", "action": "login"}),
        json!({"admin": true, "action": "wipe"}),
    ];
    let proofs = store.prove_absent_batch_json(&missing).unwrap();
    AbsenceStore::verify_absent_batch(&proofs, store.root()).unwrap();
    println!(
        "batch absence: {} proofs OK against current root",
        proofs.len()
    );

    // Compact encode the first proof
    let compact_hex = CompactProof::encode_absence_hex(&proofs[0]);
    let restored = CompactProof::decode_absence_hex(&compact_hex).unwrap();
    assert!(AbsenceStore::verify_absent(&restored, store.root()).is_ok());
    println!(
        "compact proof: {} hex chars ({} bytes raw)",
        compact_hex.len(),
        CompactProof::encode_absence(&proofs[0]).len()
    );

    // Mutate store and take epoch 1 — epoch 0 proofs stay pinned
    store
        .record_json(&json!({"user": "charlie", "action": "login"}))
        .unwrap();
    let cp1 = store.checkpoint();
    println!();
    println!(
        "checkpoint epoch {}: root={} facts={}",
        cp1.epoch,
        cp1.root_hex(),
        cp1.fact_count
    );

    let still_missing = FactId::from_json_value(&json!({"user": "eve", "action": "login"}));
    let proof_now = store.prove_absent(&still_missing).unwrap();
    assert!(store.verify_absent_at_epoch(&proof_now, 1).is_ok());
    // Proof against epoch 0 root still verifies for facts that were absent then
    assert!(store.verify_absent_at_epoch(&proofs[1], 0).is_ok());
    println!("verify_absent_at_epoch: epoch0 and epoch1 OK");

    println!();
    println!("history ({} checkpoints):", store.checkpoints().len());
    for cp in store.checkpoints() {
        println!(
            "  epoch={} facts={} root={}",
            cp.epoch,
            cp.fact_count,
            &cp.root_hex()[..16]
        );
    }

    println!();
    println!("=== Done (toy/not ZK) ===");
}
