//! Append-only consistency proof between two epoch checkpoints.
//!
//! Run with: cargo run -p absence --example consistency

use absence::{AbsenceStore, ConsistencyProof, FactId};
use serde_json::json;

fn main() {
    let mut store = AbsenceStore::new();

    let day1: Vec<FactId> = [
        json!({"agent": "planner", "memory": "user prefers metric units"}),
        json!({"agent": "planner", "memory": "project deadline is Sep 30"}),
    ]
    .iter()
    .map(FactId::from_json_value)
    .collect();
    store.record_batch_with_proof(&day1).unwrap();
    let cp0 = store.checkpoint();

    let day2: Vec<FactId> = [json!({"agent": "planner", "memory": "shipped v0.4.0"})]
        .iter()
        .map(FactId::from_json_value)
        .collect();
    let proof = store.record_batch_with_proof(&day2).unwrap();
    let cp1 = store.checkpoint();

    println!("epoch 0 root: {}", cp0.root_hex());
    println!("epoch 1 root: {}", cp1.root_hex());

    let wire = serde_json::to_string(&proof).unwrap();
    let received: ConsistencyProof = serde_json::from_str(&wire).unwrap();
    received.verify_checkpoints(&cp0, &cp1).unwrap();
    println!(
        "✓ epoch 1 is an append-only extension of epoch 0 (+{} fact)",
        received.len()
    );
}
