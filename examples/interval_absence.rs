//! Interval absence proof: prove a fact was continuously absent across epochs.
//!
//! Run with: cargo run -p absence --example interval_absence

use absence::{AbsenceStore, FactId};
use serde_json::json;

fn main() {
    let mut store = AbsenceStore::new();

    println!("=== Interval Absence Proof Demo (v0.5.0) ===\n");

    // Day 1: Initial agent memory
    println!("Day 1: Recording initial agent memories...");
    let day1_facts: Vec<FactId> = [
        json!({"agent": "planner", "memory": "user prefers metric units"}),
        json!({"agent": "planner", "memory": "project deadline is Sep 30"}),
        json!({"agent": "search", "memory": "user searched for Rust crates"}),
    ]
    .iter()
    .map(FactId::from_json_value)
    .collect();

    for fact in &day1_facts {
        store.record(fact).unwrap();
    }
    let cp0 = store.checkpoint();
    println!(
        "  Epoch 0: {} facts, root {}",
        cp0.fact_count,
        cp0.root_hex()
    );

    // Day 2: More agent activity
    println!("\nDay 2: Adding more memories...");
    let day2_facts: Vec<FactId> = [
        json!({"agent": "planner", "memory": "shipped v0.4.0 consistency proofs"}),
        json!({"agent": "coder", "memory": "implemented interval absence"}),
    ]
    .iter()
    .map(FactId::from_json_value)
    .collect();

    for fact in &day2_facts {
        store.record(fact).unwrap();
    }
    let cp1 = store.checkpoint();
    println!(
        "  Epoch 1: {} facts, root {}",
        cp1.fact_count,
        cp1.root_hex()
    );

    // Day 3: Even more activity
    println!("\nDay 3: Final batch...");
    let day3_facts: Vec<FactId> =
        [json!({"agent": "planner", "memory": "shipped v0.5.0 interval proofs"})]
            .iter()
            .map(FactId::from_json_value)
            .collect();

    for fact in &day3_facts {
        store.record(fact).unwrap();
    }
    let cp2 = store.checkpoint();
    println!(
        "  Epoch 2: {} facts, root {}",
        cp2.fact_count,
        cp2.root_hex()
    );

    // Now prove a sensitive fact was NEVER recorded across the entire span
    println!("\n=== Proving Continuous Absence ===\n");

    let sensitive_fact = json!({
        "agent": "planner",
        "memory": "user password is hunter2"
    });
    let sensitive_id = FactId::from_json_value(&sensitive_fact);

    println!("Proving this sensitive fact was absent throughout epochs 0-2:");
    println!("  {}", serde_json::to_string(&sensitive_fact).unwrap());
    println!("  Fact ID: {}\n", sensitive_id.to_hex());

    let proof = store
        .prove_absent_interval(&sensitive_id, 0, 2)
        .expect("Failed to generate interval proof");

    println!("Generated IntervalAbsenceProof:");
    println!("  From epoch: {}", proof.from_epoch);
    println!("  To epoch: {}", proof.to_epoch);
    println!(
        "  Facts added during interval: {}",
        proof.facts_added_count()
    );
    println!("  Epoch span: {}", proof.epoch_span());

    // Verify the proof
    println!("\n=== Verification ===\n");

    proof
        .verify_checkpoints(&cp0, &cp2)
        .expect("Proof verification failed");

    println!("✓ VERIFIED: The sensitive fact was continuously absent");
    println!("  - It was not present at epoch 0");
    println!(
        "  - It was not among the {} facts added through epoch 2",
        proof.facts_added_count()
    );
    println!("  - Therefore it remained absent throughout the entire span");

    // Serialize and deserialize (for transport)
    println!("\n=== Serialization ===\n");

    let wire = serde_json::to_string_pretty(&proof).unwrap();
    println!("Proof JSON size: {} bytes", wire.len());

    let received: absence::IntervalAbsenceProof =
        serde_json::from_str(&wire).expect("Failed to deserialize");

    received
        .verify_checkpoints(&cp0, &cp2)
        .expect("Deserialized proof verification failed");

    println!("✓ Serialized proof verifies correctly after transport");

    // What happens if we try to prove absence for something that WAS added?
    println!("\n=== Edge Case: Fact Added During Interval ===\n");

    let added_fact = &day2_facts[0]; // "shipped v0.4.0"
    println!("Trying to prove absence of a fact that WAS added...");
    println!("  Fact ID: {}", added_fact.to_hex());

    match store.prove_absent_interval(added_fact, 0, 2) {
        Err(e) => println!("✓ Correctly rejected: {}", e),
        Ok(_) => panic!("Should have rejected proof for fact that was added!"),
    }

    println!("\n=== Demo Complete ===");
}
