//! Basic usage example for Absence
//!
//! Run with: cargo run --example basic

use absence::{AbsenceStore, FactId};
use serde_json::json;

fn main() {
    println!("=== Absence: Sparse Merkle Non-Membership Proofs ===");
    println!();

    // Create a new store
    let mut store = AbsenceStore::new();
    println!("Created empty store");
    println!("  Root: {}", hex::encode(store.root()));
    println!();

    // Record some facts (things that DID happen)
    let facts = vec![
        json!({"user": "alice", "action": "login", "timestamp": "2026-09-24T10:00:00Z"}),
        json!({"user": "alice", "action": "view_dashboard"}),
        json!({"user": "bob", "action": "login"}),
    ];

    println!("Recording facts:");
    for fact in &facts {
        let fact_id = store.record_json(fact).unwrap();
        println!("  {} -> {}", fact, fact_id);
    }
    println!();

    // Get commitment
    let commitment = store.commitment();
    println!("Commitment (publish this):");
    println!("  Root: {}", commitment.root_hex());
    println!("  Fact count: {}", commitment.fact_count);
    println!();

    // Prove something DIDN'T happen (absence proof)
    let dangerous_action = json!({"user": "alice", "action": "delete_all_data"});
    let dangerous_id = FactId::from_json_value(&dangerous_action);
    
    println!("Proving absence of: {}", dangerous_action);
    println!("  Fact ID: {}", dangerous_id);
    
    let absence_proof = store.prove_absent_json(&dangerous_action).unwrap();
    println!("  Generated absence proof with {} siblings", absence_proof.siblings.len());
    
    // Verify the absence proof
    let result = AbsenceStore::verify_absent(&absence_proof, &commitment.root);
    println!("  Verification: {:?}", result.is_ok());
    println!();

    // Prove something DID happen (presence proof)
    let login_action = json!({"user": "alice", "action": "login", "timestamp": "2026-09-24T10:00:00Z"});
    
    println!("Proving presence of: {}", login_action);
    let presence_proof = store.prove_present_json(&login_action).unwrap();
    println!("  Generated presence proof with {} siblings", presence_proof.siblings.len());
    
    let result = AbsenceStore::verify_present(&presence_proof, &commitment.root);
    println!("  Verification: {:?}", result.is_ok());
    println!();

    // Demonstrate that proofs are pinned to roots
    println!("=== Demonstrating proof pinning ===");
    
    let new_fact = json!({"user": "charlie", "action": "login"});
    let old_root = *store.root();
    
    // Prove charlie is absent BEFORE adding
    let charlie_absence = store.prove_absent_json(&new_fact).unwrap();
    println!("Before insertion: charlie absence proof valid = {:?}", 
             AbsenceStore::verify_absent(&charlie_absence, &old_root).is_ok());
    
    // Add charlie
    store.record_json(&new_fact).unwrap();
    let new_root = *store.root();
    
    // Old proof still valid against OLD root
    println!("After insertion (old root): charlie absence proof valid = {:?}",
             AbsenceStore::verify_absent(&charlie_absence, &old_root).is_ok());
    
    // Old proof INVALID against NEW root
    println!("After insertion (new root): charlie absence proof valid = {:?}",
             AbsenceStore::verify_absent(&charlie_absence, &new_root).is_ok());
    
    println!();
    println!("=== Done ===");
}
