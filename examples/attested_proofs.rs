//! Example: Attested Consistency and Interval Proofs (v0.6.0)
//!
//! Demonstrates how to create and verify attested proofs that bind
//! ConsistencyProof and IntervalAbsenceProof to Ed25519-signed checkpoints.
//!
//! Run: cargo run --example attested_proofs

use absence::{AbsenceStore, FactId, SignerKey};
use serde_json::json;

fn main() {
    println!("=== Absence v0.6.0: Attested Proofs Demo ===\n");

    // Create a store and signing key
    let mut store = AbsenceStore::new();
    let signer = SignerKey::generate();
    let verifier = signer.verifier();

    println!("Generated Ed25519 keypair");
    println!("Public key: {}\n", verifier.to_hex());

    // ============= SETUP: Multi-day agent memory log =============
    println!("--- Setting up agent memory log ---\n");

    // Day 1: Agent records some facts
    store
        .record_json(&json!({"agent": "planner", "memory": "user prefers metric units"}))
        .unwrap();
    let _signed_cp0 = store.checkpoint_signed(&signer);
    println!("Day 1: Recorded memory, signed checkpoint (epoch 0)");

    // Day 2: More facts
    store
        .record_json(&json!({"agent": "planner", "memory": "project deadline Sep 30"}))
        .unwrap();
    let _signed_cp1 = store.checkpoint_signed(&signer);
    println!("Day 2: Recorded memory, signed checkpoint (epoch 1)");

    // Day 3: More facts
    store
        .record_json(&json!({"agent": "planner", "memory": "shipped v0.6.0"}))
        .unwrap();
    let _signed_cp2 = store.checkpoint_signed(&signer);
    println!("Day 3: Recorded memory, signed checkpoint (epoch 2)");

    println!(
        "\nStore has {} facts across {} epochs\n",
        store.len(),
        store.checkpoints().len()
    );

    // ============= ATTESTED CONSISTENCY PROOF =============
    println!("--- AttestedConsistency: Prove append-only advancement ---\n");

    // Prove the log grew append-only from epoch 0 to epoch 2
    let attested_consistency = store.attest_consistency(0, 2, &signer).unwrap();

    println!("Created attested consistency proof:");
    println!(
        "  From epoch: {}",
        attested_consistency.old_checkpoint().epoch
    );
    println!(
        "  To epoch: {}",
        attested_consistency.new_checkpoint().epoch
    );
    println!("  Facts added: {}", attested_consistency.facts_added());
    println!(
        "  Old root: {}",
        attested_consistency.old_checkpoint().root_hex()
    );
    println!(
        "  New root: {}",
        attested_consistency.new_checkpoint().root_hex()
    );
    println!();

    // A verifier with only the public key can verify both:
    // 1. The checkpoints were signed by a trusted key
    // 2. The consistency proof is valid (append-only growth)
    match attested_consistency.verify(&verifier) {
        Ok(()) => println!("✓ Attested consistency VERIFIED - log is append-only"),
        Err(e) => println!("✗ Verification failed: {}", e),
    }

    // Show JSON format (portable)
    let json_str = serde_json::to_string_pretty(&attested_consistency).unwrap();
    println!(
        "\nJSON proof (first 500 chars):\n{}...\n",
        &json_str[..json_str.len().min(500)]
    );

    // ============= ATTESTED INTERVAL PROOF =============
    println!("--- AttestedInterval: Prove continuous absence ---\n");

    // Prove that a sensitive fact was NEVER recorded throughout epochs 0-2
    let sensitive =
        FactId::from_json_value(&json!({"agent": "planner", "memory": "user password"}));
    let attested_interval = store
        .attest_interval_absent(&sensitive, 0, 2, &signer)
        .unwrap();

    println!("Created attested interval absence proof:");
    println!("  Fact ID: {}", sensitive.to_hex());
    println!(
        "  From epoch: {}",
        attested_interval.from_checkpoint().epoch
    );
    println!("  To epoch: {}", attested_interval.to_checkpoint().epoch);
    println!("  Epoch span: {}", attested_interval.epoch_span());
    println!(
        "  Facts added during interval: {}",
        attested_interval.facts_added_count()
    );
    println!();

    // A verifier with only the public key can verify both:
    // 1. The checkpoints were signed by a trusted key
    // 2. The fact was continuously absent throughout the interval
    match attested_interval.verify(&verifier) {
        Ok(()) => println!("✓ Attested interval absence VERIFIED"),
        Err(e) => println!("✗ Verification failed: {}", e),
    }

    // ============= DEMONSTRATION: Wrong key fails =============
    println!("\n--- Demonstration: Wrong key is rejected ---\n");

    let wrong_verifier = SignerKey::generate().verifier();
    match attested_consistency.verify(&wrong_verifier) {
        Ok(()) => println!("Unexpected: verification succeeded with wrong key"),
        Err(e) => println!("✓ Expected failure with wrong key: {}", e),
    }

    match attested_interval.verify(&wrong_verifier) {
        Ok(()) => println!("Unexpected: verification succeeded with wrong key"),
        Err(e) => println!("✓ Expected failure with wrong key: {}", e),
    }

    // ============= DEMONSTRATION: Self-consistency check =============
    println!("\n--- Demonstration: Self-consistency check ---\n");

    // Extract the embedded public key (proves internal consistency, not trust)
    match attested_consistency.verify_self_consistent() {
        Ok(extracted) => {
            println!("Extracted signer public key: {}", extracted.to_hex());
            if extracted.to_hex() == verifier.to_hex() {
                println!("✓ Matches original signer");
            }
        }
        Err(e) => println!("Self-consistency check failed: {}", e),
    }

    println!("\n=== Demo complete ===");
    println!("\nKey takeaways:");
    println!("1. AttestedConsistency binds ConsistencyProof to signed checkpoint pairs");
    println!("2. AttestedInterval binds IntervalAbsenceProof to signed checkpoint pairs");
    println!("3. Verifiers only need the signer's public key - no store access required");
    println!("4. Both proof types are portable JSON for cross-system verification");
}
