//! Signed checkpoints and attestations demo
//!
//! Demonstrates the v0.3.0 cryptographic attestation features:
//! - Generating Ed25519 keypairs
//! - Signing checkpoints
//! - Verifying signed checkpoints
//! - Creating and verifying RootAttestations
//! - Building WitnessBundles
//!
//! Run with: cargo run -p absence --example signed_checkpoint

use absence::{AbsenceStore, RootAttestation, SignerKey, WitnessBundle};
use serde_json::json;

fn main() {
    println!("=== Absence v0.3.0: Signed Checkpoints & Attestations ===");
    println!();

    // Step 1: Generate a signing keypair
    println!("1. Generating Ed25519 keypair...");
    let signer = SignerKey::generate();
    let verifier = signer.verifier();
    println!("   Secret key: {}...", &signer.to_hex()[..16]);
    println!("   Public key: {}", verifier.to_hex());
    println!();

    // Step 2: Create a store and record some facts
    println!("2. Recording facts...");
    let mut store = AbsenceStore::new();
    for fact in &[
        json!({"user": "alice", "action": "login"}),
        json!({"user": "bob", "action": "login"}),
        json!({"user": "alice", "action": "upload_file"}),
    ] {
        let id = store.record_json(fact).unwrap();
        println!("   Recorded {} -> {}", fact, &id.to_hex()[..16]);
    }
    println!();

    // Step 3: Create a signed checkpoint
    println!("3. Creating signed checkpoint...");
    let signed = store.checkpoint_signed(&signer);
    println!("   Epoch: {}", signed.checkpoint.epoch);
    println!("   Root: {}", signed.checkpoint.root_hex());
    println!("   Fact count: {}", signed.checkpoint.fact_count);
    println!("   Signature: {}...", &signed.signature[..32]);
    println!();

    // Step 4: Verify the signed checkpoint
    println!("4. Verifying signed checkpoint...");
    match signed.verify(&verifier) {
        Ok(()) => println!("   ✓ Signature VALID"),
        Err(e) => println!("   ✗ Signature INVALID: {}", e),
    }
    println!();

    // Step 5: Attempt verification with wrong key
    println!("5. Verification with wrong key (should fail)...");
    let wrong_verifier = SignerKey::generate().verifier();
    match signed.verify(&wrong_verifier) {
        Ok(()) => println!("   ✗ Should have failed!"),
        Err(_) => println!("   ✓ Correctly rejected wrong key"),
    }
    println!();

    // Step 6: Create an attested absence proof
    println!("6. Creating RootAttestation for absent fact...");
    let absent_fact = json!({"user": "eve", "action": "login"});
    let proof = store.prove_absent_json(&absent_fact).unwrap();
    let attestation = RootAttestation::attest_absent(&proof, &signed.checkpoint, &signer);
    println!("   Fact: {}", absent_fact);
    println!("   Fact ID: {}", attestation.fact_id().unwrap().to_hex());
    println!();

    // Step 7: Verify the attestation
    println!("7. Verifying RootAttestation...");
    match attestation.verify_absent(&verifier) {
        Ok(()) => println!("   ✓ Attestation VALID (both proof and signature)"),
        Err(e) => println!("   ✗ Attestation INVALID: {}", e),
    }
    println!();

    // Step 8: Serialize attestation to JSON
    println!("8. Attestation serialization...");
    let json_str = serde_json::to_string_pretty(&attestation).unwrap();
    println!("   JSON length: {} bytes", json_str.len());
    let restored: RootAttestation = serde_json::from_str(&json_str).unwrap();
    match restored.verify_absent(&verifier) {
        Ok(()) => println!("   ✓ Restored attestation verifies"),
        Err(e) => println!("   ✗ Restored attestation failed: {}", e),
    }
    println!();

    // Step 9: Create a WitnessBundle with multiple proofs
    println!("9. Creating WitnessBundle with batch proofs...");
    let absent_facts = vec![
        json!({"user": "eve", "action": "login"}),
        json!({"user": "mallory", "action": "login"}),
        json!({"user": "alice", "action": "delete_all"}),
    ];
    let proofs = store.prove_absent_batch_json(&absent_facts).unwrap();
    let bundle = WitnessBundle::new(&signed.checkpoint, &signer, proofs);
    println!("   Bundle contains {} proofs", bundle.proof_count());
    println!();

    // Step 10: Verify the bundle
    println!("10. Verifying WitnessBundle...");
    match bundle.verify_all(&verifier) {
        Ok(()) => println!(
            "    ✓ Bundle VALID (signature + {} proofs)",
            bundle.proof_count()
        ),
        Err(e) => println!("    ✗ Bundle INVALID: {}", e),
    }
    println!();

    // Step 11: Compact bundle encoding
    println!("11. Compact bundle encoding...");
    let compact_hexes = bundle.proofs_to_compact_hex();
    println!(
        "    Proof hex lengths: {:?}",
        compact_hexes.iter().map(|h| h.len()).collect::<Vec<_>>()
    );
    println!();

    // Summary
    println!("=== Summary ===");
    println!("Public key (verifier): {}", verifier.to_hex());
    println!("Signed checkpoints: {}", store.signed_checkpoints().len());
    println!("Facts recorded: {}", store.len());
    println!();
    println!("Verifiers can now trust absence proofs without trusting the store operator!");
    println!("They only need the signer's public key.");
    println!();
    println!("=== Done (toy/not ZK) ===");
}
