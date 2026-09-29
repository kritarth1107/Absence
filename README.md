# Absence

**Prove a fact is missing from a committed store — sparse Merkle non-membership for agent memory.**

> Your agent can prove it never stored that secret.

Absence provides cryptographic proofs that a key/fact is NOT in a committed set, without revealing the rest of the set. This complements [BlindOverlap](https://github.com/kritarth1107/BlindOverlap) (Private Set Intersection) by enabling absence proofs.

## Features

- **Sparse Merkle Tree** with correct empty-subtree default hashes (depth-256, keyed by fact-id bits)
- **Non-membership (absence) proofs** — prove a fact was never recorded (PRIMARY)
- **Membership proofs** — prove a fact was recorded (secondary)
- **Epoch checkpoints** — pin historical roots (`Checkpoint`) and verify absence at an epoch
- **Interval absence proofs** (v0.5.0) — prove continuous absence across epoch ranges
- **Append-only consistency proofs** (v0.4.0) — prove newer root = older root + additions only
- **Signed checkpoints** (v0.3.0) — Ed25519 signatures over checkpoints for trustless verification
- **Root attestations** (v0.3.0) — bind proofs to signed checkpoints for full verification
- **WitnessBundle** (v0.3.0) — portable packages of signed checkpoints + batch proofs
- **Batch absence** — prove/verify many absences against one root
- **CompactProof** — length-prefixed binary (and hex) encoding for proofs
- **Content-addressed fact IDs** — SHA-256 of RFC 8785 (JCS) canonical JSON
- **AbsenceStore API** — high-level interface for recording facts and generating proofs
- **CLI** — `absence` binary for encoding, inserting, proving, verifying, signing, attesting

## Installation

```bash
cargo install --path crates/absence-cli
```

Or add to your project:

```toml
[dependencies]
absence = { git = "https://github.com/kritarth1107/Absence" }
```

## Quick Start

### Library Usage

```rust
use absence::AbsenceStore;
use serde_json::json;

// Create a store and record some facts
let mut store = AbsenceStore::new();
store.record_json(&json!({"user": "alice", "action": "login"})).unwrap();

// Get commitment (publish this root hash)
let commitment = store.commitment();
println!("Root: {}", commitment.root_hex());

// Prove a sensitive action NEVER happened
let dangerous_action = json!({"user": "alice", "action": "delete_all_data"});
let proof = store.prove_absent_json(&dangerous_action).unwrap();

// Verifier checks proof against published root
assert!(AbsenceStore::verify_absent(&proof, &commitment.root).is_ok());
```

### Epochs, batch, and compact proofs

```rust
use absence::{AbsenceStore, CompactProof};
use serde_json::json;

let mut store = AbsenceStore::new();
store.record_json(&json!({"user": "alice", "action": "login"})).unwrap();
let cp = store.checkpoint(); // epoch 0

let missing = vec![
    json!({"user": "alice", "action": "delete_all"}),
    json!({"user": "eve", "action": "login"}),
];
let proofs = store.prove_absent_batch_json(&missing).unwrap();
AbsenceStore::verify_absent_batch(&proofs, &cp.root).unwrap();

let hex = CompactProof::encode_absence_hex(&proofs[0]);
let restored = CompactProof::decode_absence_hex(&hex).unwrap();
assert!(store.verify_absent_at_epoch(&restored, 0).is_ok());
```

### Append-only consistency proofs (v0.4.0)

```rust
use absence::{AbsenceStore, ConsistencyProof, FactId};
use serde_json::json;

let mut store = AbsenceStore::new();

// Day 1: record initial facts and checkpoint
let day1: Vec<FactId> = [
    json!({"agent": "planner", "memory": "user prefers metric units"}),
    json!({"agent": "planner", "memory": "project deadline is Sep 30"}),
].iter().map(FactId::from_json_value).collect();
store.record_batch_with_proof(&day1).unwrap();
let cp0 = store.checkpoint();

// Day 2: add more facts, get consistency proof
let day2: Vec<FactId> = [json!({"agent": "planner", "memory": "shipped v0.4.0"})]
    .iter().map(FactId::from_json_value).collect();
let proof = store.record_batch_with_proof(&day2).unwrap();
let cp1 = store.checkpoint();

// Verifier checks epoch 1 is an append-only extension of epoch 0
proof.verify_checkpoints(&cp0, &cp1).unwrap();
println!("epoch 1 = epoch 0 + {} new facts", proof.len());
```

### Interval absence proofs (v0.5.0)

```rust
use absence::{AbsenceStore, FactId};
use serde_json::json;

let mut store = AbsenceStore::new();

// Day 1: record facts and checkpoint
store.record_json(&json!({"agent": "planner", "memory": "user prefers metric"})).unwrap();
store.checkpoint(); // epoch 0

// Day 2: more facts
store.record_json(&json!({"agent": "planner", "memory": "project deadline Sep 30"})).unwrap();
store.checkpoint(); // epoch 1

// Prove a sensitive fact was NEVER recorded throughout epochs 0-1
let sensitive = FactId::from_json_value(&json!({"agent": "planner", "memory": "user password"}));
let proof = store.prove_absent_interval(&sensitive, 0, 1).unwrap();

// Verifier confirms continuous absence across the epoch range
let cp0 = store.checkpoint_at(0).unwrap();
let cp1 = store.checkpoint_at(1).unwrap();
proof.verify_checkpoints(cp0, cp1).unwrap();
println!("Fact was absent throughout epochs 0-1 ({} facts added)", proof.facts_added_count());
```

### Signed checkpoints (v0.3.0)

```rust
use absence::{AbsenceStore, SignerKey, RootAttestation};
use serde_json::json;

let mut store = AbsenceStore::new();
store.record_json(&json!({"user": "alice", "action": "login"})).unwrap();

// Generate a signing keypair (store the secret securely!)
let signer = SignerKey::generate();
let verifier = signer.verifier();
println!("Public key: {}", verifier.to_hex());

// Create a signed checkpoint
let signed = store.checkpoint_signed(&signer);
assert!(signed.verify(&verifier).is_ok());

// Create an attested absence proof
let absent = json!({"user": "eve", "action": "login"});
let proof = store.prove_absent_json(&absent).unwrap();
let attestation = RootAttestation::attest_absent(&proof, &signed.checkpoint, &signer);

// Verifier checks BOTH the proof AND the signature
assert!(attestation.verify_absent(&verifier).is_ok());
```

### CLI Usage

```bash
# Encode a JSON value to its fact-id
absence encode '{"user": "alice", "action": "login"}'

# Insert facts into a store
absence insert '{"user": "alice", "action": "login"}' '{"user": "bob", "action": "login"}'

# Show current root hash
absence root

# Snapshot an epoch checkpoint (persisted in the store file)
absence checkpoint
absence checkpoints

# Prove a fact is absent and write proof to file
absence prove-absent '{"user": "alice", "action": "delete_all"}' -o proof.json

# Batch-prove absences (args or --file JSON lines)
absence prove-absent-batch '{"x":1}' '{"x":2}' -o batch.json
absence prove-absent-batch --file examples/fixtures/batch_absent_facts.jsonl -o batch.json
absence verify-batch batch.json --root <root-hex>

# CompactProof hex
absence compact-encode proof.json
absence compact-decode <hex>

# Verify an absence proof (optionally against --epoch)
absence verify proof.json --root <root-hex>
absence verify proof.json --epoch 0 --store absence.store --root unused

# === Append-only consistency proofs (v0.4.0) ===

# Prove epoch 1 is an append-only extension of epoch 0
absence prove-consistency --from 0 --to 1 -o consistency.json

# Verify a consistency proof
absence verify-consistency consistency.json --old-root <old-hex> --new-root <new-hex>

# === Interval absence proofs (v0.5.0) ===

# Prove a fact was continuously absent across epochs 0-2
absence prove-interval --from 0 --to 2 '{"sensitive": "data"}' -o interval.json

# Verify using stored checkpoints
absence verify-interval interval.json --store absence.store

# Or verify with explicit roots
absence verify-interval interval.json --old-root <from-hex> --new-root <to-hex>

# === Signed checkpoints (v0.3.0) ===

# Generate a signing keypair
absence keygen -o my.key
# Output: Public key: abc123...

# Sign the latest checkpoint
absence sign-checkpoint -k my.key -o signed.json

# Verify a signed checkpoint
absence verify-checkpoint signed.json --pubkey abc123...

# Create a signed absence attestation
absence attest-absent '{"user": "eve"}' -k my.key -o attestation.json

# Verify an attestation
absence verify-attestation attestation.json --pubkey abc123...
```

## Scope & Limitations (v0.5.0)

| Aspect | Status | Notes |
|--------|--------|-------|
| Scale | **Toy** | Tested with ≤4096 keys; no performance optimization |
| Cryptographic security | **Commitment + opening** | Standard Merkle proofs, NOT zero-knowledge |
| Signed checkpoints | **Ed25519** | Verifiers trust root without trusting store operator |
| Consistency proofs | **Append-only** | Prove newer root = older root + additions (v0.4.0) |
| Interval absence | **Continuous** | Prove fact absent throughout epoch range (v0.5.0) |
| Privacy | **Limited** | Proves absence without revealing set contents, but proof size reveals nothing extra |
| ZK-SNARK | **No** | Not a zero-knowledge proof system |
| RSA accumulator | **No** | Uses Merkle tree, not accumulator-based |
| Production ready | **No** | Research/toy implementation; not audited |
| Persistence | **JSON file** | Simple file-based storage; checkpoints + signed in store JSON |
| Epochs | **Pinned roots** | Checkpoints store root/count/ts; no historical tree rewind |
| CompactProof | **Encoding only** | Smaller than JSON siblings; still full Merkle path |

## How It Works

1. **Fact ID**: Each fact is a JSON value. Its ID is `SHA-256(JCS(json))` where JCS is RFC 8785 JSON Canonicalization.

2. **Sparse Merkle Tree**: A depth-256 binary tree where:
   - Each leaf position is determined by the 256-bit fact ID
   - Empty subtrees use precomputed "default hashes"
   - Only non-empty paths are stored

3. **Absence Proof**: To prove key K is absent:
   - Provide sibling hashes along the path from K's leaf position to root
   - Verifier recomputes root using the EMPTY leaf hash
   - If computed root matches published root, K is provably absent

4. **Membership Proof**: Same structure, but uses the actual leaf hash.

5. **Epoch checkpoint**: `checkpoint()` records `(epoch, root, fact_count, unix_ts)`. Later proofs can be checked with `verify_absent_at_epoch` against that pinned root.

6. **Signed checkpoint** (v0.3.0): `SignedCheckpoint` wraps a checkpoint with an Ed25519 signature over a domain-separated canonical message (`absence.v1.signed-checkpoint`). Verifiers can trust the root without trusting the store operator — they only need the signer's public key.

7. **Root attestation** (v0.3.0): `RootAttestation` binds an absence (or membership) proof to a signed checkpoint. `verify_absent()` checks BOTH the Merkle proof AND the signature in one call.

8. **Batch / CompactProof**: Many absence proofs share one root; CompactProof packs `fact_id || u16_le(len) || siblings` for transport. `WitnessBundle` packages a signed checkpoint with multiple proofs.

9. **Consistency proof** (v0.4.0): `ConsistencyProof` links an older root to a newer root via a sequence of absence proofs — one per added fact. Each step proves the fact was absent, then recomputes the root with that leaf present. If the final root matches the expected new root, the new tree is exactly `old ∪ added`, guaranteeing the log is append-only.

10. **Interval absence proof** (v0.5.0): `IntervalAbsenceProof` proves a fact was continuously absent across an epoch range `[from, to]`. It combines: (1) an absence proof at `from_epoch`, (2) a consistency proof from `from_epoch` to `to_epoch`, and (3) verification that the fact ID is not among the added facts. If all three hold, the fact was absent at the start and never added, so it remained absent throughout.

## Project Structure

```
crates/
  absence/          # Core library
    src/
      fact_id.rs    # Content-addressed fact IDs
      smt.rs        # Sparse Merkle Tree
      proof.rs      # Membership & non-membership proofs
      store.rs      # High-level AbsenceStore API (+ epochs, batch, signed, consistency, interval)
      compact.rs    # CompactProof binary/hex encoding
      keys.rs       # Ed25519 SignerKey / VerifierKey (v0.3.0)
      signed.rs     # SignedCheckpoint, RootAttestation (v0.3.0)
      bundle.rs     # WitnessBundle (v0.3.0)
      consistency.rs # ConsistencyProof for append-only verification (v0.4.0)
      interval.rs   # IntervalAbsenceProof for continuous absence (v0.5.0)
  absence-cli/      # CLI binary
examples/           # Usage examples (basic, epoch_batch, signed_checkpoint, consistency, interval_absence)
```

## Related Work

- [BlindOverlap](https://github.com/kritarth1107/BlindOverlap) — Private Set Intersection for agent memory
- Sparse Merkle Trees: [Efficient Sparse Merkle Trees](https://eprint.iacr.org/2018/955)
- RFC 8785: [JSON Canonicalization Scheme (JCS)](https://datatracker.ietf.org/doc/html/rfc8785)

## License

MIT License © 2026 Kritarth Agrawal
