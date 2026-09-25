# Absence

**Prove a fact is missing from a committed store — sparse Merkle non-membership for agent memory.**

> Your agent can prove it never stored that secret.

Absence provides cryptographic proofs that a key/fact is NOT in a committed set, without revealing the rest of the set. This complements [BlindOverlap](https://github.com/kritarth1107/BlindOverlap) (Private Set Intersection) by enabling absence proofs.

## Features

- **Sparse Merkle Tree** with correct empty-subtree default hashes (depth-256, keyed by fact-id bits)
- **Non-membership (absence) proofs** — prove a fact was never recorded (PRIMARY)
- **Membership proofs** — prove a fact was recorded (secondary)
- **Epoch checkpoints** — pin historical roots (`Checkpoint`) and verify absence at an epoch
- **Batch absence** — prove/verify many absences against one root
- **CompactProof** — length-prefixed binary (and hex) encoding for proofs
- **Content-addressed fact IDs** — SHA-256 of RFC 8785 (JCS) canonical JSON
- **AbsenceStore API** — high-level interface for recording facts and generating proofs
- **CLI** — `absence` binary for encoding, inserting, proving, verifying, epochs, batch, compact

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
```

## Scope & Limitations (v0.2.0)

| Aspect | Status | Notes |
|--------|--------|-------|
| Scale | **Toy** | Tested with ≤4096 keys; no performance optimization |
| Cryptographic security | **Commitment + opening** | Standard Merkle proofs, NOT zero-knowledge |
| Privacy | **Limited** | Proves absence without revealing set contents, but proof size reveals nothing extra |
| ZK-SNARK | **No** | Not a zero-knowledge proof system |
| RSA accumulator | **No** | Uses Merkle tree, not accumulator-based |
| Production ready | **No** | Research/toy implementation; not audited |
| Persistence | **JSON file** | Simple file-based storage; checkpoints in store JSON |
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

6. **Batch / CompactProof**: Many absence proofs share one root; CompactProof packs `fact_id || u16_le(len) || siblings` for transport.

## Project Structure

```
crates/
  absence/          # Core library
    src/
      fact_id.rs    # Content-addressed fact IDs
      smt.rs        # Sparse Merkle Tree
      proof.rs      # Membership & non-membership proofs
      store.rs      # High-level AbsenceStore API (+ epochs, batch)
      compact.rs    # CompactProof binary/hex encoding
  absence-cli/      # CLI binary
examples/           # Usage examples (basic, epoch_batch)
```

## Related Work

- [BlindOverlap](https://github.com/kritarth1107/BlindOverlap) — Private Set Intersection for agent memory
- Sparse Merkle Trees: [Efficient Sparse Merkle Trees](https://eprint.iacr.org/2018/955)
- RFC 8785: [JSON Canonicalization Scheme (JCS)](https://datatracker.ietf.org/doc/html/rfc8785)

## License

MIT License © 2026 Kritarth Agrawal
