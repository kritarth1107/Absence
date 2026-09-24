# Absence

**Prove a fact is missing from a committed store — sparse Merkle non-membership for agent memory.**

> Your agent can prove it never stored that secret.

Absence provides cryptographic proofs that a key/fact is NOT in a committed set, without revealing the rest of the set. This complements [BlindOverlap](https://github.com/kritarth1107/BlindOverlap) (Private Set Intersection) by enabling absence proofs.

## Features

- **Sparse Merkle Tree** with correct empty-subtree default hashes (depth-256, keyed by fact-id bits)
- **Non-membership (absence) proofs** — prove a fact was never recorded (PRIMARY)
- **Membership proofs** — prove a fact was recorded (secondary)
- **Content-addressed fact IDs** — SHA-256 of RFC 8785 (JCS) canonical JSON
- **AbsenceStore API** — high-level interface for recording facts and generating proofs
- **CLI** — `absence` binary for encoding, inserting, proving, and verifying

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

### CLI Usage

```bash
# Encode a JSON value to its fact-id
absence encode '{"user": "alice", "action": "login"}'

# Insert facts into a store
absence insert '{"user": "alice", "action": "login"}' '{"user": "bob", "action": "login"}'

# Show current root hash
absence root

# Prove a fact is absent and write proof to file
absence prove-absent '{"user": "alice", "action": "delete_all"}' -o proof.json

# Verify an absence proof
absence verify proof.json --root <root-hex>
```

## Scope & Limitations (v0.1.0)

| Aspect | Status | Notes |
|--------|--------|-------|
| Scale | **Toy** | Tested with ≤4096 keys; no performance optimization |
| Cryptographic security | **Commitment + opening** | Standard Merkle proofs, NOT zero-knowledge |
| Privacy | **Limited** | Proves absence without revealing set contents, but proof size reveals nothing extra |
| ZK-SNARK | **No** | Not a zero-knowledge proof system |
| RSA accumulator | **No** | Uses Merkle tree, not accumulator-based |
| Production ready | **No** | Research/toy implementation; not audited |
| Persistence | **JSON file** | Simple file-based storage; no database |

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

## Project Structure

```
crates/
  absence/          # Core library
    src/
      fact_id.rs    # Content-addressed fact IDs
      smt.rs        # Sparse Merkle Tree
      proof.rs      # Membership & non-membership proofs
      store.rs      # High-level AbsenceStore API
  absence-cli/      # CLI binary
examples/           # Usage examples
```

## Related Work

- [BlindOverlap](https://github.com/kritarth1107/BlindOverlap) — Private Set Intersection for agent memory
- Sparse Merkle Trees: [Efficient Sparse Merkle Trees](https://eprint.iacr.org/2018/955)
- RFC 8785: [JSON Canonicalization Scheme (JCS)](https://datatracker.ietf.org/doc/html/rfc8785)

## License

MIT License © 2026 Kritarth Agrawal
