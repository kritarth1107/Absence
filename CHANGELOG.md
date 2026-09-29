# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-09-29

### Added

- **Interval absence proofs** — prove continuous absence across epoch ranges
  - `IntervalAbsenceProof`: combines absence proof at start epoch with consistency proof showing fact was never added
  - `IntervalError`: errors for generation and verification failures
  - Design: absence at from_epoch + consistency from→to + fact not in added set = continuous absence
  - `verify_self()`: verify internal consistency
  - `verify()`: verify against two explicit roots
  - `verify_checkpoints()`: verify against two checkpoints with epoch validation

- **AbsenceStore interval integration**
  - `prove_absent_interval(fact_id, from_epoch, to_epoch)`: generate interval absence proof
  - `prove_absent_interval_json()`: JSON variant
  - `verify_interval_absence_between_epochs()`: verify against stored checkpoints
  - `verify_interval_absence()`: static verification against explicit checkpoints
  - `fact_history()` / `set_fact_history()`: fact insertion order tracking for proof generation

- **CLI commands** (v0.5.0)
  - `prove-interval --from <epoch> --to <epoch> '<json>' [-o file]`: generate interval absence proof
  - `verify-interval <proof.json> [--old-root <hex> --new-root <hex> | --store file]`: verify interval proof

- **Examples**
  - `interval_absence.rs`: demonstrate continuous absence proofs across epochs

### Security

- Interval absence proofs combine single-epoch absence with consistency to prove continuous absence
- Relies on consistency proof security: if store is append-only, absence at start + not-in-added-set = absent throughout
- See THREAT_MODEL.md for limitations: does NOT prove temporal ordering of fact additions within an epoch
- Still a **toy/research** implementation — NOT audited

## [0.4.0] - 2026-09-28

### Added

- **Append-only consistency proofs** — prove a newer root is an extension of an older root
  - `ConsistencyProof`: sequence of absence proofs showing only facts were added, none removed
  - `ConsistencyError`: errors for generation and verification failures
  - `generate()`: build proof that appending facts to old tree yields new root
  - `verify_self()`: replay proof from old_root to new_root
  - `verify()`: verify against two explicit roots
  - `verify_checkpoints()`: verify between two checkpoints, including fact-count delta

- **AbsenceStore consistency integration**
  - `record_batch_with_proof()`: append facts and return consistency proof (all-or-nothing)
  - `verify_consistency()`: verify proof between two explicit roots
  - `verify_consistency_between_epochs()`: verify proof between two epoch checkpoints

- **CLI commands** (v0.4.0)
  - `prove-consistency --from <epoch> --to <epoch>`: generate consistency proof between epochs
  - `verify-consistency <proof.json> --old-root <hex> --new-root <hex>`: verify a consistency proof

- **Examples**
  - `consistency.rs`: demonstrate append-only proofs between epoch checkpoints

### Security

- Consistency proofs prevent forged removals or rewrites between roots
- Verifiers can check that a log is truly append-only without full replay
- Still a **toy/research** implementation — NOT audited

## [0.3.0] - 2026-09-27

### Added

- **Signed checkpoints** — cryptographic attestation of epoch roots
  - `SignerKey` / `VerifierKey`: Ed25519 keypair generation, hex serialization
  - `SignedCheckpoint`: wraps Checkpoint with Ed25519 signature over domain-separated canonical message (`absence.v1.signed-checkpoint`)
  - `sign_checkpoint()` / `verify_signed_checkpoint()` convenience APIs
  - Domain separation prevents signature replay across contexts

- **Root attestation** — bind proofs to signed checkpoints
  - `RootAttestation`: combines SignedCheckpoint with absence/membership proof
  - `verify_absent()` / `verify_present()`: checks BOTH Merkle proof AND signature
  - Full serde support for portable JSON transport

- **WitnessBundle** — portable proof packages
  - `WitnessBundle`: SignedCheckpoint + Vec<NonMembershipProof>
  - `verify_all()`: verifies signature and all proofs in one call
  - `CompactBundle`: wire-efficient multi-line format

- **AbsenceStore integration**
  - `checkpoint_signed(signer)`: create and sign checkpoint in one call
  - `signed_checkpoints()` / `signed_checkpoint_at(epoch)`: query signed history
  - Store persistence includes signed checkpoints (backward compatible)

- **CLI commands** (v0.3.0)
  - `keygen`: Generate Ed25519 keypair
  - `sign-checkpoint`: Sign a checkpoint from the store
  - `verify-checkpoint`: Verify a signed checkpoint
  - `attest-absent`: Create a RootAttestation for an absent fact
  - `verify-attestation`: Verify a RootAttestation

- **Dependencies**
  - `ed25519-dalek` 2.1 for Ed25519 signing
  - `rand` 0.8 for secure key generation

- **Examples**
  - `signed_checkpoint.rs`: comprehensive demo of signing workflow

### Security

- Signed checkpoints allow verifiers to trust roots without trusting the store operator
- Still a **toy/research** implementation — NOT zero-knowledge, NOT audited
- See THREAT_MODEL.md for signature security analysis

## [0.2.0] - 2026-09-25

### Added

- **Epoch checkpoints**
  - `EpochId` (`u64`) and `Checkpoint { epoch, root, fact_count, unix_ts }`
  - `AbsenceStore::checkpoint`, `checkpoints`, `checkpoint_at`, `set_checkpoint_history`
  - `verify_absent_at_epoch` / `verify_absent_at_checkpoint` for pinned historical roots
  - Checkpoint history persisted in the CLI store JSON

- **Batch absence proofs**
  - `prove_absent_batch` / `prove_absent_batch_json`
  - `verify_absent_batch` against a shared root
  - JSON helpers `batch_proofs_to_json` / `batch_proofs_from_json`
  - CLI: `prove-absent-batch` (multi JSON args or `--file` JSON lines), `verify-batch`

- **CompactProof** (`compact` module)
  - Length-prefixed binary encode/decode for membership and non-membership proofs
  - Hex wrappers; CLI `compact-encode` / `compact-decode`

- **CLI**
  - `checkpoint` / `checkpoints`
  - `verify --epoch` against a stored checkpoint root

- **Examples / fixtures**
  - `examples/epoch_batch.rs`
  - `examples/fixtures/batch_absent_facts.jsonl`

### Security

- Still a **toy/research** implementation — NOT zero-knowledge, NOT audited

## [0.1.0] - 2026-09-24

### Added

- **Sparse Merkle Tree** implementation with depth-256 (SHA-256 key space)
  - Correct empty-subtree default hashes
  - Insert, contains, root operations
  - Efficient storage of only non-empty nodes

- **Fact ID** module
  - Content-addressed 32-byte identifiers
  - SHA-256 of RFC 8785 (JCS) canonical JSON
  - Bit extraction for tree traversal

- **Non-membership (absence) proofs** (PRIMARY FEATURE)
  - Generate proof that a fact is NOT in the tree
  - Verify against pinned root hash
  - Serializable proof format

- **Membership proofs** (secondary)
  - Generate proof that a fact IS in the tree
  - Verify against pinned root hash

- **AbsenceStore API**
  - High-level interface for recording facts
  - Generate and verify both proof types
  - Commitment (root + count) for publishing

- **CLI** (`absence` binary)
  - `encode`: Compute fact-id from JSON
  - `insert`: Add facts to store file
  - `root`: Show current root hash
  - `prove-absent`: Generate absence proof
  - `prove-present`: Generate presence proof
  - `verify`: Verify any proof against root

- **Documentation**
  - README with usage examples and scope table
  - THREAT_MODEL.md with security analysis
  - SECURITY.md with disclosure policy

- **CI**
  - GitHub Actions: fmt, clippy, test, docs

### Security

- This is a **toy/research implementation** and is NOT production-ready
- NOT zero-knowledge (standard Merkle proofs)
- NOT audited

[0.5.0]: https://github.com/kritarth1107/Absence/releases/tag/v0.5.0
[0.4.0]: https://github.com/kritarth1107/Absence/releases/tag/v0.4.0
[0.3.0]: https://github.com/kritarth1107/Absence/releases/tag/v0.3.0
[0.2.0]: https://github.com/kritarth1107/Absence/releases/tag/v0.2.0
[0.1.0]: https://github.com/kritarth1107/Absence/releases/tag/v0.1.0
