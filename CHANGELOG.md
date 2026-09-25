# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.2.0]: https://github.com/kritarth1107/Absence/releases/tag/v0.2.0
[0.1.0]: https://github.com/kritarth1107/Absence/releases/tag/v0.1.0
