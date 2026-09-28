# Threat Model

## Overview

Absence provides **non-membership proofs** for a committed set of facts. This document describes what security properties Absence provides and what it does NOT provide.

## What Absence Proves

### Non-Membership (Absence) Proofs

Given a published root hash R, an absence proof for fact F demonstrates:

- **If verification succeeds**: F was not in the set when R was computed
- **Binding**: The prover cannot create a valid absence proof for a fact that IS in the set
- **Determinism**: The same set always produces the same root hash

### Membership (Presence) Proofs

A presence proof for fact F demonstrates:

- **If verification succeeds**: F was in the set when R was computed
- **Binding**: The prover cannot create a valid presence proof for a fact that is NOT in the set

## Security Assumptions

1. **SHA-256 collision resistance**: Two different facts produce different fact IDs with overwhelming probability
2. **SHA-256 preimage resistance**: Given a fact ID, finding the original JSON is computationally infeasible
3. **Merkle tree security**: Standard assumptions about hash-based commitments

## What Absence Does NOT Provide

### NOT Zero-Knowledge

Absence proofs are NOT zero-knowledge:
- The verifier learns the fact ID being proven absent
- The proof itself reveals the sibling hashes along the path
- This is standard Merkle proof behavior, not a limitation

### NOT Private Set Operations

Absence does not hide:
- The number of facts in the set (implicit in root changes)
- Which fact is being proven absent (fact ID is in the proof)

For private set intersection, see [BlindOverlap](https://github.com/kritarth1107/BlindOverlap).

### NOT a ZK-SNARK System

Absence is NOT:
- A zero-knowledge proof system
- Based on elliptic curves or pairings
- Suitable for anonymous credentials
- Providing succinct proofs (proofs are O(log n) = 256 hashes)

### NOT Production Ready

- **No audit**: This code has not been professionally audited
- **Toy implementation**: Optimized for clarity, not performance
- **Limited testing**: Edge cases may not be covered
- **No persistence guarantees**: Simple JSON file storage

## Attack Vectors

### Root Hash Integrity

The security of absence proofs depends entirely on the integrity of the published root hash:

- If the prover can publish a false root, they can forge proofs
- Root hashes should be published to tamper-evident logs (blockchain, CT logs, etc.)
- Verifiers must obtain root hashes through trusted channels

### Replay Attacks

An old absence proof is valid against the old root:

- A fact proven absent at time T1 may be present at time T2
- Verifiers should check proofs against the CURRENT root
- Or explicitly accept proofs against historical roots

### Fact ID Collisions

If two different JSON values produce the same fact ID (SHA-256 collision):

- This would break the binding property
- SHA-256 collisions are considered computationally infeasible
- This is NOT a practical concern

## Signed Checkpoints (v0.3.0)

### What Signed Checkpoints Provide

`SignedCheckpoint` wraps a checkpoint with an Ed25519 signature:

- **Root attestation**: A trusted signer vouches for a specific root hash
- **Domain separation**: Signatures include `absence.v1.signed-checkpoint` prefix
- **Verifier independence**: Verifiers trust the signer's public key, not the store operator

### Additional Security Assumptions

1. **Ed25519 security**: Standard elliptic curve assumptions for digital signatures
2. **Signing key secrecy**: The signing key must remain secret; compromise allows forgery
3. **Public key distribution**: Verifiers must obtain the correct public key through trusted channels

### Signed Checkpoint Attack Vectors

**Key compromise**: If the signing key is stolen, an attacker can sign arbitrary roots.
- Mitigation: Secure key storage, key rotation, consider HSMs for high-value deployments

**Outdated signatures**: An old signed checkpoint is still valid.
- A signed root from T1 may not reflect facts added at T2
- Include timestamps; verifiers should check recency when relevant

**Domain confusion**: Without domain separation, signatures could be replayed in other contexts.
- Mitigated by `absence.v1.signed-checkpoint` domain prefix

### RootAttestation Security

`RootAttestation` binds a proof to a signed checkpoint:

- Verifies BOTH Merkle proof AND signature in one call
- Prevents proof/root mismatches (proof verified against wrong root)
- Does NOT provide non-repudiation (signer can claim key compromise)

## Consistency Proofs (v0.4.0)

### What Consistency Proofs Provide

`ConsistencyProof` demonstrates that a newer root is an append-only extension of an older root:

- **Append-only**: The new tree = old tree + added facts; nothing was removed or rewritten
- **Verifiable log growth**: Auditors can verify that a log grows monotonically
- **Efficient verification**: O(n) where n = number of added facts (not total facts)

### Security Properties

- **Binding**: Cannot create a valid consistency proof for roots where facts were removed
- **Determinism**: Same sequence of additions always produces the same proof
- **Composability**: If A→B and B→C are valid proofs, then B is reachable from A

### Consistency Proof Attack Vectors

**Step tampering**: Modifying any step in the proof chain invalidates verification.
- The `verify_self()` method replays all steps and checks final root

**Step omission**: Removing steps causes final root mismatch.
- Verifiers always check that replayed root equals claimed new_root

**Reordering attacks**: Facts must be added in the exact order they appear in steps.
- Reordering would change intermediate roots, causing verification failure

### Limitations

- Does NOT prove when facts were added (only that new root extends old)
- Does NOT hide which facts were added (fact IDs are in the proof)
- Verification requires O(n × depth) hash operations

## Recommended Use Cases

✓ **Agent memory auditing**: Prove an agent never stored specific data
✓ **Negative credentials**: Prove absence of a ban/restriction
✓ **Audit logs**: Prove an action was never logged
✓ **Append-only verification**: Prove a log grew without deletions (v0.4.0)
✓ **Research/prototyping**: Understand sparse Merkle trees

## NOT Recommended For

✗ **Production systems**: Not audited, not optimized
✗ **Anonymous proofs**: Proofs reveal fact IDs
✗ **Large-scale deployment**: O(256) proof size, no batching
✗ **Privacy-critical applications**: Use proper ZK systems
