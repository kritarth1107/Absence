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

## Interval Absence Proofs (v0.5.0)

### What Interval Absence Proofs Provide

`IntervalAbsenceProof` demonstrates that a fact was continuously absent across a contiguous epoch range:

- **Continuous absence**: The fact was not in the set at `from_epoch` AND was not added through `to_epoch`
- **Temporal coverage**: Unlike a single-epoch proof, covers an entire time window
- **Efficient verification**: Reuses consistency proof verification; O(n × depth) for n added facts

### Security Properties

- **Binding**: Cannot create a valid interval proof for a fact that was present or added
- **Relies on consistency**: Inherits append-only guarantees from the underlying consistency proof
- **Composability**: If absent [0,2] and [2,5] are valid, fact was absent [0,5] (requires verification)

### Interval Absence Attack Vectors

**Tampering with absence proof**: The initial absence proof at `from_epoch` must verify against that root.
- Forging requires breaking SHA-256 collision resistance

**Omitting added facts**: The consistency proof must include ALL facts added in the interval.
- Omitting a fact (especially the queried fact) would cause root mismatch

**Root substitution**: Claimed roots must match the actual checkpoint roots.
- `verify_checkpoints()` validates epoch numbers and roots match

### Limitations

- **Epoch granularity only**: Does NOT prove temporal ordering within a single epoch. If multiple facts are added before a checkpoint, their relative order is not captured.
- **Requires fact history**: Generating proofs requires the insertion-order history of facts (stored in `AbsenceStore.fact_history` or persisted in the store file).
- **Does NOT prove non-existence before `from_epoch`**: The fact may have been present before the interval started.
- **Proof size**: Includes full absence proof + consistency proof; O(depth + n × depth) for n added facts.
- **Does NOT hide interval bounds or added facts**: Epoch range and added fact IDs are visible in the proof.

## Attested Proofs (v0.6.0)

### What Attested Proofs Provide

`AttestedConsistency` and `AttestedInterval` bind proofs to Ed25519-signed checkpoint pairs:

- **Signature binding**: Both endpoints (old/from and new/to checkpoints) are signed
- **Single-key verification**: Verifiers need only the signer's public key
- **No store access required**: All verification data is in the portable JSON proof
- **Combined verification**: Checks signatures AND underlying proof validity in one call

### Security Properties

- **Inherits proof security**: All guarantees from ConsistencyProof/IntervalAbsenceProof apply
- **Inherits signature security**: All guarantees from SignedCheckpoint apply
- **Signer consistency**: Both checkpoints must be signed by the same key
- **Binding**: Cannot create valid attested proof without both valid signatures and valid underlying proof

### Attested Proof Attack Vectors

**Key compromise**: If the signing key is compromised, attacker can sign arbitrary checkpoints.
- Mitigation: Same as SignedCheckpoint — secure key storage, rotation, HSMs

**Mixed signers**: Attempting to combine checkpoints from different signers.
- Detection: `verify()` checks `signer_public_key` matches on both checkpoints
- Returns `SignedError::SignerMismatch` if different keys detected

**Tampered checkpoint**: Modifying a checkpoint after signing.
- Detection: Signature verification fails for the tampered checkpoint

**Tampered proof**: Modifying the underlying ConsistencyProof or IntervalAbsenceProof.
- Detection: Proof verification against the signed roots fails

**Swapped checkpoints**: Using old checkpoint as new and vice versa.
- Detection: Underlying proof verification fails (wrong epoch order, root mismatch)

### Limitations

- **Does NOT provide non-repudiation**: Signer can claim key compromise
- **Does NOT hide proof contents**: Same as underlying proofs — epoch range, fact IDs visible
- **Proof size**: Sum of two SignedCheckpoints + underlying proof
- **No key rotation support**: Each attested proof is bound to a single key pair

## Recommended Use Cases

✓ **Agent memory auditing**: Prove an agent never stored specific data
✓ **Negative credentials**: Prove absence of a ban/restriction
✓ **Audit logs**: Prove an action was never logged
✓ **Append-only verification**: Prove a log grew without deletions (v0.4.0)
✓ **Continuous absence auditing**: Prove data was never stored during a time window (v0.5.0)
✓ **Cross-system verification**: Share attested proofs between services (v0.6.0)
✓ **Offline verification**: Verify proofs without access to the original store (v0.6.0)
✓ **Research/prototyping**: Understand sparse Merkle trees

## NOT Recommended For

✗ **Production systems**: Not audited, not optimized
✗ **Anonymous proofs**: Proofs reveal fact IDs
✗ **Large-scale deployment**: O(256) proof size, no batching
✗ **Privacy-critical applications**: Use proper ZK systems
