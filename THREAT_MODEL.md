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

## Recommended Use Cases

✓ **Agent memory auditing**: Prove an agent never stored specific data
✓ **Negative credentials**: Prove absence of a ban/restriction
✓ **Audit logs**: Prove an action was never logged
✓ **Research/prototyping**: Understand sparse Merkle trees

## NOT Recommended For

✗ **Production systems**: Not audited, not optimized
✗ **Anonymous proofs**: Proofs reveal fact IDs
✗ **Large-scale deployment**: O(256) proof size, no batching
✗ **Privacy-critical applications**: Use proper ZK systems
