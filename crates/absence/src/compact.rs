//! Compact binary encoding for membership and absence proofs.
//!
//! Wire format (little-endian length prefix):
//!
//! ```text
//! fact_id:     32 bytes
//! sibling_len: u16 LE  (number of sibling hashes)
//! siblings:    sibling_len × 32 bytes
//! ```
//!
//! Hex wrappers encode/decode the same bytes as lowercase hex.
//! This is a size-friendly alternative to JSON; it is NOT zero-knowledge.

use crate::proof::{MembershipProof, NonMembershipProof};
use crate::smt::{NodeHash, TREE_DEPTH};
use thiserror::Error;

/// Errors from compact encode/decode.
#[derive(Debug, Error, PartialEq)]
pub enum CompactError {
    #[error("truncated compact proof input")]
    Truncated,

    #[error("invalid sibling count: expected {expected}, got {got}")]
    InvalidSiblingCount { expected: usize, got: usize },

    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),
}

/// Namespace for compact proof encode/decode helpers.
pub struct CompactProof;

impl CompactProof {
    /// Encode an absence (non-membership) proof to compact bytes.
    pub fn encode_absence(proof: &NonMembershipProof) -> Vec<u8> {
        encode_raw(&proof.fact_id, &proof.siblings)
    }

    /// Decode an absence proof from compact bytes.
    pub fn decode_absence(bytes: &[u8]) -> Result<NonMembershipProof, CompactError> {
        let (fact_id, siblings) = decode_raw(bytes)?;
        Ok(NonMembershipProof { fact_id, siblings })
    }

    /// Encode an absence proof as lowercase hex.
    pub fn encode_absence_hex(proof: &NonMembershipProof) -> String {
        hex::encode(Self::encode_absence(proof))
    }

    /// Decode an absence proof from hex.
    pub fn decode_absence_hex(s: &str) -> Result<NonMembershipProof, CompactError> {
        let bytes = hex::decode(s.trim())?;
        Self::decode_absence(&bytes)
    }

    /// Encode a membership proof to compact bytes.
    pub fn encode_membership(proof: &MembershipProof) -> Vec<u8> {
        encode_raw(&proof.fact_id, &proof.siblings)
    }

    /// Decode a membership proof from compact bytes.
    pub fn decode_membership(bytes: &[u8]) -> Result<MembershipProof, CompactError> {
        let (fact_id, siblings) = decode_raw(bytes)?;
        Ok(MembershipProof { fact_id, siblings })
    }

    /// Encode a membership proof as lowercase hex.
    pub fn encode_membership_hex(proof: &MembershipProof) -> String {
        hex::encode(Self::encode_membership(proof))
    }

    /// Decode a membership proof from hex.
    pub fn decode_membership_hex(s: &str) -> Result<MembershipProof, CompactError> {
        let bytes = hex::decode(s.trim())?;
        Self::decode_membership(&bytes)
    }
}

fn encode_raw(fact_id: &[u8; 32], siblings: &[NodeHash]) -> Vec<u8> {
    let count = siblings.len() as u16;
    let mut out = Vec::with_capacity(32 + 2 + siblings.len() * 32);
    out.extend_from_slice(fact_id);
    out.extend_from_slice(&count.to_le_bytes());
    for sib in siblings {
        out.extend_from_slice(sib);
    }
    out
}

fn decode_raw(bytes: &[u8]) -> Result<([u8; 32], Vec<NodeHash>), CompactError> {
    if bytes.len() < 34 {
        return Err(CompactError::Truncated);
    }
    let mut fact_id = [0u8; 32];
    fact_id.copy_from_slice(&bytes[..32]);
    let count = u16::from_le_bytes([bytes[32], bytes[33]]) as usize;
    if count != TREE_DEPTH {
        return Err(CompactError::InvalidSiblingCount {
            expected: TREE_DEPTH,
            got: count,
        });
    }
    let expected_len = 34 + count * 32;
    if bytes.len() != expected_len {
        return Err(CompactError::Truncated);
    }
    let mut siblings = Vec::with_capacity(count);
    let mut offset = 34;
    for _ in 0..count {
        let mut h = [0u8; 32];
        h.copy_from_slice(&bytes[offset..offset + 32]);
        siblings.push(h);
        offset += 32;
    }
    Ok((fact_id, siblings))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smt::SparseMerkleTree;
    use crate::FactId;
    use serde_json::json;

    #[test]
    fn test_absence_compact_roundtrip() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(&FactId::from_json_value(&json!({"other": 1})));
        let absent = FactId::from_json_value(&json!({"absent": true}));
        let proof = NonMembershipProof::generate(&tree, &absent).unwrap();

        let bytes = CompactProof::encode_absence(&proof);
        assert_eq!(bytes.len(), 34 + TREE_DEPTH * 32);

        let restored = CompactProof::decode_absence(&bytes).unwrap();
        assert_eq!(restored.fact_id, proof.fact_id);
        assert_eq!(restored.siblings, proof.siblings);
        assert!(restored.verify(tree.root()).is_ok());
    }

    #[test]
    fn test_absence_compact_hex_roundtrip() {
        let tree = SparseMerkleTree::new();
        let absent = FactId::from_json_value(&json!({"hex": "roundtrip"}));
        let proof = NonMembershipProof::generate(&tree, &absent).unwrap();

        let hex_s = CompactProof::encode_absence_hex(&proof);
        assert!(hex_s.chars().all(|c| c.is_ascii_hexdigit()));
        let restored = CompactProof::decode_absence_hex(&hex_s).unwrap();
        assert!(restored.verify(tree.root()).is_ok());
    }

    #[test]
    fn test_membership_compact_roundtrip() {
        let mut tree = SparseMerkleTree::new();
        let fact = FactId::from_json_value(&json!({"present": 42}));
        tree.insert(&fact);
        let proof = MembershipProof::generate(&tree, &fact).unwrap();

        let bytes = CompactProof::encode_membership(&proof);
        let restored = CompactProof::decode_membership(&bytes).unwrap();
        assert_eq!(restored.fact_id, proof.fact_id);
        assert!(restored.verify(tree.root()).is_ok());

        let hex_s = CompactProof::encode_membership_hex(&proof);
        let restored2 = CompactProof::decode_membership_hex(&hex_s).unwrap();
        assert!(restored2.verify(tree.root()).is_ok());
    }

    #[test]
    fn test_compact_truncated() {
        assert!(matches!(
            CompactProof::decode_absence(&[0u8; 10]),
            Err(CompactError::Truncated)
        ));
    }

    #[test]
    fn test_compact_bad_sibling_count() {
        let mut bytes = vec![0u8; 34];
        // count = 1 (not TREE_DEPTH)
        bytes[32] = 1;
        bytes[33] = 0;
        bytes.extend_from_slice(&[0u8; 32]);
        assert!(matches!(
            CompactProof::decode_absence(&bytes),
            Err(CompactError::InvalidSiblingCount { .. })
        ));
    }
}
