//! Sparse Merkle Tree implementation
//!
//! A Sparse Merkle Tree (SMT) is a Merkle tree where most leaves are empty.
//! It uses precomputed "default hashes" for empty subtrees, making it efficient
//! for sparse key spaces like SHA-256 fact IDs.
//!
//! This implementation uses depth-256 (matching SHA-256 fact IDs) but stores
//! only non-empty nodes in a HashMap for efficiency.

use crate::FactId;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::LazyLock;

/// Tree depth (256 bits for SHA-256 keys).
pub const TREE_DEPTH: usize = 256;

/// Precomputed default hashes for empty subtrees at each level.
/// default_hashes[0] = hash of empty leaf
/// default_hashes[i] = hash(default_hashes[i-1] || default_hashes[i-1])
static DEFAULT_HASHES: LazyLock<[[u8; 32]; TREE_DEPTH + 1]> = LazyLock::new(|| {
    let mut hashes = [[0u8; 32]; TREE_DEPTH + 1];
    hashes[0] = Sha256::digest(b"").into();
    for i in 1..=TREE_DEPTH {
        let mut hasher = Sha256::new();
        hasher.update(hashes[i - 1]);
        hasher.update(hashes[i - 1]);
        hashes[i] = hasher.finalize().into();
    }
    hashes
});

/// Get the default hash for an empty subtree at a given depth.
/// depth=0 means leaf level, depth=256 means root of empty tree.
#[inline]
pub fn default_hash(depth: usize) -> &'static [u8; 32] {
    &DEFAULT_HASHES[depth]
}

/// A node hash in the tree.
pub type NodeHash = [u8; 32];

/// A Sparse Merkle Tree for fact IDs.
///
/// Keys are 256-bit FactIds; values are marked as present (leaf = H(key)) or absent.
#[derive(Clone, Debug)]
pub struct SparseMerkleTree {
    nodes: HashMap<(usize, [u8; 32]), NodeHash>,
    leaves: HashMap<[u8; 32], bool>,
    root: NodeHash,
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl SparseMerkleTree {
    /// Create a new empty Sparse Merkle Tree.
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            leaves: HashMap::new(),
            root: *default_hash(TREE_DEPTH),
        }
    }

    /// Get the current root hash.
    pub fn root(&self) -> &NodeHash {
        &self.root
    }

    /// Check if a fact ID is in the tree.
    pub fn contains(&self, fact_id: &FactId) -> bool {
        self.leaves
            .get(fact_id.as_bytes())
            .copied()
            .unwrap_or(false)
    }

    /// Insert a fact ID into the tree.
    /// Returns true if the fact was newly inserted, false if already present.
    pub fn insert(&mut self, fact_id: &FactId) -> bool {
        let key = *fact_id.as_bytes();

        if self.leaves.get(&key).copied().unwrap_or(false) {
            return false;
        }

        self.leaves.insert(key, true);
        self.recompute_path(fact_id);
        true
    }

    /// Recompute the path from leaf to root after an insertion.
    fn recompute_path(&mut self, fact_id: &FactId) {
        let leaf_hash = Self::leaf_hash(fact_id);
        let key = *fact_id.as_bytes();

        let mut current_hash = leaf_hash;

        for depth in 0..TREE_DEPTH {
            let bit = fact_id.bit(TREE_DEPTH - 1 - depth);
            let sibling_path = Self::sibling_path(&key, depth);
            let sibling_hash = self.get_node_hash(depth, &sibling_path);

            let parent_hash = if bit {
                Self::hash_pair(&sibling_hash, &current_hash)
            } else {
                Self::hash_pair(&current_hash, &sibling_hash)
            };

            let node_path = Self::path_for_depth(&key, depth + 1);
            self.nodes.insert((depth + 1, node_path), parent_hash);
            current_hash = parent_hash;
        }

        self.root = current_hash;
    }

    /// Get the hash of a node at a given depth and path.
    pub fn get_node_hash(&self, depth: usize, path: &[u8; 32]) -> NodeHash {
        if depth == 0 {
            if self.leaves.get(path).copied().unwrap_or(false) {
                return Self::leaf_hash(&FactId::from_bytes(*path));
            }
            return *default_hash(0);
        }

        self.nodes
            .get(&(depth, *path))
            .copied()
            .unwrap_or_else(|| *default_hash(depth))
    }

    /// Compute leaf hash: H(fact_id).
    pub fn leaf_hash(fact_id: &FactId) -> NodeHash {
        Sha256::digest(fact_id.as_bytes()).into()
    }

    /// Hash two nodes together: H(left || right).
    pub fn hash_pair(left: &NodeHash, right: &NodeHash) -> NodeHash {
        let mut hasher = Sha256::new();
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }

    /// Get the sibling's path at a given depth.
    /// At depth d (from leaves), paths have (256-d) significant bits.
    fn sibling_path(key: &[u8; 32], depth: usize) -> [u8; 32] {
        let mut path = *key;
        let bit_idx = TREE_DEPTH - 1 - depth;
        let byte_idx = bit_idx / 8;
        let bit_in_byte = 7 - (bit_idx % 8);
        path[byte_idx] ^= 1 << bit_in_byte;
        Self::truncate_to_bits(&path, TREE_DEPTH - depth)
    }

    /// Get the canonical path for a node at a given depth.
    /// At depth d, the path has (256-d) significant bits.
    fn path_for_depth(key: &[u8; 32], depth: usize) -> [u8; 32] {
        Self::truncate_to_bits(key, TREE_DEPTH - depth)
    }

    /// Truncate path to only include the first `num_bits` bits.
    fn truncate_to_bits(key: &[u8; 32], num_bits: usize) -> [u8; 32] {
        if num_bits >= TREE_DEPTH {
            return *key;
        }
        if num_bits == 0 {
            return [0u8; 32];
        }
        let mut result = [0u8; 32];
        let full_bytes = num_bits / 8;
        let remaining_bits = num_bits % 8;

        result[..full_bytes].copy_from_slice(&key[..full_bytes]);
        if remaining_bits > 0 && full_bytes < 32 {
            let mask = 0xFF << (8 - remaining_bits);
            result[full_bytes] = key[full_bytes] & mask;
        }
        result
    }

    /// Get the number of facts in the tree.
    pub fn len(&self) -> usize {
        self.leaves.values().filter(|&&v| v).count()
    }

    /// Check if the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get a sibling hash for proof generation at a given depth.
    pub fn get_sibling_hash(&self, fact_id: &FactId, depth: usize) -> NodeHash {
        let key = *fact_id.as_bytes();
        let sibling_path = Self::sibling_path(&key, depth);
        self.get_node_hash(depth, &sibling_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_empty_tree_root() {
        let tree = SparseMerkleTree::new();
        assert_eq!(tree.root(), default_hash(TREE_DEPTH));
    }

    #[test]
    fn test_insert_and_contains() {
        let mut tree = SparseMerkleTree::new();
        let fact = FactId::from_json_value(&json!({"key": "value"}));

        assert!(!tree.contains(&fact));
        assert!(tree.insert(&fact));
        assert!(tree.contains(&fact));
        assert!(!tree.insert(&fact));
    }

    #[test]
    fn test_root_changes_on_insert() {
        let mut tree = SparseMerkleTree::new();
        let initial_root = *tree.root();

        let fact = FactId::from_json_value(&json!({"test": 1}));
        tree.insert(&fact);

        assert_ne!(*tree.root(), initial_root);
    }

    #[test]
    fn test_deterministic_root() {
        let facts = vec![
            FactId::from_json_value(&json!({"a": 1})),
            FactId::from_json_value(&json!({"b": 2})),
            FactId::from_json_value(&json!({"c": 3})),
        ];

        let mut tree1 = SparseMerkleTree::new();
        for fact in &facts {
            tree1.insert(fact);
        }

        let mut tree2 = SparseMerkleTree::new();
        for fact in &facts {
            tree2.insert(fact);
        }

        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_order_independent_root() {
        let fact_a = FactId::from_json_value(&json!({"a": 1}));
        let fact_b = FactId::from_json_value(&json!({"b": 2}));

        let mut tree1 = SparseMerkleTree::new();
        tree1.insert(&fact_a);
        tree1.insert(&fact_b);

        let mut tree2 = SparseMerkleTree::new();
        tree2.insert(&fact_b);
        tree2.insert(&fact_a);

        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_tree_len() {
        let mut tree = SparseMerkleTree::new();
        assert_eq!(tree.len(), 0);
        assert!(tree.is_empty());

        tree.insert(&FactId::from_json_value(&json!({"a": 1})));
        assert_eq!(tree.len(), 1);
        assert!(!tree.is_empty());

        tree.insert(&FactId::from_json_value(&json!({"b": 2})));
        assert_eq!(tree.len(), 2);
    }

    #[test]
    fn test_default_hashes_chain() {
        let h0 = default_hash(0);
        let expected_h1 = SparseMerkleTree::hash_pair(h0, h0);
        assert_eq!(*default_hash(1), expected_h1);
    }

    #[test]
    fn test_leaf_hash() {
        let fact = FactId::from_json_value(&json!({"test": true}));
        let hash = SparseMerkleTree::leaf_hash(&fact);
        assert_ne!(hash, *default_hash(0));
    }
}
