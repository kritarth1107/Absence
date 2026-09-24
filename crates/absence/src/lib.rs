//! Absence: Sparse Merkle Tree with non-membership proofs
//!
//! Prove a key/fact is NOT in a committed set without revealing the rest of the set.

pub mod fact_id;
pub mod smt;
pub mod proof;
pub mod store;

pub use fact_id::FactId;
pub use smt::SparseMerkleTree;
pub use proof::{MembershipProof, NonMembershipProof};
pub use store::AbsenceStore;
