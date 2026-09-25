//! Absence: Sparse Merkle Tree with non-membership proofs
//!
//! Prove a key/fact is NOT in a committed set without revealing the rest of the set.

pub mod compact;
pub mod fact_id;
pub mod proof;
pub mod smt;
pub mod store;

pub use compact::{CompactError, CompactProof};
pub use fact_id::FactId;
pub use proof::{MembershipProof, NonMembershipProof};
pub use smt::SparseMerkleTree;
pub use store::{AbsenceStore, Checkpoint, Commitment, EpochId, StoreError};
