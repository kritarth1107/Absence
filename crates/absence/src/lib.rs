//! Absence: Sparse Merkle Tree with non-membership proofs
//!
//! Prove a key/fact is NOT in a committed set without revealing the rest of the set.

pub mod compact;
pub mod fact_id;
pub mod keys;
pub mod proof;
pub mod signed;
pub mod smt;
pub mod store;

pub use compact::{CompactError, CompactProof};
pub use fact_id::FactId;
pub use keys::{KeyError, SignerKey, VerifierKey};
pub use proof::{MembershipProof, NonMembershipProof};
pub use signed::{
    sign_checkpoint, verify_attested_absent, verify_attested_present, verify_signed_checkpoint,
    RootAttestation, SignedCheckpoint, SignedError, SIGNED_CHECKPOINT_DOMAIN,
};
pub use smt::SparseMerkleTree;
pub use store::{AbsenceStore, Checkpoint, Commitment, EpochId, StoreError};
