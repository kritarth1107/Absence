//! Absence: Sparse Merkle Tree with non-membership proofs
//!
//! Prove a key/fact is NOT in a committed set without revealing the rest of the set.

pub mod bundle;
pub mod compact;
pub mod consistency;
pub mod fact_id;
pub mod interval;
pub mod keys;
pub mod proof;
pub mod signed;
pub mod smt;
pub mod store;

pub use bundle::{BundleDecodeError, CompactBundle, WitnessBundle};
pub use compact::{CompactError, CompactProof};
pub use consistency::{ConsistencyError, ConsistencyProof};
pub use fact_id::FactId;
pub use interval::{IntervalAbsenceProof, IntervalError};
pub use keys::{KeyError, SignerKey, VerifierKey};
pub use proof::{MembershipProof, NonMembershipProof};
pub use signed::{
    sign_checkpoint, verify_attested_absent, verify_attested_consistency, verify_attested_interval,
    verify_attested_present, verify_signed_checkpoint, AttestedConsistency, AttestedInterval,
    RootAttestation, SignedCheckpoint, SignedError, SIGNED_CHECKPOINT_DOMAIN,
};
pub use smt::SparseMerkleTree;
pub use store::{AbsenceStore, Checkpoint, Commitment, EpochId, StoreError};
