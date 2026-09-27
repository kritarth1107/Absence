//! Ed25519 signing keys for checkpoint attestation.
//!
//! Provides [`SignerKey`] (private) and [`VerifierKey`] (public) for signing
//! and verifying epoch checkpoints. Keys serialize to/from hex.

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Length of a secret key in bytes.
pub const SECRET_KEY_LEN: usize = 32;
/// Length of a public (verifier) key in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Errors related to key operations.
#[derive(Debug, Error)]
pub enum KeyError {
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },

    #[error("invalid hex: {0}")]
    HexDecode(#[from] hex::FromHexError),

    #[error("invalid key bytes")]
    InvalidKeyBytes,
}

/// Ed25519 signing (private) key for creating signed checkpoints.
///
/// # Example
///
/// ```
/// use absence::keys::SignerKey;
///
/// let signer = SignerKey::generate();
/// let hex = signer.to_hex();
/// let restored = SignerKey::from_hex(&hex).unwrap();
/// assert_eq!(signer.verifier().to_hex(), restored.verifier().to_hex());
/// ```
#[derive(Clone)]
pub struct SignerKey {
    inner: SigningKey,
}

impl SignerKey {
    /// Generate a new random signing key using OS entropy.
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let inner = SigningKey::generate(&mut csprng);
        Self { inner }
    }

    /// Create from raw 32-byte secret key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        if bytes.len() != SECRET_KEY_LEN {
            return Err(KeyError::InvalidLength {
                expected: SECRET_KEY_LEN,
                got: bytes.len(),
            });
        }
        let mut arr = [0u8; SECRET_KEY_LEN];
        arr.copy_from_slice(bytes);
        Ok(Self {
            inner: SigningKey::from_bytes(&arr),
        })
    }

    /// Create from hex-encoded secret key.
    pub fn from_hex(hex: &str) -> Result<Self, KeyError> {
        let bytes = hex::decode(hex.trim())?;
        Self::from_bytes(&bytes)
    }

    /// Serialize to raw 32-byte secret key.
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LEN] {
        self.inner.to_bytes()
    }

    /// Serialize to lowercase hex (64 characters).
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Get the corresponding public verifier key.
    pub fn verifier(&self) -> VerifierKey {
        VerifierKey {
            inner: self.inner.verifying_key(),
        }
    }

    #[allow(dead_code)] // Used by signed module
    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.inner
    }
}

impl std::fmt::Debug for SignerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignerKey")
            .field("public", &self.verifier().to_hex())
            .finish_non_exhaustive()
    }
}

/// Ed25519 verifying (public) key for checking signed checkpoints.
///
/// Can be shared publicly; only proves identity, does not grant signing ability.
///
/// # Example
///
/// ```
/// use absence::keys::{SignerKey, VerifierKey};
///
/// let signer = SignerKey::generate();
/// let verifier = signer.verifier();
/// let hex = verifier.to_hex();
/// let restored = VerifierKey::from_hex(&hex).unwrap();
/// assert_eq!(verifier.to_hex(), restored.to_hex());
/// ```
#[derive(Clone, Serialize, Deserialize)]
pub struct VerifierKey {
    #[serde(
        serialize_with = "serialize_verifying_key",
        deserialize_with = "deserialize_verifying_key"
    )]
    inner: VerifyingKey,
}

fn serialize_verifying_key<S>(key: &VerifyingKey, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&hex::encode(key.to_bytes()))
}

fn deserialize_verifying_key<'de, D>(deserializer: D) -> Result<VerifyingKey, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let hex_str = String::deserialize(deserializer)?;
    let bytes = hex::decode(hex_str.trim()).map_err(serde::de::Error::custom)?;
    if bytes.len() != PUBLIC_KEY_LEN {
        return Err(serde::de::Error::custom(format!(
            "invalid key length: expected {}, got {}",
            PUBLIC_KEY_LEN,
            bytes.len()
        )));
    }
    let mut arr = [0u8; PUBLIC_KEY_LEN];
    arr.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&arr).map_err(serde::de::Error::custom)
}

impl VerifierKey {
    /// Create from raw 32-byte public key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        if bytes.len() != PUBLIC_KEY_LEN {
            return Err(KeyError::InvalidLength {
                expected: PUBLIC_KEY_LEN,
                got: bytes.len(),
            });
        }
        let mut arr = [0u8; PUBLIC_KEY_LEN];
        arr.copy_from_slice(bytes);
        let inner =
            VerifyingKey::from_bytes(&arr).map_err(|_| KeyError::InvalidKeyBytes)?;
        Ok(Self { inner })
    }

    /// Create from hex-encoded public key.
    pub fn from_hex(hex: &str) -> Result<Self, KeyError> {
        let bytes = hex::decode(hex.trim())?;
        Self::from_bytes(&bytes)
    }

    /// Serialize to raw 32-byte public key.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.inner.to_bytes()
    }

    /// Serialize to lowercase hex (64 characters).
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    #[allow(dead_code)] // Used by signed module
    pub(crate) fn verifying_key(&self) -> &VerifyingKey {
        &self.inner
    }
}

impl std::fmt::Debug for VerifierKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifierKey")
            .field("hex", &self.to_hex())
            .finish()
    }
}

impl PartialEq for VerifierKey {
    fn eq(&self, other: &Self) -> bool {
        self.inner.to_bytes() == other.inner.to_bytes()
    }
}

impl Eq for VerifierKey {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signer_key_generate() {
        let key1 = SignerKey::generate();
        let key2 = SignerKey::generate();
        assert_ne!(key1.to_hex(), key2.to_hex());
    }

    #[test]
    fn test_signer_key_roundtrip_bytes() {
        let key = SignerKey::generate();
        let bytes = key.to_bytes();
        let restored = SignerKey::from_bytes(&bytes).unwrap();
        assert_eq!(key.to_hex(), restored.to_hex());
    }

    #[test]
    fn test_signer_key_roundtrip_hex() {
        let key = SignerKey::generate();
        let hex = key.to_hex();
        assert_eq!(hex.len(), 64);
        let restored = SignerKey::from_hex(&hex).unwrap();
        assert_eq!(key.to_hex(), restored.to_hex());
    }

    #[test]
    fn test_signer_key_hex_whitespace() {
        let key = SignerKey::generate();
        let hex = format!("  {}  \n", key.to_hex());
        let restored = SignerKey::from_hex(&hex).unwrap();
        assert_eq!(key.to_hex(), restored.to_hex());
    }

    #[test]
    fn test_signer_key_invalid_length() {
        let err = SignerKey::from_bytes(&[0u8; 16]).unwrap_err();
        match err {
            KeyError::InvalidLength { expected, got } => {
                assert_eq!(expected, 32);
                assert_eq!(got, 16);
            }
            _ => panic!("expected InvalidLength error"),
        }
    }

    #[test]
    fn test_verifier_from_signer() {
        let signer = SignerKey::generate();
        let verifier = signer.verifier();
        assert_eq!(verifier.to_hex().len(), 64);
    }

    #[test]
    fn test_verifier_key_roundtrip_bytes() {
        let signer = SignerKey::generate();
        let verifier = signer.verifier();
        let bytes = verifier.to_bytes();
        let restored = VerifierKey::from_bytes(&bytes).unwrap();
        assert_eq!(verifier.to_hex(), restored.to_hex());
    }

    #[test]
    fn test_verifier_key_roundtrip_hex() {
        let signer = SignerKey::generate();
        let verifier = signer.verifier();
        let hex = verifier.to_hex();
        let restored = VerifierKey::from_hex(&hex).unwrap();
        assert_eq!(verifier.to_hex(), restored.to_hex());
    }

    #[test]
    fn test_verifier_key_invalid_length() {
        let err = VerifierKey::from_bytes(&[0u8; 10]).unwrap_err();
        match err {
            KeyError::InvalidLength { expected, got } => {
                assert_eq!(expected, 32);
                assert_eq!(got, 10);
            }
            _ => panic!("expected InvalidLength error"),
        }
    }

    #[test]
    fn test_verifier_key_serde() {
        let signer = SignerKey::generate();
        let verifier = signer.verifier();
        let json = serde_json::to_string(&verifier).unwrap();
        let restored: VerifierKey = serde_json::from_str(&json).unwrap();
        assert_eq!(verifier, restored);
    }

    #[test]
    fn test_signer_debug_hides_secret() {
        let signer = SignerKey::generate();
        let debug = format!("{:?}", signer);
        assert!(debug.contains("SignerKey"));
        assert!(!debug.contains(&signer.to_hex()));
    }
}
