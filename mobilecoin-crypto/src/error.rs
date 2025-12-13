//! Error types for cryptographic operations.

use thiserror::Error;

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// The public key has an invalid length or format.
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// The signature has an invalid length or format.
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// The signature verification failed.
    #[error("Signature verification failed")]
    VerificationFailed,

    /// The message hash computation failed.
    #[error("Hash computation failed: {0}")]
    HashError(String),

    /// Key generation failed.
    #[error("Key generation failed: {0}")]
    KeyGenerationError(String),

    /// Serialization or deserialization failed.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// The payload format is invalid.
    #[error("Invalid payload: {0}")]
    InvalidPayload(String),
}

impl From<ed25519_dalek::SignatureError> for CryptoError {
    fn from(err: ed25519_dalek::SignatureError) -> Self {
        CryptoError::InvalidSignature(err.to_string())
    }
}
