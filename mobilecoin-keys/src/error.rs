//! Error types for key operations.

use thiserror::Error;

/// Errors that can occur during key operations.
#[derive(Debug, Error)]
pub enum KeyError {
    /// The key bytes are invalid.
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// Invalid public key.
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// The point is not on the curve.
    #[error("Point not on curve")]
    InvalidPoint,

    /// Key derivation failed.
    #[error("Key derivation failed: {0}")]
    DerivationError(String),

    /// The scalar is invalid.
    #[error("Invalid scalar: {0}")]
    InvalidScalar(String),

    /// Output index is out of bounds.
    #[error("Output index {0} is out of bounds")]
    IndexOutOfBounds(u64),

    /// The intent ID format is invalid.
    #[error("Invalid intent ID: {0}")]
    InvalidIntentId(String),
}
