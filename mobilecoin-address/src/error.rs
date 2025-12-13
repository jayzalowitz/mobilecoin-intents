//! Error types for address operations.

use thiserror::Error;

/// Errors that can occur during address operations.
#[derive(Debug, Error)]
pub enum AddressError {
    /// The address string is not valid Base58.
    #[error("Invalid Base58 encoding: {0}")]
    InvalidBase58(String),

    /// The address checksum is invalid.
    #[error("Invalid checksum")]
    InvalidChecksum,

    /// The address has an invalid length.
    #[error("Invalid address length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    /// The address version byte is invalid.
    #[error("Invalid version byte: {0}")]
    InvalidVersion(u8),

    /// The public key point is not on the curve.
    #[error("Invalid public key: not on curve")]
    InvalidPublicKey,

    /// The network does not match expected.
    #[error("Network mismatch: expected {expected:?}, got {actual:?}")]
    NetworkMismatch {
        expected: crate::MobNetwork,
        actual: crate::MobNetwork,
    },

    /// The Fog metadata is invalid.
    #[error("Invalid Fog info: {0}")]
    InvalidFogInfo(String),

    /// The address format is unrecognized.
    #[error("Unrecognized address format")]
    UnrecognizedFormat,

    /// Serialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),
}
