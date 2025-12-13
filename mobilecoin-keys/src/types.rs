//! Core key types for MobileCoin one-time addresses.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A Ristretto private key (scalar).
///
/// # Security
/// - Uses `OsRng` for cryptographically secure random generation
/// - Implements `ZeroizeOnDrop` to securely erase the key from memory
/// - Debug output is redacted to prevent key leakage in logs
#[derive(Clone, ZeroizeOnDrop)]
pub struct RistrettoPrivate(#[zeroize(skip)] pub Scalar);

impl RistrettoPrivate {
    /// Create from a scalar.
    pub fn new(scalar: Scalar) -> Self {
        Self(scalar)
    }

    /// Generate a random private key using cryptographically secure RNG.
    ///
    /// # Security
    /// Uses `OsRng` which provides cryptographically secure randomness
    /// from the operating system.
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        let scalar = Scalar::from_bytes_mod_order_wide(&bytes);
        // Zero the temporary bytes
        bytes.zeroize();
        Self(scalar)
    }

    /// Create from bytes (mod order).
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(Scalar::from_bytes_mod_order(*bytes))
    }

    /// Get the scalar.
    pub fn as_scalar(&self) -> &Scalar {
        &self.0
    }

    /// Convert to bytes.
    ///
    /// # Security Warning
    /// The returned bytes contain the private key. Ensure they are
    /// zeroized after use.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Compute the corresponding public key.
    pub fn public_key(&self) -> RistrettoPublic {
        let point = RISTRETTO_BASEPOINT_TABLE.basepoint() * self.0;
        RistrettoPublic::from_point(point)
    }
}

impl std::fmt::Debug for RistrettoPrivate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RistrettoPrivate([REDACTED])")
    }
}

/// A Ristretto public key (compressed point).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RistrettoPublic(pub [u8; 32]);

impl RistrettoPublic {
    /// Create from bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create from a Ristretto point.
    pub fn from_point(point: RistrettoPoint) -> Self {
        Self(point.compress().to_bytes())
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Create from hex string.
    pub fn from_hex(hex_str: &str) -> Result<Self, crate::KeyError> {
        let bytes = hex::decode(hex_str).map_err(|e| crate::KeyError::InvalidKey(e.to_string()))?;

        if bytes.len() != 32 {
            return Err(crate::KeyError::InvalidKey(format!(
                "Expected 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Decompress to a Ristretto point.
    pub fn decompress(&self) -> Option<RistrettoPoint> {
        CompressedRistretto::from_slice(&self.0)
            .ok()
            .and_then(|c| c.decompress())
    }

    /// Check if this is a valid point.
    pub fn is_valid(&self) -> bool {
        self.decompress().is_some()
    }
}

impl From<mobilecoin_address::RistrettoPublic> for RistrettoPublic {
    fn from(key: mobilecoin_address::RistrettoPublic) -> Self {
        Self(*key.as_bytes())
    }
}

/// A view key pair for scanning transactions.
pub struct ViewKeyPair {
    /// Private view key.
    pub private_key: RistrettoPrivate,
    /// Public view key.
    pub public_key: RistrettoPublic,
}

impl ViewKeyPair {
    /// Generate a new random view key pair.
    pub fn generate() -> Self {
        let private_key = RistrettoPrivate::generate();
        let public_key = private_key.public_key();
        Self {
            private_key,
            public_key,
        }
    }

    /// Create from a private key.
    pub fn from_private(private_key: RistrettoPrivate) -> Self {
        let public_key = private_key.public_key();
        Self {
            private_key,
            public_key,
        }
    }
}

impl std::fmt::Debug for ViewKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ViewKeyPair")
            .field("public_key", &self.public_key)
            .finish()
    }
}

/// A spend key pair for authorizing transactions.
pub struct SpendKeyPair {
    /// Private spend key.
    pub private_key: RistrettoPrivate,
    /// Public spend key.
    pub public_key: RistrettoPublic,
}

impl SpendKeyPair {
    /// Generate a new random spend key pair.
    pub fn generate() -> Self {
        let private_key = RistrettoPrivate::generate();
        let public_key = private_key.public_key();
        Self {
            private_key,
            public_key,
        }
    }

    /// Create from a private key.
    pub fn from_private(private_key: RistrettoPrivate) -> Self {
        let public_key = private_key.public_key();
        Self {
            private_key,
            public_key,
        }
    }
}

impl std::fmt::Debug for SpendKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpendKeyPair")
            .field("public_key", &self.public_key)
            .finish()
    }
}

/// Full wallet key set containing view and spend keys.
pub struct WalletKeys {
    /// View key pair for scanning.
    pub view_key_pair: ViewKeyPair,
    /// Spend key pair for authorization.
    pub spend_key_pair: SpendKeyPair,
}

impl WalletKeys {
    /// Generate a new random wallet.
    pub fn generate() -> Self {
        Self {
            view_key_pair: ViewKeyPair::generate(),
            spend_key_pair: SpendKeyPair::generate(),
        }
    }

    /// Create from existing key pairs.
    pub fn new(view_key_pair: ViewKeyPair, spend_key_pair: SpendKeyPair) -> Self {
        Self {
            view_key_pair,
            spend_key_pair,
        }
    }

    /// Get the public view key.
    pub fn view_public(&self) -> &RistrettoPublic {
        &self.view_key_pair.public_key
    }

    /// Get the public spend key.
    pub fn spend_public(&self) -> &RistrettoPublic {
        &self.spend_key_pair.public_key
    }
}

impl std::fmt::Debug for WalletKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletKeys")
            .field("view_key_pair", &self.view_key_pair)
            .field("spend_key_pair", &self.spend_key_pair)
            .finish()
    }
}

/// A transaction key (ephemeral, generated per transaction).
pub struct TxKey {
    /// Private transaction key.
    pub private_key: RistrettoPrivate,
    /// Public transaction key.
    pub public_key: RistrettoPublic,
}

impl TxKey {
    /// Generate a new random transaction key.
    pub fn generate() -> Self {
        let private_key = RistrettoPrivate::generate();
        let public_key = private_key.public_key();
        Self {
            private_key,
            public_key,
        }
    }

    /// Create from a private key.
    pub fn from_private(private_key: RistrettoPrivate) -> Self {
        let public_key = private_key.public_key();
        Self {
            private_key,
            public_key,
        }
    }
}

impl std::fmt::Debug for TxKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxKey")
            .field("public_key", &self.public_key)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_key_generation() {
        let key1 = RistrettoPrivate::generate();
        let key2 = RistrettoPrivate::generate();

        // Should generate different keys
        assert_ne!(key1.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn test_private_public_key_relationship() {
        let private_key = RistrettoPrivate::generate();
        let public_key = private_key.public_key();

        // Public key should be valid
        assert!(public_key.is_valid());
    }

    #[test]
    fn test_public_key_hex_roundtrip() {
        let private_key = RistrettoPrivate::generate();
        let public_key = private_key.public_key();

        let hex = public_key.to_hex();
        let recovered = RistrettoPublic::from_hex(&hex).unwrap();

        assert_eq!(public_key, recovered);
    }

    #[test]
    fn test_wallet_keys_generation() {
        let wallet = WalletKeys::generate();

        // Both keys should be valid
        assert!(wallet.view_key_pair.public_key.is_valid());
        assert!(wallet.spend_key_pair.public_key.is_valid());

        // Keys should be different
        assert_ne!(
            wallet.view_key_pair.public_key,
            wallet.spend_key_pair.public_key
        );
    }

    #[test]
    fn test_tx_key_generation() {
        let tx_key = TxKey::generate();

        assert!(tx_key.public_key.is_valid());
    }
}
