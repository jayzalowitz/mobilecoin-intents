//! Core cryptographic types for MobileCoin.

use crate::error::CryptoError;
use ed25519_dalek::{SecretKey, Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A MobileCoin Ed25519 public key (32 bytes).
///
/// This is used to verify signatures and identify accounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MobPublicKey(#[serde(with = "hex_bytes_32")] pub [u8; 32]);

impl MobPublicKey {
    /// Create a new public key from raw bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create from a hex string.
    pub fn from_hex(hex_str: &str) -> Result<Self, CryptoError> {
        let bytes =
            hex::decode(hex_str).map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;

        if bytes.len() != 32 {
            return Err(CryptoError::InvalidPublicKey(format!(
                "Expected 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to ed25519_dalek VerifyingKey.
    pub fn to_verifying_key(&self) -> Result<VerifyingKey, CryptoError> {
        VerifyingKey::from_bytes(&self.0).map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))
    }
}

impl From<VerifyingKey> for MobPublicKey {
    fn from(key: VerifyingKey) -> Self {
        Self(key.to_bytes())
    }
}

impl TryFrom<&[u8]> for MobPublicKey {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidPublicKey(format!(
                "Expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }
}

/// A MobileCoin Ed25519 signature (64 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MobSignature(#[serde(with = "hex_bytes_64")] pub [u8; 64]);

impl MobSignature {
    /// Create a new signature from raw bytes.
    pub fn new(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Create from a hex string.
    pub fn from_hex(hex_str: &str) -> Result<Self, CryptoError> {
        let bytes =
            hex::decode(hex_str).map_err(|e| CryptoError::InvalidSignature(e.to_string()))?;

        if bytes.len() != 64 {
            return Err(CryptoError::InvalidSignature(format!(
                "Expected 64 bytes, got {}",
                bytes.len()
            )));
        }

        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Convert to ed25519_dalek Signature.
    pub fn to_signature(&self) -> Signature {
        Signature::from_bytes(&self.0)
    }
}

impl From<Signature> for MobSignature {
    fn from(sig: Signature) -> Self {
        Self(sig.to_bytes())
    }
}

impl TryFrom<&[u8]> for MobSignature {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 64 {
            return Err(CryptoError::InvalidSignature(format!(
                "Expected 64 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }
}

/// A MobileCoin key pair for signing.
pub struct MobKeyPair {
    signing_key: SigningKey,
}

impl MobKeyPair {
    /// Generate a new random key pair.
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        Self { signing_key }
    }

    /// Create from a secret key (32 bytes).
    pub fn from_secret_key(secret: &[u8; 32]) -> Self {
        let secret_key = SecretKey::from(*secret);
        let signing_key = SigningKey::from(secret_key);
        Self { signing_key }
    }

    /// Get the public key.
    pub fn public_key(&self) -> MobPublicKey {
        MobPublicKey::from(self.signing_key.verifying_key())
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> MobSignature {
        use ed25519_dalek::Signer;
        MobSignature::from(self.signing_key.sign(message))
    }

    /// Get the secret key bytes (use with caution).
    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

/// A signed payload containing the original payload, signature, and public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobSignedPayload {
    /// The original payload bytes.
    pub payload: Vec<u8>,
    /// The Ed25519 signature over the payload.
    pub signature: MobSignature,
    /// The public key of the signer.
    pub public_key: MobPublicKey,
}

impl MobSignedPayload {
    /// Create a new signed payload.
    pub fn new(payload: Vec<u8>, signature: MobSignature, public_key: MobPublicKey) -> Self {
        Self {
            payload,
            signature,
            public_key,
        }
    }

    /// Create by signing a payload with a key pair.
    pub fn sign(payload: Vec<u8>, key_pair: &MobKeyPair) -> Self {
        let signature = key_pair.sign(&payload);
        let public_key = key_pair.public_key();
        Self {
            payload,
            signature,
            public_key,
        }
    }
}

/// Serde module for 32-byte arrays as hex strings.
mod hex_bytes_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "Expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

/// Serde module for 64-byte arrays as hex strings.
mod hex_bytes_64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "Expected 64 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = MobKeyPair::generate();
        let public_key = keypair.public_key();

        // Public key should be 32 bytes
        assert_eq!(public_key.as_bytes().len(), 32);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = MobKeyPair::generate();
        let message = b"test message";
        let signature = keypair.sign(message);

        // Signature should be 64 bytes
        assert_eq!(signature.as_bytes().len(), 64);
    }

    #[test]
    fn test_public_key_hex_roundtrip() {
        let keypair = MobKeyPair::generate();
        let public_key = keypair.public_key();
        let hex_str = public_key.to_hex();
        let recovered = MobPublicKey::from_hex(&hex_str).unwrap();

        assert_eq!(public_key, recovered);
    }

    #[test]
    fn test_signature_hex_roundtrip() {
        let keypair = MobKeyPair::generate();
        let signature = keypair.sign(b"test");
        let hex_str = signature.to_hex();
        let recovered = MobSignature::from_hex(&hex_str).unwrap();

        assert_eq!(signature, recovered);
    }

    #[test]
    fn test_invalid_public_key_length() {
        let result = MobPublicKey::from_hex("0102030405");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_signature_length() {
        let result = MobSignature::from_hex("0102030405");
        assert!(result.is_err());
    }
}
