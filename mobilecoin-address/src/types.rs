//! Core types for MobileCoin addresses.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use serde::{Deserialize, Serialize};

/// A compressed Ristretto point (32 bytes).
///
/// This is used for public keys in MobileCoin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RistrettoPublic(pub [u8; 32]);

impl RistrettoPublic {
    /// Create from raw bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
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
    pub fn from_hex(hex_str: &str) -> Result<Self, crate::AddressError> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| crate::AddressError::InvalidBase58(e.to_string()))?;

        if bytes.len() != 32 {
            return Err(crate::AddressError::InvalidLength {
                expected: 32,
                actual: bytes.len(),
            });
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Check if this point is valid (on the curve).
    pub fn is_valid(&self) -> bool {
        CompressedRistretto::from_slice(&self.0)
            .map(|compressed| compressed.decompress().is_some())
            .unwrap_or(false)
    }

    /// Decompress to a full Ristretto point.
    pub fn decompress(&self) -> Option<RistrettoPoint> {
        CompressedRistretto::from_slice(&self.0)
            .ok()
            .and_then(|compressed| compressed.decompress())
    }
}

impl From<RistrettoPoint> for RistrettoPublic {
    fn from(point: RistrettoPoint) -> Self {
        Self(point.compress().to_bytes())
    }
}

impl TryFrom<&[u8]> for RistrettoPublic {
    type Error = crate::AddressError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 32 {
            return Err(crate::AddressError::InvalidLength {
                expected: 32,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }
}

/// Network type for MobileCoin addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MobNetwork {
    /// MobileCoin mainnet.
    Mainnet,
    /// MobileCoin testnet.
    Testnet,
}

impl MobNetwork {
    /// Get the version byte for this network.
    pub fn version_byte(&self) -> u8 {
        match self {
            MobNetwork::Mainnet => crate::MAINNET_VERSION,
            MobNetwork::Testnet => crate::TESTNET_VERSION,
        }
    }

    /// Create from version byte.
    pub fn from_version_byte(byte: u8) -> Option<Self> {
        match byte {
            crate::MAINNET_VERSION => Some(MobNetwork::Mainnet),
            crate::TESTNET_VERSION => Some(MobNetwork::Testnet),
            _ => None,
        }
    }
}

/// Fog service metadata for MobileCoin addresses.
///
/// Fog is MobileCoin's optional privacy-preserving transaction
/// scanning service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FogInfo {
    /// URL of the Fog report server.
    pub fog_report_url: String,
    /// Report ID for Fog attestation.
    pub fog_report_id: String,
    /// Subject Public Key Info for Fog authority.
    pub fog_authority_spki: Vec<u8>,
}

impl FogInfo {
    /// Create new Fog info.
    pub fn new(
        fog_report_url: String,
        fog_report_id: String,
        fog_authority_spki: Vec<u8>,
    ) -> Self {
        Self {
            fog_report_url,
            fog_report_id,
            fog_authority_spki,
        }
    }

    /// Check if the Fog URL is valid.
    pub fn is_valid_url(&self) -> bool {
        !self.fog_report_url.is_empty()
            && (self.fog_report_url.starts_with("https://")
                || self.fog_report_url.starts_with("http://"))
    }
}

/// A MobileCoin address containing view and spend public keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MobAddress {
    /// Public view key for scanning transactions.
    pub view_public_key: RistrettoPublic,
    /// Public spend key for identifying the recipient.
    pub spend_public_key: RistrettoPublic,
    /// Optional Fog service metadata.
    pub fog_info: Option<FogInfo>,
    /// Network this address belongs to.
    pub network: MobNetwork,
}

impl MobAddress {
    /// Create a new MobileCoin address.
    pub fn new(
        view_public_key: RistrettoPublic,
        spend_public_key: RistrettoPublic,
        network: MobNetwork,
    ) -> Self {
        Self {
            view_public_key,
            spend_public_key,
            fog_info: None,
            network,
        }
    }

    /// Create a new MobileCoin address with Fog info.
    pub fn with_fog(
        view_public_key: RistrettoPublic,
        spend_public_key: RistrettoPublic,
        fog_info: FogInfo,
        network: MobNetwork,
    ) -> Self {
        Self {
            view_public_key,
            spend_public_key,
            fog_info: Some(fog_info),
            network,
        }
    }

    /// Check if this address has Fog enabled.
    pub fn has_fog(&self) -> bool {
        self.fog_info.is_some()
    }

    /// Check if the public keys are valid (on the curve).
    pub fn has_valid_keys(&self) -> bool {
        self.view_public_key.is_valid() && self.spend_public_key.is_valid()
    }

    /// Get the network this address belongs to.
    pub fn network(&self) -> MobNetwork {
        self.network
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ristretto_public_hex_roundtrip() {
        let bytes = [1u8; 32];
        let public = RistrettoPublic::new(bytes);
        let hex = public.to_hex();
        let recovered = RistrettoPublic::from_hex(&hex).unwrap();

        assert_eq!(public, recovered);
    }

    #[test]
    fn test_network_version_bytes() {
        assert_eq!(MobNetwork::Mainnet.version_byte(), 0x00);
        assert_eq!(MobNetwork::Testnet.version_byte(), 0x01);

        assert_eq!(MobNetwork::from_version_byte(0x00), Some(MobNetwork::Mainnet));
        assert_eq!(MobNetwork::from_version_byte(0x01), Some(MobNetwork::Testnet));
        assert_eq!(MobNetwork::from_version_byte(0x02), None);
    }

    #[test]
    fn test_fog_info_url_validation() {
        let valid_fog = FogInfo::new(
            "https://fog.example.com".to_string(),
            "report-1".to_string(),
            vec![1, 2, 3],
        );
        assert!(valid_fog.is_valid_url());

        let invalid_fog = FogInfo::new(
            "fog.example.com".to_string(),
            "report-1".to_string(),
            vec![1, 2, 3],
        );
        assert!(!invalid_fog.is_valid_url());
    }

    #[test]
    fn test_mob_address_creation() {
        let view_key = RistrettoPublic::new([1u8; 32]);
        let spend_key = RistrettoPublic::new([2u8; 32]);

        let address = MobAddress::new(view_key, spend_key, MobNetwork::Mainnet);

        assert_eq!(address.network(), MobNetwork::Mainnet);
        assert!(!address.has_fog());
    }

    #[test]
    fn test_mob_address_with_fog() {
        let view_key = RistrettoPublic::new([1u8; 32]);
        let spend_key = RistrettoPublic::new([2u8; 32]);
        let fog_info = FogInfo::new(
            "https://fog.mobilecoin.com".to_string(),
            "report-123".to_string(),
            vec![4, 5, 6],
        );

        let address = MobAddress::with_fog(view_key, spend_key, fog_info, MobNetwork::Mainnet);

        assert!(address.has_fog());
    }
}
