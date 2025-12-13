//! Address serialization functions.

use crate::{AddressError, FogInfo, MobAddress, MobNetwork, RistrettoPublic};
use sha2::{Digest, Sha256};

/// Serialize a MobileCoin address to a Base58Check encoded string.
///
/// # Arguments
/// * `address` - The address to serialize
///
/// # Returns
/// A Base58Check encoded string representation of the address.
pub fn serialize_mob_address(address: &MobAddress) -> String {
    let bytes = address_to_bytes(address);
    bs58::encode(&bytes).into_string()
}

/// Serialize an address to raw bytes (including checksum).
///
/// # Format
/// ```text
/// [version:1][view_key:32][spend_key:32][fog_data:var][checksum:4]
/// ```
pub fn address_to_bytes(address: &MobAddress) -> Vec<u8> {
    let mut bytes = Vec::new();

    // Version byte
    bytes.push(address.network.version_byte());

    // View public key
    bytes.extend_from_slice(address.view_public_key.as_bytes());

    // Spend public key
    bytes.extend_from_slice(address.spend_public_key.as_bytes());

    // Fog info (if present)
    if let Some(ref fog_info) = address.fog_info {
        bytes.extend_from_slice(&serialize_fog_info(fog_info));
    }

    // Compute and append checksum
    let checksum = compute_checksum(&bytes);
    bytes.extend_from_slice(&checksum);

    bytes
}

/// Deserialize an address from raw bytes.
///
/// # Arguments
/// * `bytes` - The raw bytes including checksum
///
/// # Returns
/// * `Ok(MobAddress)` - Successfully deserialized address
/// * `Err(AddressError)` - Deserialization failed
pub fn address_from_bytes(bytes: &[u8]) -> Result<MobAddress, AddressError> {
    // Minimum: version + 2 keys + checksum = 1 + 32 + 32 + 4 = 69
    if bytes.len() < 69 {
        return Err(AddressError::InvalidLength {
            expected: 69,
            actual: bytes.len(),
        });
    }

    // Verify checksum
    let checksum_start = bytes.len() - 4;
    let payload = &bytes[..checksum_start];
    let provided_checksum = &bytes[checksum_start..];
    let computed_checksum = compute_checksum(payload);

    if provided_checksum != computed_checksum {
        return Err(AddressError::InvalidChecksum);
    }

    // Parse version
    let version = payload[0];
    let network =
        MobNetwork::from_version_byte(version).ok_or(AddressError::InvalidVersion(version))?;

    // Parse keys
    let view_key_bytes: [u8; 32] =
        payload[1..33]
            .try_into()
            .map_err(|_| AddressError::InvalidLength {
                expected: 32,
                actual: 0,
            })?;

    let spend_key_bytes: [u8; 32] =
        payload[33..65]
            .try_into()
            .map_err(|_| AddressError::InvalidLength {
                expected: 32,
                actual: 0,
            })?;

    let view_public_key = RistrettoPublic::new(view_key_bytes);
    let spend_public_key = RistrettoPublic::new(spend_key_bytes);

    // Parse fog info if present
    let fog_info = if payload.len() > 65 {
        deserialize_fog_info(&payload[65..])?
    } else {
        None
    };

    Ok(MobAddress {
        view_public_key,
        spend_public_key,
        fog_info,
        network,
    })
}

/// Convert a MobileCoin address to a NEAR-compatible string format.
///
/// This creates a deterministic string representation that can be
/// stored and validated on NEAR.
///
/// # Format
/// `mob:<network>:<view_key_hex>:<spend_key_hex>[:<fog_url>]`
pub fn mob_address_to_near_string(address: &MobAddress) -> String {
    let network_str = match address.network {
        MobNetwork::Mainnet => "mainnet",
        MobNetwork::Testnet => "testnet",
    };

    let view_hex = address.view_public_key.to_hex();
    let spend_hex = address.spend_public_key.to_hex();

    let base = format!("mob:{}:{}:{}", network_str, view_hex, spend_hex);

    if let Some(ref fog_info) = address.fog_info {
        format!("{}:{}", base, fog_info.fog_report_url)
    } else {
        base
    }
}

/// Parse a NEAR-formatted address string back to a MobileCoin address.
///
/// # Arguments
/// * `s` - The NEAR-formatted address string
///
/// # Returns
/// * `Ok(MobAddress)` - Successfully parsed address
/// * `Err(AddressError)` - Parsing failed
pub fn near_string_to_mob_address(s: &str) -> Result<MobAddress, AddressError> {
    let parts: Vec<&str> = s.split(':').collect();

    if parts.len() < 4 || parts[0] != "mob" {
        return Err(AddressError::UnrecognizedFormat);
    }

    let network = match parts[1] {
        "mainnet" => MobNetwork::Mainnet,
        "testnet" => MobNetwork::Testnet,
        _ => return Err(AddressError::UnrecognizedFormat),
    };

    let view_public_key = RistrettoPublic::from_hex(parts[2])?;
    let spend_public_key = RistrettoPublic::from_hex(parts[3])?;

    let fog_info = if parts.len() > 4 && !parts[4].is_empty() {
        Some(FogInfo {
            fog_report_url: parts[4].to_string(),
            fog_report_id: String::new(),
            fog_authority_spki: vec![],
        })
    } else {
        None
    };

    Ok(MobAddress {
        view_public_key,
        spend_public_key,
        fog_info,
        network,
    })
}

/// Serialize Fog info to bytes.
fn serialize_fog_info(fog_info: &FogInfo) -> Vec<u8> {
    let mut bytes = Vec::new();

    // URL length + URL
    let url_bytes = fog_info.fog_report_url.as_bytes();
    bytes.extend_from_slice(&(url_bytes.len() as u16).to_le_bytes());
    bytes.extend_from_slice(url_bytes);

    // Report ID length + Report ID
    let report_id_bytes = fog_info.fog_report_id.as_bytes();
    bytes.extend_from_slice(&(report_id_bytes.len() as u16).to_le_bytes());
    bytes.extend_from_slice(report_id_bytes);

    // SPKI length + SPKI
    bytes.extend_from_slice(&(fog_info.fog_authority_spki.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&fog_info.fog_authority_spki);

    bytes
}

/// Deserialize Fog info from bytes.
fn deserialize_fog_info(bytes: &[u8]) -> Result<Option<FogInfo>, AddressError> {
    if bytes.is_empty() {
        return Ok(None);
    }

    if bytes.len() < 2 {
        return Err(AddressError::InvalidFogInfo("Too short".to_string()));
    }

    let mut offset = 0;

    // URL
    let url_len = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]) as usize;
    offset += 2;

    if offset + url_len > bytes.len() {
        return Err(AddressError::InvalidFogInfo("URL overflow".to_string()));
    }

    let fog_report_url = String::from_utf8(bytes[offset..offset + url_len].to_vec())
        .map_err(|e| AddressError::InvalidFogInfo(e.to_string()))?;
    offset += url_len;

    // Report ID
    if offset + 2 > bytes.len() {
        return Err(AddressError::InvalidFogInfo(
            "Missing report ID".to_string(),
        ));
    }

    let report_id_len = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]) as usize;
    offset += 2;

    if offset + report_id_len > bytes.len() {
        return Err(AddressError::InvalidFogInfo(
            "Report ID overflow".to_string(),
        ));
    }

    let fog_report_id = String::from_utf8(bytes[offset..offset + report_id_len].to_vec())
        .map_err(|e| AddressError::InvalidFogInfo(e.to_string()))?;
    offset += report_id_len;

    // SPKI
    if offset + 2 > bytes.len() {
        return Err(AddressError::InvalidFogInfo("Missing SPKI".to_string()));
    }

    let spki_len = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]) as usize;
    offset += 2;

    if offset + spki_len > bytes.len() {
        return Err(AddressError::InvalidFogInfo("SPKI overflow".to_string()));
    }

    let fog_authority_spki = bytes[offset..offset + spki_len].to_vec();

    Ok(Some(FogInfo {
        fog_report_url,
        fog_report_id,
        fog_authority_spki,
    }))
}

/// Compute double SHA-256 checksum.
fn compute_checksum(payload: &[u8]) -> [u8; 4] {
    let hash1 = Sha256::digest(payload);
    let hash2 = Sha256::digest(hash1);
    let mut checksum = [0u8; 4];
    checksum.copy_from_slice(&hash2[..4]);
    checksum
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_address() -> MobAddress {
        let view_key = RistrettoPublic::new([1u8; 32]);
        let spend_key = RistrettoPublic::new([2u8; 32]);
        MobAddress::new(view_key, spend_key, MobNetwork::Mainnet)
    }

    fn create_fog_address() -> MobAddress {
        let view_key = RistrettoPublic::new([3u8; 32]);
        let spend_key = RistrettoPublic::new([4u8; 32]);
        let fog_info = FogInfo {
            fog_report_url: "https://fog.example.com".to_string(),
            fog_report_id: "test-report".to_string(),
            fog_authority_spki: vec![1, 2, 3, 4, 5],
        };
        MobAddress::with_fog(view_key, spend_key, fog_info, MobNetwork::Mainnet)
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let address = create_test_address();
        let bytes = address_to_bytes(&address);
        let recovered = address_from_bytes(&bytes).unwrap();

        assert_eq!(address.view_public_key, recovered.view_public_key);
        assert_eq!(address.spend_public_key, recovered.spend_public_key);
        assert_eq!(address.network, recovered.network);
    }

    #[test]
    fn test_base58_roundtrip() {
        let address = create_test_address();
        let encoded = serialize_mob_address(&address);

        // Should be valid Base58
        assert!(bs58::decode(&encoded).into_vec().is_ok());

        // Should roundtrip via parsing
        let bytes = bs58::decode(&encoded).into_vec().unwrap();
        let recovered = address_from_bytes(&bytes).unwrap();

        assert_eq!(address.view_public_key, recovered.view_public_key);
    }

    #[test]
    fn test_fog_address_serialization() {
        let address = create_fog_address();
        let bytes = address_to_bytes(&address);
        let recovered = address_from_bytes(&bytes).unwrap();

        assert!(recovered.fog_info.is_some());
        let fog = recovered.fog_info.unwrap();
        assert_eq!(fog.fog_report_url, "https://fog.example.com");
        assert_eq!(fog.fog_report_id, "test-report");
        assert_eq!(fog.fog_authority_spki, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_near_string_conversion() {
        let address = create_test_address();
        let near_str = mob_address_to_near_string(&address);

        assert!(near_str.starts_with("mob:mainnet:"));

        let recovered = near_string_to_mob_address(&near_str).unwrap();
        assert_eq!(address.view_public_key, recovered.view_public_key);
        assert_eq!(address.spend_public_key, recovered.spend_public_key);
    }

    #[test]
    fn test_near_string_with_fog() {
        let address = create_fog_address();
        let near_str = mob_address_to_near_string(&address);

        assert!(near_str.contains("https://fog.example.com"));

        let recovered = near_string_to_mob_address(&near_str).unwrap();
        assert!(recovered.fog_info.is_some());
    }

    #[test]
    fn test_invalid_near_string() {
        let result = near_string_to_mob_address("invalid");
        assert!(result.is_err());

        let result = near_string_to_mob_address("eth:mainnet:abc:def");
        assert!(result.is_err());
    }

    #[test]
    fn test_testnet_address() {
        let view_key = RistrettoPublic::new([5u8; 32]);
        let spend_key = RistrettoPublic::new([6u8; 32]);
        let address = MobAddress::new(view_key, spend_key, MobNetwork::Testnet);

        let bytes = address_to_bytes(&address);
        let recovered = address_from_bytes(&bytes).unwrap();

        assert_eq!(recovered.network, MobNetwork::Testnet);

        let near_str = mob_address_to_near_string(&address);
        assert!(near_str.starts_with("mob:testnet:"));
    }

    #[test]
    fn test_checksum_validation() {
        let address = create_test_address();
        let mut bytes = address_to_bytes(&address);

        // Corrupt the checksum
        let len = bytes.len();
        bytes[len - 1] ^= 0xFF;

        let result = address_from_bytes(&bytes);
        assert!(matches!(result, Err(AddressError::InvalidChecksum)));
    }
}
