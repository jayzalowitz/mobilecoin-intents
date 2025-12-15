//! Address parsing from strings.

use crate::{AddressError, FogInfo, MobAddress, MobNetwork, RistrettoPublic};
use sha2::{Digest, Sha256};

/// Minimum address length (version + 2 keys + checksum).
const MIN_ADDRESS_LEN: usize = 1 + 32 + 32 + 4; // 69 bytes

/// Parse a MobileCoin address from a Base58Check encoded string.
///
/// # Arguments
/// * `address_str` - The Base58Check encoded address string
///
/// # Returns
/// * `Ok(MobAddress)` - Successfully parsed address
/// * `Err(AddressError)` - Parsing failed
///
/// # Example
/// ```rust
/// use mobilecoin_address::parse_mob_address;
///
/// let address = "..."; // Base58Check encoded address
/// let parsed = parse_mob_address(address);
/// ```
pub fn parse_mob_address(address_str: &str) -> Result<MobAddress, AddressError> {
    // Decode Base58
    let bytes = bs58::decode(address_str)
        .into_vec()
        .map_err(|e| AddressError::InvalidBase58(e.to_string()))?;

    // Check minimum length
    if bytes.len() < MIN_ADDRESS_LEN {
        return Err(AddressError::InvalidLength {
            expected: MIN_ADDRESS_LEN,
            actual: bytes.len(),
        });
    }

    // Extract and verify checksum
    let checksum_start = bytes.len() - 4;
    let payload = &bytes[..checksum_start];
    let provided_checksum = &bytes[checksum_start..];

    let computed_checksum = compute_checksum(payload);
    if provided_checksum != computed_checksum {
        return Err(AddressError::InvalidChecksum);
    }

    // Parse version byte
    let version = payload[0];
    let network =
        MobNetwork::from_version_byte(version).ok_or(AddressError::InvalidVersion(version))?;

    // Parse public keys
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

    // Parse optional Fog info
    let fog_info = if payload.len() > 65 {
        parse_fog_info(&payload[65..])?
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

/// Parse a MobileCoin address with network validation.
///
/// # Arguments
/// * `address_str` - The Base58Check encoded address string
/// * `expected_network` - The expected network (mainnet/testnet)
///
/// # Returns
/// * `Ok(MobAddress)` - Successfully parsed address on expected network
/// * `Err(AddressError)` - Parsing failed or network mismatch
pub fn parse_mob_address_for_network(
    address_str: &str,
    expected_network: MobNetwork,
) -> Result<MobAddress, AddressError> {
    let address = parse_mob_address(address_str)?;

    if address.network != expected_network {
        return Err(AddressError::NetworkMismatch {
            expected: expected_network,
            actual: address.network,
        });
    }

    Ok(address)
}

/// Parse Fog info from remaining bytes.
fn parse_fog_info(bytes: &[u8]) -> Result<Option<FogInfo>, AddressError> {
    if bytes.is_empty() {
        return Ok(None);
    }

    // Fog info format:
    // [url_len:2][url][report_id_len:2][report_id][spki_len:2][spki]

    if bytes.len() < 2 {
        return Err(AddressError::InvalidFogInfo("Too short".to_string()));
    }

    let mut offset = 0;

    // Parse URL
    let url_len = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]) as usize;
    offset += 2;

    if offset + url_len > bytes.len() {
        return Err(AddressError::InvalidFogInfo(
            "URL length overflow".to_string(),
        ));
    }

    let fog_report_url = String::from_utf8(bytes[offset..offset + url_len].to_vec())
        .map_err(|e| AddressError::InvalidFogInfo(e.to_string()))?;
    offset += url_len;

    // Parse Report ID
    if offset + 2 > bytes.len() {
        return Err(AddressError::InvalidFogInfo(
            "Missing report ID length".to_string(),
        ));
    }

    let report_id_len = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]) as usize;
    offset += 2;

    if offset + report_id_len > bytes.len() {
        return Err(AddressError::InvalidFogInfo(
            "Report ID length overflow".to_string(),
        ));
    }

    let fog_report_id = String::from_utf8(bytes[offset..offset + report_id_len].to_vec())
        .map_err(|e| AddressError::InvalidFogInfo(e.to_string()))?;
    offset += report_id_len;

    // Parse SPKI
    if offset + 2 > bytes.len() {
        return Err(AddressError::InvalidFogInfo(
            "Missing SPKI length".to_string(),
        ));
    }

    let spki_len = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]) as usize;
    offset += 2;

    if offset + spki_len > bytes.len() {
        return Err(AddressError::InvalidFogInfo(
            "SPKI length overflow".to_string(),
        ));
    }

    let fog_authority_spki = bytes[offset..offset + spki_len].to_vec();

    Ok(Some(FogInfo {
        fog_report_url,
        fog_report_id,
        fog_authority_spki,
    }))
}

/// Compute double SHA-256 checksum (first 4 bytes).
fn compute_checksum(payload: &[u8]) -> [u8; 4] {
    let hash1 = Sha256::digest(payload);
    let hash2 = Sha256::digest(hash1);
    let mut checksum = [0u8; 4];
    checksum.copy_from_slice(&hash2[..4]);
    checksum
}

/// Extract public keys from an address.
#[allow(dead_code)]
pub fn extract_public_keys(address: &MobAddress) -> (RistrettoPublic, RistrettoPublic) {
    (address.view_public_key, address.spend_public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serialization::serialize_mob_address;

    #[test]
    fn test_parse_roundtrip() {
        // Create a test address
        let view_key = RistrettoPublic::new([1u8; 32]);
        let spend_key = RistrettoPublic::new([2u8; 32]);
        let address = MobAddress::new(view_key, spend_key, MobNetwork::Mainnet);

        // Serialize
        let encoded = serialize_mob_address(&address);

        // Parse back
        let parsed = parse_mob_address(&encoded).unwrap();

        assert_eq!(address.view_public_key, parsed.view_public_key);
        assert_eq!(address.spend_public_key, parsed.spend_public_key);
        assert_eq!(address.network, parsed.network);
    }

    #[test]
    fn test_parse_invalid_base58() {
        let result = parse_mob_address("not_valid_base58!!!");
        assert!(matches!(result, Err(AddressError::InvalidBase58(_))));
    }

    #[test]
    fn test_parse_too_short() {
        // Base58 encode something too short
        let short = bs58::encode(&[0u8; 10]).into_string();
        let result = parse_mob_address(&short);
        assert!(matches!(result, Err(AddressError::InvalidLength { .. })));
    }

    #[test]
    fn test_parse_invalid_checksum() {
        // Create valid address bytes but corrupt checksum
        let view_key = [1u8; 32];
        let spend_key = [2u8; 32];
        let mut bytes = Vec::new();
        bytes.push(0x00); // mainnet
        bytes.extend_from_slice(&view_key);
        bytes.extend_from_slice(&spend_key);
        bytes.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]); // bad checksum

        let encoded = bs58::encode(&bytes).into_string();
        let result = parse_mob_address(&encoded);
        assert!(matches!(result, Err(AddressError::InvalidChecksum)));
    }

    #[test]
    fn test_parse_invalid_version() {
        // Create address with invalid version
        let view_key = [1u8; 32];
        let spend_key = [2u8; 32];
        let mut bytes = Vec::new();
        bytes.push(0xFF); // invalid version
        bytes.extend_from_slice(&view_key);
        bytes.extend_from_slice(&spend_key);

        let checksum = compute_checksum(&bytes);
        bytes.extend_from_slice(&checksum);

        let encoded = bs58::encode(&bytes).into_string();
        let result = parse_mob_address(&encoded);
        assert!(matches!(result, Err(AddressError::InvalidVersion(0xFF))));
    }

    #[test]
    fn test_parse_for_network() {
        let view_key = RistrettoPublic::new([1u8; 32]);
        let spend_key = RistrettoPublic::new([2u8; 32]);
        let address = MobAddress::new(view_key, spend_key, MobNetwork::Mainnet);
        let encoded = serialize_mob_address(&address);

        // Should succeed for correct network
        let result = parse_mob_address_for_network(&encoded, MobNetwork::Mainnet);
        assert!(result.is_ok());

        // Should fail for wrong network
        let result = parse_mob_address_for_network(&encoded, MobNetwork::Testnet);
        assert!(matches!(result, Err(AddressError::NetworkMismatch { .. })));
    }

    #[test]
    fn test_extract_public_keys() {
        let view_key = RistrettoPublic::new([1u8; 32]);
        let spend_key = RistrettoPublic::new([2u8; 32]);
        let address = MobAddress::new(view_key, spend_key, MobNetwork::Mainnet);

        let (extracted_view, extracted_spend) = extract_public_keys(&address);

        assert_eq!(extracted_view, view_key);
        assert_eq!(extracted_spend, spend_key);
    }
}
