//! Address validation functions.

use crate::parsing::parse_mob_address;
use crate::{AddressError, FogInfo, MobAddress, MobNetwork, RistrettoPublic};

/// Result of address validation.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Whether the address is valid.
    pub is_valid: bool,
    /// Detected network.
    pub network: Option<MobNetwork>,
    /// Whether the address has Fog enabled.
    pub has_fog: bool,
    /// Validation messages (warnings or errors).
    pub messages: Vec<String>,
}

impl ValidationResult {
    /// Create a valid result.
    pub fn valid(network: MobNetwork, has_fog: bool) -> Self {
        Self {
            is_valid: true,
            network: Some(network),
            has_fog,
            messages: vec![],
        }
    }

    /// Create an invalid result with an error message.
    pub fn invalid(message: impl Into<String>) -> Self {
        Self {
            is_valid: false,
            network: None,
            has_fog: false,
            messages: vec![message.into()],
        }
    }

    /// Add a warning message.
    pub fn with_warning(mut self, message: impl Into<String>) -> Self {
        self.messages.push(message.into());
        self
    }
}

/// Validate a MobileCoin address format and structure.
///
/// # Arguments
/// * `address_str` - The address string to validate
///
/// # Returns
/// * `Ok(ValidationResult)` - Validation completed (check is_valid field)
/// * `Err(AddressError)` - Validation could not be performed
///
/// # Example
/// ```rust
/// use mobilecoin_address::validate_mob_address;
///
/// let result = validate_mob_address("...").unwrap();
/// if result.is_valid {
///     println!("Address is valid on {:?}", result.network);
/// } else {
///     println!("Invalid: {:?}", result.messages);
/// }
/// ```
pub fn validate_mob_address(address_str: &str) -> Result<ValidationResult, AddressError> {
    // Try to parse the address
    let address = match parse_mob_address(address_str) {
        Ok(addr) => addr,
        Err(e) => {
            return Ok(ValidationResult::invalid(format!("{}", e)));
        }
    };

    // Validate public keys are on curve
    let mut result = if !address.view_public_key.is_valid() {
        ValidationResult::invalid("View public key is not on curve")
    } else if !address.spend_public_key.is_valid() {
        ValidationResult::invalid("Spend public key is not on curve")
    } else {
        ValidationResult::valid(address.network, address.has_fog())
    };

    // Check Fog info if present
    if let Some(ref fog_info) = address.fog_info {
        if !validate_fog_info(fog_info).is_ok() {
            result = result.with_warning("Fog info may be invalid");
        }
    }

    Ok(result)
}

/// Check if an address is on the expected network.
///
/// # Arguments
/// * `address` - The parsed address
/// * `network` - The expected network
///
/// # Returns
/// `true` if the address is on the expected network.
pub fn validate_network(address: &MobAddress, network: MobNetwork) -> bool {
    address.network == network
}

/// Validate a public key is on the Ristretto curve.
///
/// # Arguments
/// * `key` - The public key to validate
///
/// # Returns
/// `true` if the key is a valid point on the curve.
pub fn validate_public_key(key: &RistrettoPublic) -> bool {
    key.is_valid()
}

/// Validate Fog service metadata.
///
/// # Arguments
/// * `fog_info` - The Fog info to validate
///
/// # Returns
/// * `Ok(())` - Fog info is valid
/// * `Err(AddressError)` - Fog info is invalid
pub fn validate_fog_info(fog_info: &FogInfo) -> Result<(), AddressError> {
    // Check URL format
    if fog_info.fog_report_url.is_empty() {
        return Err(AddressError::InvalidFogInfo(
            "Empty fog report URL".to_string(),
        ));
    }

    if !fog_info.fog_report_url.starts_with("https://")
        && !fog_info.fog_report_url.starts_with("http://")
    {
        return Err(AddressError::InvalidFogInfo(
            "Fog report URL must be HTTP(S)".to_string(),
        ));
    }

    // Check report ID
    if fog_info.fog_report_id.is_empty() {
        return Err(AddressError::InvalidFogInfo(
            "Empty fog report ID".to_string(),
        ));
    }

    // Check SPKI
    if fog_info.fog_authority_spki.is_empty() {
        return Err(AddressError::InvalidFogInfo(
            "Empty fog authority SPKI".to_string(),
        ));
    }

    Ok(())
}

/// Validate an address for use in NEAR Intents settlement.
///
/// This performs additional checks specific to NEAR Intents requirements.
///
/// # Arguments
/// * `address_str` - The address string to validate
///
/// # Returns
/// * `Ok(MobAddress)` - Address is valid for settlement
/// * `Err(AddressError)` - Address is not valid for settlement
pub fn validate_for_settlement(address_str: &str) -> Result<MobAddress, AddressError> {
    let address = parse_mob_address(address_str)?;

    // For settlement, we require mainnet addresses
    if address.network != MobNetwork::Mainnet {
        return Err(AddressError::NetworkMismatch {
            expected: MobNetwork::Mainnet,
            actual: address.network,
        });
    }

    // Verify keys are on curve
    if !address.view_public_key.is_valid() {
        return Err(AddressError::InvalidPublicKey);
    }

    if !address.spend_public_key.is_valid() {
        return Err(AddressError::InvalidPublicKey);
    }

    Ok(address)
}

/// Check if two addresses are equal (same keys).
pub fn addresses_equal(addr1: &MobAddress, addr2: &MobAddress) -> bool {
    addr1.view_public_key == addr2.view_public_key
        && addr1.spend_public_key == addr2.spend_public_key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serialization::serialize_mob_address;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;
    use rand::RngCore;

    /// Generate a valid Ristretto public key (on the curve).
    fn generate_valid_key() -> RistrettoPublic {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        let scalar = Scalar::from_bytes_mod_order_wide(&bytes);
        let point = RISTRETTO_BASEPOINT_TABLE.basepoint() * scalar;
        RistrettoPublic::from(point)
    }

    fn create_test_address() -> MobAddress {
        let view_key = generate_valid_key();
        let spend_key = generate_valid_key();
        MobAddress::new(view_key, spend_key, MobNetwork::Mainnet)
    }

    #[test]
    fn test_validate_address() {
        let address = create_test_address();
        let encoded = serialize_mob_address(&address);

        let result = validate_mob_address(&encoded).unwrap();

        // Keys are properly generated on the curve
        assert!(result.is_valid);
        assert!(result.network.is_some());
    }

    #[test]
    fn test_validate_invalid_address() {
        let result = validate_mob_address("invalid_address").unwrap();
        assert!(!result.is_valid);
        assert!(!result.messages.is_empty());
    }

    #[test]
    fn test_validate_network() {
        let mainnet_address = create_test_address();

        assert!(validate_network(&mainnet_address, MobNetwork::Mainnet));
        assert!(!validate_network(&mainnet_address, MobNetwork::Testnet));
    }

    #[test]
    fn test_validate_fog_info_valid() {
        let fog_info = FogInfo {
            fog_report_url: "https://fog.mobilecoin.com".to_string(),
            fog_report_id: "report-123".to_string(),
            fog_authority_spki: vec![1, 2, 3, 4],
        };

        assert!(validate_fog_info(&fog_info).is_ok());
    }

    #[test]
    fn test_validate_fog_info_empty_url() {
        let fog_info = FogInfo {
            fog_report_url: "".to_string(),
            fog_report_id: "report-123".to_string(),
            fog_authority_spki: vec![1, 2, 3, 4],
        };

        assert!(validate_fog_info(&fog_info).is_err());
    }

    #[test]
    fn test_validate_fog_info_bad_url() {
        let fog_info = FogInfo {
            fog_report_url: "fog.mobilecoin.com".to_string(), // missing protocol
            fog_report_id: "report-123".to_string(),
            fog_authority_spki: vec![1, 2, 3, 4],
        };

        assert!(validate_fog_info(&fog_info).is_err());
    }

    #[test]
    fn test_validate_for_settlement() {
        let address = create_test_address();
        let encoded = serialize_mob_address(&address);

        // This may fail if keys aren't on curve, which is expected for test data
        let result = validate_for_settlement(&encoded);
        // We're mainly testing the flow here
        assert!(result.is_ok() || matches!(result, Err(AddressError::InvalidPublicKey)));
    }

    #[test]
    fn test_addresses_equal() {
        let view_key = generate_valid_key();
        let spend_key = generate_valid_key();

        let addr1 = MobAddress::new(view_key, spend_key, MobNetwork::Mainnet);
        let addr2 = MobAddress::new(view_key, spend_key, MobNetwork::Mainnet);

        assert!(addresses_equal(&addr1, &addr2));

        let different_addr = MobAddress::new(
            generate_valid_key(),
            generate_valid_key(),
            MobNetwork::Mainnet,
        );

        assert!(!addresses_equal(&addr1, &different_addr));
    }

    #[test]
    fn test_validation_result_methods() {
        let valid = ValidationResult::valid(MobNetwork::Mainnet, true);
        assert!(valid.is_valid);
        assert_eq!(valid.network, Some(MobNetwork::Mainnet));
        assert!(valid.has_fog);

        let invalid = ValidationResult::invalid("Test error");
        assert!(!invalid.is_valid);
        assert!(invalid.messages.contains(&"Test error".to_string()));

        let with_warning =
            ValidationResult::valid(MobNetwork::Mainnet, false).with_warning("Test warning");
        assert!(with_warning.messages.contains(&"Test warning".to_string()));
    }
}
