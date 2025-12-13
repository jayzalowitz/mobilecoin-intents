//! Integration tests for the mobilecoin-address crate.

use crate::*;
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

#[test]
fn test_full_address_workflow() {
    // Create an address with valid keys
    let view_key = generate_valid_key();
    let spend_key = generate_valid_key();
    let address = MobAddress::new(view_key, spend_key, MobNetwork::Mainnet);

    // Serialize to Base58
    let encoded = serialize_mob_address(&address);
    println!("Encoded address: {}", encoded);

    // Validate
    let validation = validate_mob_address(&encoded).unwrap();
    assert_eq!(validation.network, Some(MobNetwork::Mainnet));
    assert!(!validation.has_fog);

    // Parse back
    let parsed = parse_mob_address(&encoded).unwrap();
    assert_eq!(parsed.view_public_key, view_key);
    assert_eq!(parsed.spend_public_key, spend_key);
    assert_eq!(parsed.network, MobNetwork::Mainnet);
}

#[test]
fn test_fog_enabled_address() {
    let view_key = generate_valid_key();
    let spend_key = generate_valid_key();
    let fog_info = FogInfo::new(
        "https://fog.mobilecoin.com".to_string(),
        "report-001".to_string(),
        vec![0x01, 0x02, 0x03, 0x04],
    );

    let address = MobAddress::with_fog(view_key, spend_key, fog_info.clone(), MobNetwork::Mainnet);

    // Serialize and deserialize
    let encoded = serialize_mob_address(&address);
    let parsed = parse_mob_address(&encoded).unwrap();

    assert!(parsed.has_fog());
    let parsed_fog = parsed.fog_info.unwrap();
    assert_eq!(parsed_fog.fog_report_url, fog_info.fog_report_url);
    assert_eq!(parsed_fog.fog_report_id, fog_info.fog_report_id);
    assert_eq!(parsed_fog.fog_authority_spki, fog_info.fog_authority_spki);
}

#[test]
fn test_network_validation() {
    // Create mainnet address
    let view_key = RistrettoPublic::new([1u8; 32]);
    let spend_key = RistrettoPublic::new([2u8; 32]);
    let mainnet_addr = MobAddress::new(view_key, spend_key, MobNetwork::Mainnet);
    let encoded = serialize_mob_address(&mainnet_addr);

    // Should parse successfully for mainnet
    let result = parse_mob_address_for_network(&encoded, MobNetwork::Mainnet);
    assert!(result.is_ok());

    // Should fail for testnet
    let result = parse_mob_address_for_network(&encoded, MobNetwork::Testnet);
    assert!(matches!(result, Err(AddressError::NetworkMismatch { .. })));
}

#[test]
fn test_near_string_format() {
    let view_key = RistrettoPublic::new([0x11; 32]);
    let spend_key = RistrettoPublic::new([0x22; 32]);
    let address = MobAddress::new(view_key, spend_key, MobNetwork::Mainnet);

    let near_str = mob_address_to_near_string(&address);

    // Verify format
    assert!(near_str.starts_with("mob:mainnet:"));
    let parts: Vec<&str> = near_str.split(':').collect();
    assert_eq!(parts.len(), 4);
    assert_eq!(parts[0], "mob");
    assert_eq!(parts[1], "mainnet");
    assert_eq!(parts[2].len(), 64); // 32 bytes = 64 hex chars
    assert_eq!(parts[3].len(), 64);

    // Round-trip
    let recovered = near_string_to_mob_address(&near_str).unwrap();
    assert_eq!(recovered.view_public_key, address.view_public_key);
    assert_eq!(recovered.spend_public_key, address.spend_public_key);
}

#[test]
fn test_address_comparison() {
    let view1 = RistrettoPublic::new([1u8; 32]);
    let spend1 = RistrettoPublic::new([2u8; 32]);
    let addr1 = MobAddress::new(view1, spend1, MobNetwork::Mainnet);

    let view2 = RistrettoPublic::new([1u8; 32]);
    let spend2 = RistrettoPublic::new([2u8; 32]);
    let addr2 = MobAddress::new(view2, spend2, MobNetwork::Mainnet);

    // Same keys should be equal
    assert_eq!(addr1.view_public_key, addr2.view_public_key);
    assert_eq!(addr1.spend_public_key, addr2.spend_public_key);

    // Different keys should not be equal
    let view3 = RistrettoPublic::new([3u8; 32]);
    let addr3 = MobAddress::new(view3, spend1, MobNetwork::Mainnet);
    assert_ne!(addr1.view_public_key, addr3.view_public_key);
}

#[test]
fn test_bytes_serialization() {
    let view_key = RistrettoPublic::new([0xAB; 32]);
    let spend_key = RistrettoPublic::new([0xCD; 32]);
    let address = MobAddress::new(view_key, spend_key, MobNetwork::Mainnet);

    let bytes = address_to_bytes(&address);

    // Verify structure
    assert!(bytes.len() >= 69); // version + keys + checksum

    // First byte should be version
    assert_eq!(bytes[0], MobNetwork::Mainnet.version_byte());

    // Deserialize
    let recovered = address_from_bytes(&bytes).unwrap();
    assert_eq!(recovered.view_public_key, address.view_public_key);
    assert_eq!(recovered.spend_public_key, address.spend_public_key);
}

#[test]
fn test_error_cases() {
    // Empty string
    let result = parse_mob_address("");
    assert!(result.is_err());

    // Invalid Base58
    let result = parse_mob_address("O0l1"); // Contains invalid Base58 chars
    assert!(result.is_err());

    // Too short
    let short = bs58::encode(&[0u8; 10]).into_string();
    let result = parse_mob_address(&short);
    assert!(matches!(result, Err(AddressError::InvalidLength { .. })));
}

#[test]
fn test_validation_result_details() {
    let view_key = generate_valid_key();
    let spend_key = generate_valid_key();
    let address = MobAddress::new(view_key, spend_key, MobNetwork::Testnet);
    let encoded = serialize_mob_address(&address);

    let result = validate_mob_address(&encoded).unwrap();

    // Should detect testnet
    assert_eq!(result.network, Some(MobNetwork::Testnet));
    assert!(!result.has_fog);
}

#[test]
fn test_testnet_vs_mainnet() {
    let view_key = RistrettoPublic::new([0x55; 32]);
    let spend_key = RistrettoPublic::new([0x66; 32]);

    let mainnet = MobAddress::new(view_key, spend_key, MobNetwork::Mainnet);
    let testnet = MobAddress::new(view_key, spend_key, MobNetwork::Testnet);

    let mainnet_encoded = serialize_mob_address(&mainnet);
    let testnet_encoded = serialize_mob_address(&testnet);

    // Should produce different encodings
    assert_ne!(mainnet_encoded, testnet_encoded);

    // Should parse to different networks
    let mainnet_parsed = parse_mob_address(&mainnet_encoded).unwrap();
    let testnet_parsed = parse_mob_address(&testnet_encoded).unwrap();

    assert_eq!(mainnet_parsed.network, MobNetwork::Mainnet);
    assert_eq!(testnet_parsed.network, MobNetwork::Testnet);
}
