//! MobileCoin Address Validation Module
//!
//! This crate provides address parsing, validation, and serialization
//! for MobileCoin addresses used in NEAR Intents.
//!
//! # Overview
//!
//! MobileCoin uses a dual-key system derived from CryptoNote:
//! - **View Key**: Used to scan the blockchain for incoming transactions
//! - **Spend Key**: Used to authorize spending of funds
//!
//! A MobileCoin address is composed of:
//! - Public View Key (32 bytes)
//! - Public Spend Key (32 bytes)
//! - Optional Fog metadata
//!
//! # Address Format
//!
//! Addresses are encoded using Base58Check with the following structure:
//! ```text
//! [version_byte][view_public_key][spend_public_key][fog_data][checksum]
//! ```
//!
//! # Example
//!
//! ```rust
//! use mobilecoin_address::{parse_mob_address, validate_mob_address, MobNetwork};
//!
//! let address = "..."; // Base58Check encoded MobileCoin address
//!
//! // Validate address format
//! if let Ok(result) = validate_mob_address(address) {
//!     println!("Address is valid: {:?}", result);
//! }
//!
//! // Parse address to extract public keys
//! if let Ok(parsed) = parse_mob_address(address) {
//!     println!("View key: {:?}", parsed.view_public_key);
//!     println!("Spend key: {:?}", parsed.spend_public_key);
//! }
//! ```

mod types;
mod parsing;
mod validation;
mod serialization;
mod error;

pub use types::{MobAddress, FogInfo, MobNetwork, RistrettoPublic};
pub use parsing::{parse_mob_address, parse_mob_address_for_network};
pub use validation::{
    validate_mob_address, validate_network, validate_public_key, ValidationResult,
};
pub use serialization::{
    serialize_mob_address, address_to_bytes, address_from_bytes,
    mob_address_to_near_string, near_string_to_mob_address,
};
pub use error::AddressError;

/// Version byte for mainnet addresses.
pub const MAINNET_VERSION: u8 = 0x00;

/// Version byte for testnet addresses.
pub const TESTNET_VERSION: u8 = 0x01;

#[cfg(test)]
mod tests;
