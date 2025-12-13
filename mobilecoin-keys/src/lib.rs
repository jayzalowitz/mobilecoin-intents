//! One-Time Key Derivation for MobileCoin
//!
//! This crate implements the stealth address (one-time key) system used by
//! MobileCoin for privacy-preserving transactions.
//!
//! # Overview
//!
//! MobileCoin uses a dual-key system derived from CryptoNote:
//! - **View Key**: Used to scan the blockchain for incoming transactions
//! - **Spend Key**: Used to authorize spending of funds
//!
//! For each transaction output, a unique one-time address is derived:
//! ```text
//! P = Hs(r*A, index)*G + B
//! ```
//! Where:
//! - `r` = random transaction private key
//! - `A` = recipient's public view key
//! - `B` = recipient's public spend key
//! - `G` = generator point
//! - `Hs` = hash-to-scalar function
//!
//! # Example
//!
//! ```rust
//! use mobilecoin_keys::{WalletKeys, generate_tx_key, derive_one_time_public_key};
//!
//! // Generate wallet keys
//! let wallet = WalletKeys::generate();
//!
//! // Sender generates transaction key
//! let tx_key = generate_tx_key();
//!
//! // Derive one-time public key for transaction output
//! let one_time_key = derive_one_time_public_key(
//!     &wallet.view_key_pair.public_key,
//!     &wallet.spend_key_pair.public_key,
//!     &tx_key.private_key,
//!     0, // output index
//! );
//! ```

mod types;
mod derivation;
mod ownership;
mod shared_secret;
mod near_intents;
mod error;

pub use types::{
    ViewKeyPair, SpendKeyPair, WalletKeys, TxKey,
    RistrettoPrivate, RistrettoPublic,
};
pub use derivation::{
    derive_one_time_public_key, derive_one_time_private_key,
    generate_tx_key, derive_key_image,
};
pub use ownership::{
    check_output_ownership, scan_outputs_for_ownership, OwnedOutput,
};
pub use shared_secret::{compute_shared_secret, hash_to_scalar};
pub use near_intents::{
    generate_settlement_address, verify_settlement_address,
    generate_refund_address,
};
pub use error::KeyError;

#[cfg(test)]
mod tests;
