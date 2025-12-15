//! MobileCoin Ed25519 Cryptographic Module
//!
//! This crate provides Ed25519 signature verification and key handling
//! for MobileCoin integration with NEAR Intents.
//!
//! # Overview
//!
//! MobileCoin uses Ed25519 (Edwards-curve Digital Signature Algorithm) for all
//! cryptographic signing operations. This module provides:
//!
//! - Public key and signature types
//! - Signature verification
//! - Message hashing for signing
//! - Payload trait implementations for NEAR Intents
//!
//! # Example
//!
//! ```rust
//! use mobilecoin_crypto::{MobKeyPair, verify_mob_signature};
//!
//! let keypair = MobKeyPair::generate();
//! let message = b"Hello, MobileCoin!";
//! let signature = keypair.sign(message);
//! let public_key = keypair.public_key();
//!
//! match verify_mob_signature(message, &signature, &public_key) {
//!     Ok(true) => println!("Valid signature"),
//!     Ok(false) => println!("Invalid signature"),
//!     Err(e) => println!("Error: {}", e),
//! }
//! ```

mod error;
mod hash;
mod payload;
mod signature;
mod types;

pub use error::CryptoError;
pub use hash::{create_signable_message, hash_message_for_signing};
pub use payload::{MobPayload, Payload, SignedMobPayload, SignedPayload};
#[cfg(feature = "std")]
pub use signature::sign_message;
pub use signature::{verify_mob_signature, verify_mob_signature_with_domain, MOB_INTENT_DOMAIN};
#[cfg(feature = "std")]
pub use types::MobKeyPair;
pub use types::{MobPublicKey, MobSignature, MobSignedPayload};

#[cfg(test)]
mod tests;
