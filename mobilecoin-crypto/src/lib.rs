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

mod types;
mod signature;
mod payload;
mod hash;
mod error;

pub use types::{MobPublicKey, MobSignature, MobSignedPayload, MobKeyPair};
pub use signature::{verify_mob_signature, verify_mob_signature_with_domain, sign_message, MOB_INTENT_DOMAIN};
pub use payload::{MobPayload, Payload, SignedPayload, SignedMobPayload};
pub use hash::{hash_message_for_signing, create_signable_message};
pub use error::CryptoError;

#[cfg(test)]
mod tests;
