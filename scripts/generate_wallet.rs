//! MobileCoin Wallet Generator
//!
//! Generates all necessary keys for the bridge custody wallet.
//! Run with: cargo run --release --bin generate-wallet
//!
//! WARNING: This generates real cryptographic keys.
//! Store the output securely and NEVER commit to git.

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Sha256, Sha512, Digest};
use std::fs;
use std::path::Path;

fn main() {
    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║   MobileCoin Bridge Wallet Generator                           ║");
    println!("║   Project: Marseille                                           ║");
    println!("╚════════════════════════════════════════════════════════════════╝");
    println!();

    // Generate View keypair
    let view_signing = SigningKey::generate(&mut OsRng);
    let view_verifying = view_signing.verifying_key();

    // Generate Spend keypair
    let spend_signing = SigningKey::generate(&mut OsRng);
    let spend_verifying = spend_signing.verifying_key();

    // Generate 3 Authority keypairs for the bridge
    let mut authorities = Vec::new();
    for i in 1..=3 {
        let auth_signing = SigningKey::generate(&mut OsRng);
        let auth_verifying = auth_signing.verifying_key();
        authorities.push((auth_signing, auth_verifying));
        println!("Generated Authority {} keypair", i);
    }

    // Create public address (simplified - real MOB uses more complex derivation)
    let public_address = create_mob_address(&view_verifying, &spend_verifying);

    println!();
    println!("════════════════════════════════════════════════════════════════");
    println!("  CUSTODY WALLET");
    println!("════════════════════════════════════════════════════════════════");
    println!();
    println!("Public Address (MOB_CUSTODY_ADDRESS):");
    println!("  {}", public_address);
    println!();
    println!("View Public Key:");
    println!("  {}", hex::encode(view_verifying.as_bytes()));
    println!();
    println!("View Private Key (SECRET - for monitoring deposits):");
    println!("  {}", hex::encode(view_signing.to_bytes()));
    println!();
    println!("Spend Public Key:");
    println!("  {}", hex::encode(spend_verifying.as_bytes()));
    println!();
    println!("Spend Private Key (SECRET - for withdrawals):");
    println!("  {}", hex::encode(spend_signing.to_bytes()));
    println!();

    println!("════════════════════════════════════════════════════════════════");
    println!("  BRIDGE AUTHORITIES (for NEAR contract)");
    println!("════════════════════════════════════════════════════════════════");
    println!();

    for (i, (signing, verifying)) in authorities.iter().enumerate() {
        let near_pubkey = format!("ed25519:{}", bs58::encode(verifying.as_bytes()).into_string());
        println!("Authority {}:", i + 1);
        println!("  NEAR Public Key: {}", near_pubkey);
        println!("  Private Key (SECRET): {}", hex::encode(signing.to_bytes()));
        println!();
    }

    println!("════════════════════════════════════════════════════════════════");
    println!("  ENVIRONMENT VARIABLES");
    println!("════════════════════════════════════════════════════════════════");
    println!();
    println!("export MOB_CUSTODY_ADDRESS=\"{}\"", public_address);
    println!("export AUTHORITY1=\"ed25519:{}\"", bs58::encode(authorities[0].1.as_bytes()).into_string());
    println!("export AUTHORITY2=\"ed25519:{}\"", bs58::encode(authorities[1].1.as_bytes()).into_string());
    println!("export AUTHORITY3=\"ed25519:{}\"", bs58::encode(authorities[2].1.as_bytes()).into_string());
    println!();

    println!("════════════════════════════════════════════════════════════════");
    println!("  ⚠️  SECURITY WARNINGS");
    println!("════════════════════════════════════════════════════════════════");
    println!();
    println!("1. NEVER commit private keys to git");
    println!("2. Store private keys in a secure location (HSM, vault, etc.)");
    println!("3. The spend private key controls all funds - protect it!");
    println!("4. Authority keys should be distributed to different operators");
    println!("5. Consider using a hardware wallet for production");
    println!();
}

/// Create a MobileCoin-style public address from view and spend public keys.
///
/// Note: This is a simplified version. Real MobileCoin addresses include
/// network byte, fog info, and use RistrettoPoint encoding.
fn create_mob_address(view_pub: &VerifyingKey, spend_pub: &VerifyingKey) -> String {
    // Combine both public keys
    let mut combined = Vec::new();
    combined.extend_from_slice(view_pub.as_bytes());
    combined.extend_from_slice(spend_pub.as_bytes());

    // Hash for checksum
    let hash = Sha256::digest(&combined);

    // Append checksum (first 4 bytes)
    combined.extend_from_slice(&hash[0..4]);

    // Base58 encode (MobileCoin uses Base58Check)
    bs58::encode(combined).into_string()
}
