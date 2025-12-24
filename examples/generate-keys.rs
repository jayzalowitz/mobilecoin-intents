//! MobileCoin Bridge Key Generator
//!
//! Generates all cryptographic keys needed for the Marseille bridge:
//! - Custody wallet (view + spend keypairs) with proper MobileCoin address
//! - 3 Authority keypairs for the PoA bridge (NEAR-compatible format)
//!
//! Run with:
//!   cargo run --example generate-keys
//!
//! Output is saved to secrets/wallet-keys.json (gitignored)

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

#[derive(Serialize, Clone)]
struct Keypair {
    private_key_hex: String,
    public_key_hex: String,
    near_public_key: String,
}

#[derive(Serialize)]
struct WalletKeys {
    generated_at: String,
    warning: String,
    custody_wallet: CustodyWallet,
    authorities: Vec<Authority>,
    environment_variables: EnvironmentVars,
}

#[derive(Serialize)]
struct CustodyWallet {
    view_keypair: Keypair,
    spend_keypair: Keypair,
    public_address: String,
    public_address_note: String,
}

#[derive(Serialize, Clone)]
struct Authority {
    index: u32,
    keypair: Keypair,
}

#[derive(Serialize)]
struct EnvironmentVars {
    #[serde(rename = "MOB_CUSTODY_ADDRESS")]
    mob_custody_address: String,
    #[serde(rename = "AUTHORITY1")]
    authority1: String,
    #[serde(rename = "AUTHORITY2")]
    authority2: String,
    #[serde(rename = "AUTHORITY3")]
    authority3: String,
}

fn generate_keypair() -> Keypair {
    let signing = SigningKey::generate(&mut OsRng);
    let verifying = signing.verifying_key();

    Keypair {
        private_key_hex: hex::encode(signing.to_bytes()),
        public_key_hex: hex::encode(verifying.as_bytes()),
        near_public_key: format!("ed25519:{}", bs58::encode(verifying.as_bytes()).into_string()),
    }
}

/// Create a MobileCoin-style public address from view and spend public keys.
///
/// This creates a Base58Check encoded address containing:
/// - View public key (32 bytes)
/// - Spend public key (32 bytes)
/// - Checksum (4 bytes from SHA256)
///
/// Note: Real MobileCoin addresses also include network byte and fog info.
/// This simplified version is suitable for the bridge demo.
fn create_mob_address(view_pub_hex: &str, spend_pub_hex: &str) -> String {
    let view_pub = hex::decode(view_pub_hex).expect("Invalid view public key hex");
    let spend_pub = hex::decode(spend_pub_hex).expect("Invalid spend public key hex");

    let mut combined = Vec::with_capacity(68); // 32 + 32 + 4
    combined.extend_from_slice(&view_pub);
    combined.extend_from_slice(&spend_pub);

    // Double SHA256 for checksum (Bitcoin/MobileCoin style)
    let hash1 = Sha256::digest(&combined);
    let hash2 = Sha256::digest(&hash1);
    combined.extend_from_slice(&hash2[0..4]);

    bs58::encode(combined).into_string()
}

fn main() {
    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║   MobileCoin Bridge Key Generator                              ║");
    println!("║   Project: Marseille                                           ║");
    println!("╚════════════════════════════════════════════════════════════════╝");
    println!();

    // Generate custody wallet keypairs
    println!("Generating Custody Wallet keys...");
    let view = generate_keypair();
    let spend = generate_keypair();

    // Create the public address
    let public_address = create_mob_address(&view.public_key_hex, &spend.public_key_hex);
    println!("  Public Address: {}", public_address);

    // Generate authority keypairs
    println!("Generating Authority keypairs...");
    let auth1 = generate_keypair();
    println!("  Authority 1: {}", auth1.near_public_key);
    let auth2 = generate_keypair();
    println!("  Authority 2: {}", auth2.near_public_key);
    let auth3 = generate_keypair();
    println!("  Authority 3: {}", auth3.near_public_key);

    // Build the output structure
    let wallet = WalletKeys {
        generated_at: chrono::Utc::now().to_rfc3339(),
        warning: "NEVER COMMIT THIS FILE TO GIT - Contains private keys!".to_string(),
        custody_wallet: CustodyWallet {
            view_keypair: view,
            spend_keypair: spend,
            public_address: public_address.clone(),
            public_address_note: "Base58Check encoded (view_pub || spend_pub || checksum)".to_string(),
        },
        authorities: vec![
            Authority { index: 1, keypair: auth1.clone() },
            Authority { index: 2, keypair: auth2.clone() },
            Authority { index: 3, keypair: auth3.clone() },
        ],
        environment_variables: EnvironmentVars {
            mob_custody_address: public_address.clone(),
            authority1: auth1.near_public_key.clone(),
            authority2: auth2.near_public_key.clone(),
            authority3: auth3.near_public_key.clone(),
        },
    };

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&wallet).expect("Failed to serialize");

    // Create secrets directory if it doesn't exist
    let secrets_dir = Path::new("secrets");
    if !secrets_dir.exists() {
        fs::create_dir_all(secrets_dir).expect("Failed to create secrets directory");
    }

    // Write to file
    let output_path = secrets_dir.join("wallet-keys.json");
    fs::write(&output_path, &json).expect("Failed to write keys file");

    println!();
    println!("════════════════════════════════════════════════════════════════");
    println!("  Keys saved to: {}", output_path.display());
    println!("════════════════════════════════════════════════════════════════");
    println!();
    println!("{}", json);
    println!();
    println!("════════════════════════════════════════════════════════════════");
    println!("  ENVIRONMENT VARIABLES (copy to your shell or .env file)");
    println!("════════════════════════════════════════════════════════════════");
    println!();
    println!("export MOB_CUSTODY_ADDRESS=\"{}\"", wallet.environment_variables.mob_custody_address);
    println!("export AUTHORITY1=\"{}\"", wallet.environment_variables.authority1);
    println!("export AUTHORITY2=\"{}\"", wallet.environment_variables.authority2);
    println!("export AUTHORITY3=\"{}\"", wallet.environment_variables.authority3);
    println!();
    println!("════════════════════════════════════════════════════════════════");
    println!("  ⚠️  SECURITY WARNINGS");
    println!("════════════════════════════════════════════════════════════════");
    println!();
    println!("1. NEVER commit secrets/wallet-keys.json to git");
    println!("2. Back up private keys securely (encrypted, offline)");
    println!("3. The spend_keypair private key controls ALL custody funds");
    println!("4. Distribute authority private keys to different operators");
    println!("5. For production, use HSM or hardware security modules");
    println!();
}
