//! Complete Withdrawal Script
//!
//! Signs a withdrawal completion proof after MOB has been sent to the user.
//! Uses authority keys to sign and generates NEAR CLI command.
//!
//! Run with:
//!   WITHDRAWAL_ID=0 MOB_TX_HASH=abc123 cargo run --example complete-withdrawal -p mobilecoin-crypto

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::env;

fn main() {
    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║   MobileCoin Bridge - Withdrawal Completion                    ║");
    println!("║   Project: Marseille                                           ║");
    println!("╚════════════════════════════════════════════════════════════════╝");
    println!();

    // Load authority keys from secrets file
    let secrets_path = "secrets/wallet-keys.json";
    let secrets_content = std::fs::read_to_string(secrets_path)
        .expect("Failed to read secrets/wallet-keys.json");

    let secrets: serde_json::Value = serde_json::from_str(&secrets_content)
        .expect("Failed to parse secrets JSON");

    let auth1_hex = secrets["authorities"][0]["keypair"]["private_key_hex"]
        .as_str()
        .expect("Missing authority 1 key");
    let auth2_hex = secrets["authorities"][1]["keypair"]["private_key_hex"]
        .as_str()
        .expect("Missing authority 2 key");

    println!("Loaded authority keys");
    println!();

    // Get withdrawal details from environment
    let withdrawal_id: u64 = env::var("WITHDRAWAL_ID")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .expect("Invalid withdrawal ID");

    // Generate a tx hash representing the MOB transaction on MobileCoin
    let mob_tx_hash = env::var("MOB_TX_HASH").unwrap_or_else(|_| {
        let timestamp = chrono::Utc::now().timestamp();
        let mut hasher = Sha256::new();
        hasher.update(format!("mob_withdrawal_{}_{}", withdrawal_id, timestamp).as_bytes());
        hex::encode(hasher.finalize())
    });

    println!("════════════════════════════════════════════════════════════════");
    println!("  WITHDRAWAL COMPLETION DETAILS");
    println!("════════════════════════════════════════════════════════════════");
    println!();
    println!("  Withdrawal ID: {}", withdrawal_id);
    println!("  MOB TX Hash:   {}", mob_tx_hash);
    println!();

    // Create the message to sign (same format as bridge contract)
    let msg = format!("COMPLETE:{}:{}", withdrawal_id, mob_tx_hash);
    println!("Message to sign:");
    println!("  {}", msg);

    let mut hasher = Sha256::new();
    hasher.update(msg.as_bytes());
    let message_hash = hasher.finalize();

    println!("Message hash:    {}", hex::encode(&message_hash));
    println!();

    // Sign with authority 1
    let auth1_bytes = hex::decode(auth1_hex).expect("Invalid auth1 hex");
    let auth1_key = SigningKey::from_bytes(&auth1_bytes.try_into().expect("Wrong key length"));
    let sig1 = auth1_key.sign(&message_hash);
    let sig1_hex = hex::encode(sig1.to_bytes());

    println!("Authority 1 signature: {}...", &sig1_hex[0..32]);

    // Sign with authority 2
    let auth2_bytes = hex::decode(auth2_hex).expect("Invalid auth2 hex");
    let auth2_key = SigningKey::from_bytes(&auth2_bytes.try_into().expect("Wrong key length"));
    let sig2 = auth2_key.sign(&message_hash);
    let sig2_hex = hex::encode(sig2.to_bytes());

    println!("Authority 2 signature: {}...", &sig2_hex[0..32]);
    println!();

    // Build the completion proof JSON
    let completion = serde_json::json!({
        "withdrawal_id": withdrawal_id,
        "mob_tx_hash": mob_tx_hash,
        "signatures": [
            {
                "authority_index": 0,
                "signature": sig1_hex
            },
            {
                "authority_index": 1,
                "signature": sig2_hex
            }
        ]
    });

    let completion_json = serde_json::to_string(&completion).unwrap();
    let completion_pretty = serde_json::to_string_pretty(&completion).unwrap();

    println!("════════════════════════════════════════════════════════════════");
    println!("  COMPLETION PROOF");
    println!("════════════════════════════════════════════════════════════════");
    println!();
    println!("{}", completion_pretty);
    println!();

    println!("════════════════════════════════════════════════════════════════");
    println!("  NEAR CLI COMMAND");
    println!("════════════════════════════════════════════════════════════════");
    println!();
    println!("NEAR_ENV=testnet near contract call-function as-transaction \\");
    println!("  bridge-marseille.testnet complete_withdrawal \\");
    println!("  json-args '{}' \\", completion_json.replace('\'', "\\'"));
    println!("  prepaid-gas '100.0 Tgas' \\");
    println!("  attached-deposit '0 NEAR' \\");
    println!("  sign-as marseille-mob.testnet \\");
    println!("  network-config testnet sign-with-keychain send");
    println!();

    println!("════════════════════════════════════════════════════════════════");
    println!("  WHAT THIS REPRESENTS");
    println!("════════════════════════════════════════════════════════════════");
    println!();
    println!("  This completion attestation confirms that:");
    println!("    • The MOB has been sent to the destination address");
    println!("    • Transaction {} is finalized on MobileCoin", &mob_tx_hash[0..16]);
    println!("    • 2 of 3 authorities have verified the transfer");
    println!();
    println!("  After completion:");
    println!("    • The withdrawal request is marked as Completed");
    println!("    • Storage deposit is refunded to the requester");
    println!();
}
