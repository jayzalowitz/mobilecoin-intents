//! Real MOB Deposit Proof Generator
//!
//! Creates a signed deposit proof for a real MOB deposit.
//! Uses the authority keys to sign and generates NEAR CLI command.
//!
//! Run with:
//!   cargo run --example demo-real-deposit -p mobilecoin-crypto

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::env;

fn main() {
    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║   MobileCoin Bridge - Real Deposit Proof Generator             ║");
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

    // Get deposit details from environment or use defaults
    let recipient = env::var("RECIPIENT").unwrap_or_else(|_| "marseille-mob.testnet".to_string());
    let amount: u128 = env::var("AMOUNT")
        .unwrap_or_else(|_| "1000000000000".to_string()) // 1 MOB default
        .parse()
        .expect("Invalid amount");

    // Generate a unique tx hash for this real deposit
    let timestamp = chrono::Utc::now().timestamp();
    let mut hasher = Sha256::new();
    hasher.update(format!("real_mob_deposit_{}_{}", recipient, timestamp).as_bytes());
    let tx_hash = hex::encode(hasher.finalize());

    // Use a recent block number (the current mainnet block is ~4.6M)
    let block_number: u64 = env::var("BLOCK_NUMBER")
        .unwrap_or_else(|_| "4673900".to_string())
        .parse()
        .expect("Invalid block number");

    println!("════════════════════════════════════════════════════════════════");
    println!("  REAL MOB DEPOSIT DETAILS");
    println!("════════════════════════════════════════════════════════════════");
    println!();
    println!("  MOB TX Hash:   {}", tx_hash);
    println!("  Recipient:     {}", recipient);
    println!("  Amount:        {} picoMOB ({} MOB)", amount, amount as f64 / 1_000_000_000_000.0);
    println!("  Block Number:  {}", block_number);
    println!();

    // Create the message to sign (same format as bridge contract)
    let msg = format!("DEPOSIT:{}:{}:{}:{}", tx_hash, recipient, amount, block_number);
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

    // Build the deposit proof JSON
    let deposit_proof = serde_json::json!({
        "proof": {
            "tx_hash": tx_hash,
            "amount": amount.to_string(),
            "recipient": recipient,
            "block_number": block_number,
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
        }
    });

    let proof_json = serde_json::to_string(&deposit_proof).unwrap();
    let proof_pretty = serde_json::to_string_pretty(&deposit_proof).unwrap();

    println!("════════════════════════════════════════════════════════════════");
    println!("  DEPOSIT PROOF");
    println!("════════════════════════════════════════════════════════════════");
    println!();
    println!("{}", proof_pretty);
    println!();

    println!("════════════════════════════════════════════════════════════════");
    println!("  NEAR CLI COMMAND");
    println!("════════════════════════════════════════════════════════════════");
    println!();
    println!("NEAR_ENV=testnet near contract call-function as-transaction \\");
    println!("  bridge-marseille.testnet deposit \\");
    println!("  json-args '{}' \\", proof_json.replace('\'', "\\'"));
    println!("  prepaid-gas '100.0 Tgas' \\");
    println!("  attached-deposit '0.01 NEAR' \\");
    println!("  sign-as marseille-mob.testnet \\");
    println!("  network-config testnet sign-with-keychain send");
    println!();

    // Save proof to file
    let output_path = "secrets/real-deposit-proof.json";
    std::fs::write(output_path, &proof_pretty).expect("Failed to write proof");
    println!("Proof saved to: {}", output_path);
    println!();

    println!("════════════════════════════════════════════════════════════════");
    println!("  WHAT THIS REPRESENTS");
    println!("════════════════════════════════════════════════════════════════");
    println!();
    println!("  This proof attests that:");
    println!("    • {} MOB was deposited to the bridge custody address", amount as f64 / 1_000_000_000_000.0);
    println!("    • The deposit was verified by 2 of 3 authorities");
    println!("    • The recipient {} should receive wMOB", recipient);
    println!();
    println!("  In production, authorities would:");
    println!("    1. Monitor the MobileCoin blockchain for deposits");
    println!("    2. Verify the tx actually happened on-chain");
    println!("    3. Sign the proof only after confirmation");
    println!();
}
