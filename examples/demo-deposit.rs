//! Demo Deposit Script
//!
//! Signs a mock MOB deposit and outputs the JSON needed to call the bridge contract.
//!
//! Run with:
//!   cargo run --example demo-deposit
//!
//! Then use the output to call the bridge contract on NEAR testnet.

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

fn main() {
    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║   MobileCoin Bridge Demo - Create Signed Deposit               ║");
    println!("║   Project: Marseille                                           ║");
    println!("╚════════════════════════════════════════════════════════════════╝");
    println!();

    // Load authority keys from secrets file
    let secrets_path = "secrets/wallet-keys.json";
    let secrets_content = std::fs::read_to_string(secrets_path)
        .expect("Failed to read secrets/wallet-keys.json. Run: cargo run --example generate-keys -p mobilecoin-crypto");

    let secrets: serde_json::Value = serde_json::from_str(&secrets_content)
        .expect("Failed to parse secrets JSON");

    // Get authority private keys
    let auth1_hex = secrets["authorities"][0]["keypair"]["private_key_hex"]
        .as_str()
        .expect("Missing authority 1 key");
    let auth2_hex = secrets["authorities"][1]["keypair"]["private_key_hex"]
        .as_str()
        .expect("Missing authority 2 key");

    println!("Loaded authority keys from secrets/wallet-keys.json");
    println!();

    // Create mock deposit details
    // MobileCoin tx hashes are 64 hex chars (32 bytes) - we create a realistic looking one
    let timestamp = chrono::Utc::now().timestamp();
    let mut hasher = Sha256::new();
    hasher.update(format!("mob_deposit_demo_{}", timestamp).as_bytes());
    let tx_hash = hex::encode(hasher.finalize()); // 64 hex chars
    let recipient = "marseille-mob.testnet";
    let amount: u128 = 1_000_000_000_000; // 1 MOB in picoMOB
    let block_number: u64 = 12345678;

    println!("Deposit Details:");
    println!("  TX Hash:      {}", tx_hash);
    println!("  Recipient:    {}", recipient);
    println!("  Amount:       {} picoMOB (1 MOB)", amount);
    println!("  Block Number: {}", block_number);
    println!();

    // Create the message to sign (same format as bridge contract)
    let msg = format!("DEPOSIT:{}:{}:{}:{}", tx_hash, recipient, amount, block_number);
    println!("Message to sign: {}", msg);

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
    println!("  DEPOSIT PROOF (for bridge contract)");
    println!("════════════════════════════════════════════════════════════════");
    println!();
    println!("{}", proof_pretty);
    println!();

    println!("════════════════════════════════════════════════════════════════");
    println!("  NEAR CLI COMMAND");
    println!("════════════════════════════════════════════════════════════════");
    println!();
    println!("Run this command to submit the deposit to the bridge:");
    println!();
    println!("NEAR_ENV=testnet near contract call-function as-transaction \\");
    println!("  bridge-marseille.testnet deposit \\");
    println!("  json-args '{}' \\", proof_json.replace("'", "\\'"));
    println!("  prepaid-gas '100.0 Tgas' \\");
    println!("  attached-deposit '0.01 NEAR' \\");
    println!("  sign-as marseille-mob.testnet \\");
    println!("  network-config testnet sign-with-keychain send");
    println!();

    // Also save to a file for easier use
    let output_path = "secrets/demo-deposit-proof.json";
    std::fs::write(output_path, proof_pretty).expect("Failed to write proof file");
    println!("Proof also saved to: {}", output_path);
    println!();
}
