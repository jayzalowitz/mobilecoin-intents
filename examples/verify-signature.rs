//! Verify Ed25519 signatures match between Rust and NEAR
//!
//! Run with:
//!   cargo run --example verify-signature -p mobilecoin-crypto

use ed25519_dalek::{Signer, SigningKey, VerifyingKey, Verifier, Signature};
use sha2::{Digest, Sha256};

fn main() {
    println!("Ed25519 Signature Verification Test");
    println!("====================================\n");

    // Load authority keys from secrets file
    let secrets_path = "secrets/wallet-keys.json";
    let secrets_content = std::fs::read_to_string(secrets_path)
        .expect("Failed to read secrets/wallet-keys.json");

    let secrets: serde_json::Value = serde_json::from_str(&secrets_content)
        .expect("Failed to parse secrets JSON");

    let auth1_private_hex = secrets["authorities"][0]["keypair"]["private_key_hex"]
        .as_str()
        .expect("Missing authority 1 private key");
    let auth1_public_hex = secrets["authorities"][0]["keypair"]["public_key_hex"]
        .as_str()
        .expect("Missing authority 1 public key");

    println!("Authority 1:");
    println!("  Private key (hex): {}", auth1_private_hex);
    println!("  Public key (hex):  {}", auth1_public_hex);

    // Decode private key
    let private_bytes = hex::decode(auth1_private_hex).expect("Invalid hex");
    let signing_key = SigningKey::from_bytes(&private_bytes.try_into().expect("Wrong length"));

    // Verify the public key matches
    let verifying_key = signing_key.verifying_key();
    let derived_public_hex = hex::encode(verifying_key.as_bytes());
    println!("  Derived pubkey:    {}", derived_public_hex);
    println!("  Keys match:        {}\n", derived_public_hex == auth1_public_hex);

    // Create a test message (same format as bridge)
    let tx_hash = "6ed61bc4408f3151328d703e1b47aec87ac6eca245d843b3ffc7d9eb74918aba";
    let recipient = "marseille-mob.testnet";
    let amount: u128 = 1000000000000;
    let block_number: u64 = 4673900;

    let msg = format!("DEPOSIT:{}:{}:{}:{}", tx_hash, recipient, amount, block_number);
    println!("Message: {}", msg);

    // Hash the message
    let mut hasher = Sha256::new();
    hasher.update(msg.as_bytes());
    let message_hash = hasher.finalize();
    println!("SHA256 hash: {}\n", hex::encode(&message_hash));

    // Sign the message hash
    let signature = signing_key.sign(&message_hash);
    let sig_hex = hex::encode(signature.to_bytes());
    println!("Signature: {}", sig_hex);
    println!("Sig length: {} bytes ({} hex chars)\n", signature.to_bytes().len(), sig_hex.len());

    // Verify the signature
    let sig_bytes: [u8; 64] = signature.to_bytes();
    let signature2 = Signature::from_bytes(&sig_bytes);
    let verify_result = verifying_key.verify(&message_hash, &signature2);
    println!("Verification result: {:?}\n", verify_result);

    // Now let's check what NEAR expects
    println!("NEAR PublicKey format:");
    let near_pubkey = secrets["authorities"][0]["keypair"]["near_public_key"]
        .as_str()
        .expect("Missing NEAR public key");
    println!("  {}", near_pubkey);

    // NEAR's ed25519_verify expects:
    // - signature: &[u8; 64]
    // - message: &[u8]  (the hash in our case)
    // - public_key: &[u8; 32]
    //
    // The bridge code does:
    //   let pubkey_bytes = authority_pubkey.as_bytes();  // NEAR PublicKey serialized
    //   let ed25519_pubkey = &pubkey_bytes[1..33];  // Skip curve type byte

    println!("\nWhat the bridge will do:");
    println!("  1. Take NEAR PublicKey");
    println!("  2. Get as_bytes() which is: [curve_type] || [32 bytes pubkey]");
    println!("  3. Use bytes[1..33] as the raw Ed25519 public key");
    println!("  4. Call env::ed25519_verify(sig, message_hash, pubkey)");
    println!("\nRaw Ed25519 pubkey (32 bytes): {}", auth1_public_hex);
}
