//! Message hashing utilities for MobileCoin signing.

use sha2::{Sha256, Sha512, Digest};

/// Hash a message for MobileCoin signing using SHA-512.
///
/// This function creates a 64-byte hash of the input message,
/// which is the internal hash function used by Ed25519.
///
/// # Arguments
/// * `message` - The message to hash
///
/// # Returns
/// A 64-byte SHA-512 hash.
pub fn hash_message_for_signing(message: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(message);
    let result = hasher.finalize();
    let mut output = [0u8; 64];
    output.copy_from_slice(&result);
    output
}

/// Create a signable message for a MobileCoin intent.
///
/// This function creates a structured message that can be signed,
/// following the format used by NEAR Intents.
///
/// # Arguments
/// * `intent_id` - Unique identifier for the intent
/// * `action` - The action type (e.g., "swap", "transfer")
/// * `params` - Additional parameters as bytes
///
/// # Returns
/// A byte vector containing the signable message.
///
/// # Message Format
/// ```text
/// MobileCoin Intent v1\n
/// intent_id: <intent_id>\n
/// action: <action>\n
/// params_hash: <sha256(params)>\n
/// ```
pub fn create_signable_message(
    intent_id: &str,
    action: &str,
    params: &[u8],
) -> Vec<u8> {
    let params_hash = hash_params(params);
    let params_hash_hex = hex::encode(params_hash);

    let message = format!(
        "MobileCoin Intent v1\nintent_id: {}\naction: {}\nparams_hash: {}\n",
        intent_id, action, params_hash_hex
    );

    message.into_bytes()
}

/// Hash parameters using SHA-256.
fn hash_params(params: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(params);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Create a signable message for a swap intent.
///
/// # Arguments
/// * `intent_id` - Unique identifier for the intent
/// * `source_asset` - Source asset (e.g., "MOB")
/// * `source_amount` - Amount in smallest unit (picoMOB)
/// * `dest_asset` - Destination asset (e.g., "wMOB")
/// * `min_dest_amount` - Minimum acceptable destination amount
/// * `dest_address` - Destination address
/// * `deadline` - Unix timestamp deadline
///
/// # Returns
/// A byte vector containing the signable message.
pub fn create_swap_message(
    intent_id: &str,
    source_asset: &str,
    source_amount: u128,
    dest_asset: &str,
    min_dest_amount: u128,
    dest_address: &str,
    deadline: u64,
) -> Vec<u8> {
    let message = format!(
        "MobileCoin Swap Intent v1\n\
        intent_id: {}\n\
        source_asset: {}\n\
        source_amount: {}\n\
        dest_asset: {}\n\
        min_dest_amount: {}\n\
        dest_address: {}\n\
        deadline: {}\n",
        intent_id,
        source_asset,
        source_amount,
        dest_asset,
        min_dest_amount,
        dest_address,
        deadline
    );

    message.into_bytes()
}

/// Create a SHA-256 hash of arbitrary data.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Create a SHA-512 hash of arbitrary data.
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; 64];
    output.copy_from_slice(&result);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_message_for_signing() {
        let message = b"Hello, MobileCoin!";
        let hash = hash_message_for_signing(message);

        // SHA-512 produces 64 bytes
        assert_eq!(hash.len(), 64);

        // Same input should produce same hash
        let hash2 = hash_message_for_signing(message);
        assert_eq!(hash, hash2);

        // Different input should produce different hash
        let different_hash = hash_message_for_signing(b"Different message");
        assert_ne!(hash, different_hash);
    }

    #[test]
    fn test_create_signable_message() {
        let intent_id = "intent-123";
        let action = "swap";
        let params = b"some params";

        let message = create_signable_message(intent_id, action, params);

        // Message should start with version prefix
        assert!(String::from_utf8_lossy(&message).starts_with("MobileCoin Intent v1\n"));

        // Message should contain intent_id
        assert!(String::from_utf8_lossy(&message).contains("intent_id: intent-123"));

        // Message should contain action
        assert!(String::from_utf8_lossy(&message).contains("action: swap"));
    }

    #[test]
    fn test_create_swap_message() {
        let message = create_swap_message(
            "swap-456",
            "MOB",
            1_000_000_000_000,
            "wMOB",
            990_000_000_000,
            "test.near",
            1700000000,
        );

        let message_str = String::from_utf8_lossy(&message);

        assert!(message_str.contains("MobileCoin Swap Intent v1"));
        assert!(message_str.contains("intent_id: swap-456"));
        assert!(message_str.contains("source_asset: MOB"));
        assert!(message_str.contains("source_amount: 1000000000000"));
        assert!(message_str.contains("dest_asset: wMOB"));
        assert!(message_str.contains("min_dest_amount: 990000000000"));
        assert!(message_str.contains("dest_address: test.near"));
        assert!(message_str.contains("deadline: 1700000000"));
    }

    #[test]
    fn test_sha256() {
        let data = b"test data";
        let hash = sha256(data);

        assert_eq!(hash.len(), 32);

        // Known SHA-256 hash for "test data"
        let expected = hex::decode(
            "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
        )
        .unwrap();

        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha512() {
        let data = b"test data";
        let hash = sha512(data);

        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_deterministic_messages() {
        let msg1 = create_signable_message("id", "action", b"params");
        let msg2 = create_signable_message("id", "action", b"params");

        assert_eq!(msg1, msg2);
    }
}
