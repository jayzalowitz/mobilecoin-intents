//! NEAR Intents integration for one-time key derivation.

use crate::derivation::{derive_one_time_from_receiver, derive_one_time_public_key};
use crate::shared_secret::hash_to_scalar;
use crate::{KeyError, RistrettoPrivate, RistrettoPublic, TxKey};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use mobilecoin_address::MobAddress;

/// Generate a deterministic one-time address for NEAR Intents settlement.
///
/// This uses the intent ID as a seed to deterministically generate
/// a transaction key, allowing both parties to verify the settlement
/// address without additional communication.
///
/// # Arguments
/// * `recipient_address` - The recipient's MobileCoin address
/// * `intent_id` - The NEAR Intents intent ID (used as seed)
///
/// # Returns
/// A tuple of (one_time_public_key, tx_key) for the settlement.
pub fn generate_settlement_address(
    recipient_address: &MobAddress,
    intent_id: &str,
) -> (RistrettoPublic, TxKey) {
    // Derive deterministic transaction key from intent ID
    let tx_key = derive_tx_key_from_intent(intent_id, "settlement");

    // Convert address keys
    let view_public = RistrettoPublic::from(recipient_address.view_public_key);
    let spend_public = RistrettoPublic::from(recipient_address.spend_public_key);

    // Derive one-time public key
    let one_time_public = derive_one_time_public_key(
        &view_public,
        &spend_public,
        &tx_key.private_key,
        0, // Always use output index 0 for settlements
    );

    (one_time_public, tx_key)
}

/// Verify that a settlement was sent to the correct one-time address.
///
/// This allows anyone to verify that a MOB transaction output
/// was correctly addressed to the intended recipient.
///
/// # Arguments
/// * `output_public_key` - The actual output public key from the transaction
/// * `tx_public_key` - The transaction public key (R)
/// * `recipient_address` - The expected recipient's MobileCoin address
/// * `intent_id` - The NEAR Intents intent ID
///
/// # Returns
/// `true` if the output was correctly addressed.
pub fn verify_settlement_address(
    output_public_key: &RistrettoPublic,
    tx_public_key: &RistrettoPublic,
    recipient_address: &MobAddress,
    intent_id: &str,
) -> bool {
    // Derive the expected transaction key
    let expected_tx_key = derive_tx_key_from_intent(intent_id, "settlement");

    // Check if the transaction public keys match
    if expected_tx_key.public_key != *tx_public_key {
        return false;
    }

    // Compute expected one-time public key
    let view_public = RistrettoPublic::from(recipient_address.view_public_key);
    let spend_public = RistrettoPublic::from(recipient_address.spend_public_key);

    let expected_one_time =
        derive_one_time_public_key(&view_public, &spend_public, &expected_tx_key.private_key, 0);

    // Verify they match
    expected_one_time == *output_public_key
}

/// Generate a deterministic refund address for a failed/expired intent.
///
/// If a swap fails, the original sender needs to receive their funds back.
/// This generates a deterministic address for the refund.
///
/// # Arguments
/// * `sender_address` - The original sender's MobileCoin address
/// * `intent_id` - The NEAR Intents intent ID
///
/// # Returns
/// A tuple of (one_time_public_key, tx_key) for the refund.
pub fn generate_refund_address(
    sender_address: &MobAddress,
    intent_id: &str,
) -> (RistrettoPublic, TxKey) {
    // Use different domain for refund to avoid collision with settlement
    let tx_key = derive_tx_key_from_intent(intent_id, "refund");

    let view_public = RistrettoPublic::from(sender_address.view_public_key);
    let spend_public = RistrettoPublic::from(sender_address.spend_public_key);

    let one_time_public =
        derive_one_time_public_key(&view_public, &spend_public, &tx_key.private_key, 0);

    (one_time_public, tx_key)
}

/// Derive a deterministic transaction key from an intent ID.
///
/// This uses hash-to-scalar to create a deterministic private key
/// from the intent ID and a domain separator.
fn derive_tx_key_from_intent(intent_id: &str, domain: &str) -> TxKey {
    // Create deterministic seed
    let seed = format!("NEAR_INTENTS:{}:{}", domain, intent_id);
    let scalar = hash_to_scalar(seed.as_bytes());

    let private_key = RistrettoPrivate::new(scalar);
    TxKey::from_private(private_key)
}

/// Generate a unique output identifier for tracking.
///
/// This creates a deterministic identifier that can be used to
/// track and reference specific outputs in the NEAR Intents system.
///
/// # Arguments
/// * `intent_id` - The NEAR Intents intent ID
/// * `output_type` - The type of output ("settlement" or "refund")
/// * `output_index` - The output index
///
/// # Returns
/// A unique identifier string.
pub fn generate_output_id(intent_id: &str, output_type: &str, output_index: u64) -> String {
    format!("mob:{}:{}:{}", intent_id, output_type, output_index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use mobilecoin_address::{MobNetwork, RistrettoPublic as AddrRistrettoPublic};
    use rand::RngCore;

    /// Generate a valid Ristretto public key (on the curve) for mobilecoin_address.
    fn generate_valid_addr_key() -> AddrRistrettoPublic {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        let scalar = Scalar::from_bytes_mod_order_wide(&bytes);
        let point = RISTRETTO_BASEPOINT_TABLE.basepoint() * scalar;
        AddrRistrettoPublic::from(point)
    }

    fn create_test_address() -> MobAddress {
        let view_key = generate_valid_addr_key();
        let spend_key = generate_valid_addr_key();
        MobAddress::new(view_key, spend_key, MobNetwork::Mainnet)
    }

    #[test]
    fn test_settlement_address_deterministic() {
        let address = create_test_address();
        let intent_id = "intent-12345";

        let (key1, tx_key1) = generate_settlement_address(&address, intent_id);
        let (key2, tx_key2) = generate_settlement_address(&address, intent_id);

        // Same inputs should produce same outputs
        assert_eq!(key1, key2);
        assert_eq!(tx_key1.public_key, tx_key2.public_key);
    }

    #[test]
    fn test_settlement_address_different_intents() {
        let address = create_test_address();

        let (key1, _) = generate_settlement_address(&address, "intent-1");
        let (key2, _) = generate_settlement_address(&address, "intent-2");

        // Different intents should produce different addresses
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_settlement_address_different_recipients() {
        let address1 = create_test_address();
        let address2 = create_test_address();

        let (key1, tx_key1) = generate_settlement_address(&address1, "intent-1");
        let (key2, tx_key2) = generate_settlement_address(&address2, "intent-1");

        // Same intent but different recipients should produce:
        // - Same transaction key (deterministic from intent)
        // - Different one-time public keys
        assert_eq!(tx_key1.public_key, tx_key2.public_key);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_verify_settlement_address() {
        let address = create_test_address();
        let intent_id = "intent-verify-test";

        let (one_time_key, tx_key) = generate_settlement_address(&address, intent_id);

        // Should verify correctly
        assert!(verify_settlement_address(
            &one_time_key,
            &tx_key.public_key,
            &address,
            intent_id,
        ));

        // Should fail with wrong intent ID
        assert!(!verify_settlement_address(
            &one_time_key,
            &tx_key.public_key,
            &address,
            "wrong-intent",
        ));
    }

    #[test]
    fn test_refund_address_different_from_settlement() {
        let address = create_test_address();
        let intent_id = "intent-1";

        let (settlement_key, settlement_tx) = generate_settlement_address(&address, intent_id);
        let (refund_key, refund_tx) = generate_refund_address(&address, intent_id);

        // Settlement and refund should have different keys
        assert_ne!(settlement_key, refund_key);
        assert_ne!(settlement_tx.public_key, refund_tx.public_key);
    }

    #[test]
    fn test_refund_address_deterministic() {
        let address = create_test_address();
        let intent_id = "intent-refund-test";

        let (key1, _) = generate_refund_address(&address, intent_id);
        let (key2, _) = generate_refund_address(&address, intent_id);

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_output_id_generation() {
        let id = generate_output_id("intent-123", "settlement", 0);
        assert_eq!(id, "mob:intent-123:settlement:0");

        let id2 = generate_output_id("intent-456", "refund", 1);
        assert_eq!(id2, "mob:intent-456:refund:1");
    }
}
