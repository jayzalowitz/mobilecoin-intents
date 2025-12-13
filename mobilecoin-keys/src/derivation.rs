//! One-time key derivation functions.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use crate::shared_secret::{compute_shared_secret, hash_to_point};
use crate::{KeyError, RistrettoPrivate, RistrettoPublic, TxKey};

/// Derive a one-time public key for a transaction output.
///
/// This implements the CryptoNote one-time address derivation:
/// ```text
/// P = Hs(r*A, index)*G + B
/// ```
/// Where:
/// - `r` = transaction private key
/// - `A` = recipient's public view key
/// - `B` = recipient's public spend key
/// - `G` = generator point
/// - `Hs` = hash-to-scalar
///
/// # Arguments
/// * `recipient_view_public` - Recipient's public view key (A)
/// * `recipient_spend_public` - Recipient's public spend key (B)
/// * `tx_private_key` - Transaction private key (r)
/// * `output_index` - Output index within the transaction
///
/// # Returns
/// The one-time public key for this output.
///
/// # Security
/// This function validates that the input public keys are valid points
/// on the Ristretto curve to prevent invalid curve attacks.
pub fn derive_one_time_public_key(
    recipient_view_public: &RistrettoPublic,
    recipient_spend_public: &RistrettoPublic,
    tx_private_key: &RistrettoPrivate,
    output_index: u64,
) -> RistrettoPublic {
    // Compute shared secret: Hs(r*A, index)
    // Note: compute_shared_secret validates the view public key internally
    let shared_secret = compute_shared_secret(recipient_view_public, tx_private_key, output_index);

    // Compute Hs(r*A)*G
    let derived_point = RISTRETTO_BASEPOINT_TABLE.basepoint() * shared_secret;

    // Get spend public key as point - use safe fallback for invalid keys
    let spend_point = match recipient_spend_public.decompress() {
        Some(point) => point,
        None => {
            // Return identity point derivative if key is invalid
            // This creates an unspendable output but doesn't panic
            return RistrettoPublic::from_point(derived_point);
        }
    };

    // P = Hs(r*A)*G + B
    let one_time_point = derived_point + spend_point;

    RistrettoPublic::from_point(one_time_point)
}

/// Safely derive a one-time public key, returning an error for invalid inputs.
///
/// This is the recommended function for production use as it handles
/// invalid public keys gracefully instead of panicking.
///
/// # Returns
/// * `Ok(RistrettoPublic)` - The derived one-time public key
/// * `Err(KeyError)` - If either input public key is invalid
pub fn derive_one_time_public_key_safe(
    recipient_view_public: &RistrettoPublic,
    recipient_spend_public: &RistrettoPublic,
    tx_private_key: &RistrettoPrivate,
    output_index: u64,
) -> Result<RistrettoPublic, KeyError> {
    // Validate view public key
    if !recipient_view_public.is_valid() {
        return Err(KeyError::InvalidPublicKey(
            "Invalid view public key".to_string(),
        ));
    }

    // Validate spend public key
    let spend_point = recipient_spend_public
        .decompress()
        .ok_or_else(|| KeyError::InvalidPublicKey("Invalid spend public key".to_string()))?;

    // Compute shared secret: Hs(r*A, index)
    let shared_secret = compute_shared_secret(recipient_view_public, tx_private_key, output_index);

    // Compute Hs(r*A)*G
    let derived_point = RISTRETTO_BASEPOINT_TABLE.basepoint() * shared_secret;

    // P = Hs(r*A)*G + B
    let one_time_point = derived_point + spend_point;

    Ok(RistrettoPublic::from_point(one_time_point))
}

/// Derive the one-time private key for spending an output.
///
/// This is used by the recipient to compute the private key
/// corresponding to a one-time public key:
/// ```text
/// p = Hs(a*R, index) + b
/// ```
/// Where:
/// - `a` = recipient's private view key
/// - `R` = transaction public key
/// - `b` = recipient's private spend key
///
/// # Arguments
/// * `tx_public_key` - Transaction public key (R)
/// * `view_private_key` - Recipient's private view key (a)
/// * `spend_private_key` - Recipient's private spend key (b)
/// * `output_index` - Output index within the transaction
///
/// # Returns
/// The one-time private key for spending this output.
pub fn derive_one_time_private_key(
    tx_public_key: &RistrettoPublic,
    view_private_key: &RistrettoPrivate,
    spend_private_key: &RistrettoPrivate,
    output_index: u64,
) -> RistrettoPrivate {
    // Compute shared secret: Hs(a*R, index)
    let shared_secret = compute_shared_secret(tx_public_key, view_private_key, output_index);

    // p = Hs(a*R) + b
    let one_time_scalar = shared_secret + spend_private_key.as_scalar();

    RistrettoPrivate::new(one_time_scalar)
}

/// Generate a new random transaction key.
///
/// A new transaction key should be generated for each transaction
/// to ensure unlinkability.
pub fn generate_tx_key() -> TxKey {
    TxKey::generate()
}

/// Derive the key image for a spent output.
///
/// Key images are used to detect double-spending without
/// revealing which output was spent:
/// ```text
/// I = p * Hp(P)
/// ```
/// Where:
/// - `p` = one-time private key
/// - `P` = one-time public key
/// - `Hp` = hash-to-point
///
/// # Arguments
/// * `one_time_private_key` - The one-time private key for the output
///
/// # Returns
/// The key image for this output.
pub fn derive_key_image(one_time_private_key: &RistrettoPrivate) -> RistrettoPublic {
    // Get the corresponding public key
    let one_time_public = one_time_private_key.public_key();

    // Hash the public key to a point
    let hash_point = hash_to_point(&one_time_public);

    // I = p * Hp(P)
    let key_image = one_time_private_key.as_scalar() * hash_point;

    RistrettoPublic::from_point(key_image)
}

/// Derive a one-time public key from the recipient's perspective.
///
/// This is used to verify that an output belongs to us:
/// ```text
/// P' = Hs(a*R, index)*G + B
/// ```
///
/// If P' == P (the output's public key), then the output is ours.
///
/// # Security
/// This function handles invalid public keys gracefully without panicking.
pub fn derive_one_time_from_receiver(
    tx_public_key: &RistrettoPublic,
    view_private_key: &RistrettoPrivate,
    spend_public_key: &RistrettoPublic,
    output_index: u64,
) -> RistrettoPublic {
    // Compute shared secret from receiver's perspective
    let shared_secret = compute_shared_secret(tx_public_key, view_private_key, output_index);

    // Compute Hs(a*R)*G
    let derived_point = RISTRETTO_BASEPOINT_TABLE.basepoint() * shared_secret;

    // Get spend public key as point - handle invalid keys gracefully
    let spend_point = match spend_public_key.decompress() {
        Some(point) => point,
        None => {
            // Return the derived point alone if spend key is invalid
            // This won't match any valid output, which is the correct behavior
            return RistrettoPublic::from_point(derived_point);
        }
    };

    // P' = Hs(a*R)*G + B
    let computed_point = derived_point + spend_point;

    RistrettoPublic::from_point(computed_point)
}

/// Safely derive a one-time public key from the recipient's perspective.
///
/// # Returns
/// * `Ok(RistrettoPublic)` - The computed one-time public key
/// * `Err(KeyError)` - If any input key is invalid
pub fn derive_one_time_from_receiver_safe(
    tx_public_key: &RistrettoPublic,
    view_private_key: &RistrettoPrivate,
    spend_public_key: &RistrettoPublic,
    output_index: u64,
) -> Result<RistrettoPublic, KeyError> {
    // Validate tx public key
    if !tx_public_key.is_valid() {
        return Err(KeyError::InvalidPublicKey(
            "Invalid transaction public key".to_string(),
        ));
    }

    // Validate spend public key
    let spend_point = spend_public_key
        .decompress()
        .ok_or_else(|| KeyError::InvalidPublicKey("Invalid spend public key".to_string()))?;

    // Compute shared secret from receiver's perspective
    let shared_secret = compute_shared_secret(tx_public_key, view_private_key, output_index);

    // Compute Hs(a*R)*G
    let derived_point = RISTRETTO_BASEPOINT_TABLE.basepoint() * shared_secret;

    // P' = Hs(a*R)*G + B
    let computed_point = derived_point + spend_point;

    Ok(RistrettoPublic::from_point(computed_point))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WalletKeys;

    #[test]
    fn test_one_time_key_derivation_consistency() {
        // Recipient generates wallet
        let wallet = WalletKeys::generate();

        // Sender generates transaction key
        let tx_key = generate_tx_key();

        // Sender derives one-time public key
        let sender_one_time = derive_one_time_public_key(
            &wallet.view_key_pair.public_key,
            &wallet.spend_key_pair.public_key,
            &tx_key.private_key,
            0,
        );

        // Recipient computes the same one-time public key
        let receiver_one_time = derive_one_time_from_receiver(
            &tx_key.public_key,
            &wallet.view_key_pair.private_key,
            &wallet.spend_key_pair.public_key,
            0,
        );

        // Both should match
        assert_eq!(sender_one_time, receiver_one_time);
    }

    #[test]
    fn test_one_time_private_key_matches_public() {
        let wallet = WalletKeys::generate();
        let tx_key = generate_tx_key();

        // Derive one-time public key (sender's view)
        let one_time_public = derive_one_time_public_key(
            &wallet.view_key_pair.public_key,
            &wallet.spend_key_pair.public_key,
            &tx_key.private_key,
            0,
        );

        // Derive one-time private key (receiver's view)
        let one_time_private = derive_one_time_private_key(
            &tx_key.public_key,
            &wallet.view_key_pair.private_key,
            &wallet.spend_key_pair.private_key,
            0,
        );

        // The private key should correspond to the public key
        let computed_public = one_time_private.public_key();
        assert_eq!(one_time_public, computed_public);
    }

    #[test]
    fn test_different_outputs_different_keys() {
        let wallet = WalletKeys::generate();
        let tx_key = generate_tx_key();

        let key0 = derive_one_time_public_key(
            &wallet.view_key_pair.public_key,
            &wallet.spend_key_pair.public_key,
            &tx_key.private_key,
            0,
        );

        let key1 = derive_one_time_public_key(
            &wallet.view_key_pair.public_key,
            &wallet.spend_key_pair.public_key,
            &tx_key.private_key,
            1,
        );

        // Different output indices should produce different keys
        assert_ne!(key0, key1);
    }

    #[test]
    fn test_different_transactions_different_keys() {
        let wallet = WalletKeys::generate();
        let tx_key1 = generate_tx_key();
        let tx_key2 = generate_tx_key();

        let key1 = derive_one_time_public_key(
            &wallet.view_key_pair.public_key,
            &wallet.spend_key_pair.public_key,
            &tx_key1.private_key,
            0,
        );

        let key2 = derive_one_time_public_key(
            &wallet.view_key_pair.public_key,
            &wallet.spend_key_pair.public_key,
            &tx_key2.private_key,
            0,
        );

        // Different transactions should produce different keys
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_key_image_derivation() {
        let wallet = WalletKeys::generate();
        let tx_key = generate_tx_key();

        let one_time_private = derive_one_time_private_key(
            &tx_key.public_key,
            &wallet.view_key_pair.private_key,
            &wallet.spend_key_pair.private_key,
            0,
        );

        let key_image = derive_key_image(&one_time_private);

        // Key image should be a valid point
        assert!(key_image.is_valid());

        // Same private key should always produce same key image
        let key_image2 = derive_key_image(&one_time_private);
        assert_eq!(key_image, key_image2);
    }

    #[test]
    fn test_tx_key_generation() {
        let tx_key1 = generate_tx_key();
        let tx_key2 = generate_tx_key();

        // Each transaction should have a unique key
        assert_ne!(tx_key1.public_key, tx_key2.public_key);
    }
}
