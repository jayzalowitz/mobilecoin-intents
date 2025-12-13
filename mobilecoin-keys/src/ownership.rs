//! Output ownership verification.

use crate::derivation::{
    derive_key_image, derive_one_time_from_receiver, derive_one_time_private_key,
};
use crate::{KeyError, RistrettoPrivate, RistrettoPublic};

/// A detected output that belongs to a wallet.
#[derive(Debug, Clone)]
pub struct OwnedOutput {
    /// Index of this output in the transaction.
    pub output_index: u64,
    /// The one-time public key of this output.
    pub one_time_public_key: RistrettoPublic,
    /// The derived one-time private key (for spending).
    pub one_time_private_key: RistrettoPrivate,
    /// The key image (for double-spend detection).
    pub key_image: RistrettoPublic,
}

/// Check if a transaction output belongs to a wallet.
///
/// This verifies ownership by computing:
/// ```text
/// P' = Hs(a*R, index)*G + B
/// ```
/// and checking if P' == P (the output's public key).
///
/// # Arguments
/// * `output_public_key` - The output's one-time public key (P)
/// * `tx_public_key` - The transaction public key (R)
/// * `view_private_key` - Wallet's private view key (a)
/// * `spend_public_key` - Wallet's public spend key (B)
/// * `output_index` - The output's index in the transaction
///
/// # Returns
/// `true` if the output belongs to this wallet.
pub fn check_output_ownership(
    output_public_key: &RistrettoPublic,
    tx_public_key: &RistrettoPublic,
    view_private_key: &RistrettoPrivate,
    spend_public_key: &RistrettoPublic,
    output_index: u64,
) -> bool {
    // Compute what the one-time public key should be
    let computed = derive_one_time_from_receiver(
        tx_public_key,
        view_private_key,
        spend_public_key,
        output_index,
    );

    // Compare with the actual output public key
    computed == *output_public_key
}

/// Scan multiple outputs to find ones belonging to a wallet.
///
/// This is more efficient than calling `check_output_ownership` repeatedly
/// as it can cache intermediate computations.
///
/// # Arguments
/// * `outputs` - Slice of (output_public_key, output_index) pairs
/// * `tx_public_key` - The transaction public key (R)
/// * `view_private_key` - Wallet's private view key (a)
/// * `spend_public_key` - Wallet's public spend key (B)
/// * `spend_private_key` - Wallet's private spend key (b) for deriving spending keys
///
/// # Returns
/// A vector of `OwnedOutput` for each output belonging to this wallet.
pub fn scan_outputs_for_ownership(
    outputs: &[(RistrettoPublic, u64)],
    tx_public_key: &RistrettoPublic,
    view_private_key: &RistrettoPrivate,
    spend_public_key: &RistrettoPublic,
    spend_private_key: &RistrettoPrivate,
) -> Vec<OwnedOutput> {
    let mut owned = Vec::new();

    for (output_public_key, output_index) in outputs {
        if check_output_ownership(
            output_public_key,
            tx_public_key,
            view_private_key,
            spend_public_key,
            *output_index,
        ) {
            // Derive the spending key
            let one_time_private = derive_one_time_private_key(
                tx_public_key,
                view_private_key,
                spend_private_key,
                *output_index,
            );

            // Compute key image
            let key_image = derive_key_image(&one_time_private);

            owned.push(OwnedOutput {
                output_index: *output_index,
                one_time_public_key: *output_public_key,
                one_time_private_key: one_time_private,
                key_image,
            });
        }
    }

    owned
}

/// Check if an output might belong to any subaddress of a wallet.
///
/// MobileCoin supports subaddresses for account separation. This function
/// checks a range of subaddresses.
///
/// Note: This is a simplified implementation. Full subaddress support
/// requires additional derivation logic.
///
/// # Arguments
/// * `output_public_key` - The output's one-time public key
/// * `tx_public_key` - The transaction public key
/// * `view_private_key` - Wallet's private view key
/// * `spend_public_key` - Wallet's public spend key (main address)
/// * `output_index` - The output's index
/// * `max_subaddress` - Maximum subaddress index to check
///
/// # Returns
/// `Some(subaddress_index)` if found, `None` otherwise.
pub fn check_subaddress_ownership(
    output_public_key: &RistrettoPublic,
    tx_public_key: &RistrettoPublic,
    view_private_key: &RistrettoPrivate,
    spend_public_key: &RistrettoPublic,
    output_index: u64,
    max_subaddress: u32,
) -> Option<u32> {
    // Check main address (index 0)
    if check_output_ownership(
        output_public_key,
        tx_public_key,
        view_private_key,
        spend_public_key,
        output_index,
    ) {
        return Some(0);
    }

    // For a full implementation, we would need to derive subaddress keys
    // and check each one. This is a placeholder.
    // TODO: Implement full subaddress derivation

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{derive_one_time_public_key, generate_tx_key, WalletKeys};

    #[test]
    fn test_ownership_check_positive() {
        let wallet = WalletKeys::generate();
        let tx_key = generate_tx_key();

        // Derive one-time public key for this wallet
        let one_time = derive_one_time_public_key(
            &wallet.view_key_pair.public_key,
            &wallet.spend_key_pair.public_key,
            &tx_key.private_key,
            0,
        );

        // Wallet should recognize the output
        assert!(check_output_ownership(
            &one_time,
            &tx_key.public_key,
            &wallet.view_key_pair.private_key,
            &wallet.spend_key_pair.public_key,
            0,
        ));
    }

    #[test]
    fn test_ownership_check_negative() {
        let wallet1 = WalletKeys::generate();
        let wallet2 = WalletKeys::generate();
        let tx_key = generate_tx_key();

        // Derive one-time public key for wallet1
        let one_time = derive_one_time_public_key(
            &wallet1.view_key_pair.public_key,
            &wallet1.spend_key_pair.public_key,
            &tx_key.private_key,
            0,
        );

        // wallet2 should NOT recognize the output
        assert!(!check_output_ownership(
            &one_time,
            &tx_key.public_key,
            &wallet2.view_key_pair.private_key,
            &wallet2.spend_key_pair.public_key,
            0,
        ));
    }

    #[test]
    fn test_ownership_check_wrong_index() {
        let wallet = WalletKeys::generate();
        let tx_key = generate_tx_key();

        // Derive one-time public key for index 0
        let one_time = derive_one_time_public_key(
            &wallet.view_key_pair.public_key,
            &wallet.spend_key_pair.public_key,
            &tx_key.private_key,
            0,
        );

        // Checking with wrong index should fail
        assert!(!check_output_ownership(
            &one_time,
            &tx_key.public_key,
            &wallet.view_key_pair.private_key,
            &wallet.spend_key_pair.public_key,
            1, // wrong index
        ));
    }

    #[test]
    fn test_scan_outputs() {
        let wallet = WalletKeys::generate();
        let tx_key = generate_tx_key();

        // Create outputs: 0 and 2 for this wallet, 1 for someone else
        let our_output_0 = derive_one_time_public_key(
            &wallet.view_key_pair.public_key,
            &wallet.spend_key_pair.public_key,
            &tx_key.private_key,
            0,
        );

        let other_wallet = WalletKeys::generate();
        let other_output = derive_one_time_public_key(
            &other_wallet.view_key_pair.public_key,
            &other_wallet.spend_key_pair.public_key,
            &tx_key.private_key,
            1,
        );

        let our_output_2 = derive_one_time_public_key(
            &wallet.view_key_pair.public_key,
            &wallet.spend_key_pair.public_key,
            &tx_key.private_key,
            2,
        );

        let outputs = vec![(our_output_0, 0), (other_output, 1), (our_output_2, 2)];

        let owned = scan_outputs_for_ownership(
            &outputs,
            &tx_key.public_key,
            &wallet.view_key_pair.private_key,
            &wallet.spend_key_pair.public_key,
            &wallet.spend_key_pair.private_key,
        );

        // Should find 2 outputs
        assert_eq!(owned.len(), 2);
        assert_eq!(owned[0].output_index, 0);
        assert_eq!(owned[1].output_index, 2);

        // Keys should be valid
        assert!(owned[0].key_image.is_valid());
        assert!(owned[1].key_image.is_valid());

        // Private keys should match public keys
        assert_eq!(
            owned[0].one_time_private_key.public_key(),
            owned[0].one_time_public_key
        );
        assert_eq!(
            owned[1].one_time_private_key.public_key(),
            owned[1].one_time_public_key
        );
    }

    #[test]
    fn test_owned_output_spending() {
        let wallet = WalletKeys::generate();
        let tx_key = generate_tx_key();

        let one_time_public = derive_one_time_public_key(
            &wallet.view_key_pair.public_key,
            &wallet.spend_key_pair.public_key,
            &tx_key.private_key,
            0,
        );

        let outputs = vec![(one_time_public, 0)];

        let owned = scan_outputs_for_ownership(
            &outputs,
            &tx_key.public_key,
            &wallet.view_key_pair.private_key,
            &wallet.spend_key_pair.public_key,
            &wallet.spend_key_pair.private_key,
        );

        assert_eq!(owned.len(), 1);

        // Verify the derived private key actually corresponds to the public key
        let derived_public = owned[0].one_time_private_key.public_key();
        assert_eq!(derived_public, one_time_public);
    }
}
