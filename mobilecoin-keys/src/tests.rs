//! Integration tests for the mobilecoin-keys crate.

use crate::*;

#[test]
fn test_full_transaction_flow() {
    // 1. Recipient generates wallet
    let recipient_wallet = WalletKeys::generate();
    println!("Recipient wallet generated");

    // 2. Sender generates transaction key
    let tx_key = generate_tx_key();
    println!("Transaction key generated");

    // 3. Sender derives one-time public key for output
    let one_time_public = derive_one_time_public_key(
        &recipient_wallet.view_key_pair.public_key,
        &recipient_wallet.spend_key_pair.public_key,
        &tx_key.private_key,
        0,
    );
    println!(
        "One-time public key derived: {:?}",
        one_time_public.to_hex()
    );

    // 4. Recipient scans for output
    let is_ours = check_output_ownership(
        &one_time_public,
        &tx_key.public_key,
        &recipient_wallet.view_key_pair.private_key,
        &recipient_wallet.spend_key_pair.public_key,
        0,
    );
    assert!(is_ours, "Recipient should recognize the output");

    // 5. Recipient derives spending key
    let one_time_private = derive_one_time_private_key(
        &tx_key.public_key,
        &recipient_wallet.view_key_pair.private_key,
        &recipient_wallet.spend_key_pair.private_key,
        0,
    );

    // 6. Verify private key matches public key
    assert_eq!(
        one_time_private.public_key(),
        one_time_public,
        "Derived private key should match public key"
    );

    // 7. Derive key image for spending
    let key_image = derive_key_image(&one_time_private);
    assert!(key_image.is_valid(), "Key image should be valid");

    println!("Full transaction flow completed successfully");
}

#[test]
fn test_multiple_outputs_same_transaction() {
    let recipient_wallet = WalletKeys::generate();
    let tx_key = generate_tx_key();

    // Create 5 outputs in the same transaction
    let outputs: Vec<_> = (0..5)
        .map(|i| {
            let one_time = derive_one_time_public_key(
                &recipient_wallet.view_key_pair.public_key,
                &recipient_wallet.spend_key_pair.public_key,
                &tx_key.private_key,
                i,
            );
            (one_time, i)
        })
        .collect();

    // All outputs should be unique
    for i in 0..outputs.len() {
        for j in (i + 1)..outputs.len() {
            assert_ne!(
                outputs[i].0, outputs[j].0,
                "Output {} and {} should be different",
                i, j
            );
        }
    }

    // Scan all outputs
    let owned = scan_outputs_for_ownership(
        &outputs,
        &tx_key.public_key,
        &recipient_wallet.view_key_pair.private_key,
        &recipient_wallet.spend_key_pair.public_key,
        &recipient_wallet.spend_key_pair.private_key,
    );

    assert_eq!(owned.len(), 5, "Should find all 5 outputs");

    // Each should have unique key image
    for i in 0..owned.len() {
        for j in (i + 1)..owned.len() {
            assert_ne!(
                owned[i].key_image, owned[j].key_image,
                "Key images should be unique"
            );
        }
    }
}

#[test]
fn test_multi_recipient_transaction() {
    let recipient1 = WalletKeys::generate();
    let recipient2 = WalletKeys::generate();
    let recipient3 = WalletKeys::generate();
    let tx_key = generate_tx_key();

    // Create outputs for different recipients
    let output1 = derive_one_time_public_key(
        &recipient1.view_key_pair.public_key,
        &recipient1.spend_key_pair.public_key,
        &tx_key.private_key,
        0,
    );

    let output2 = derive_one_time_public_key(
        &recipient2.view_key_pair.public_key,
        &recipient2.spend_key_pair.public_key,
        &tx_key.private_key,
        1,
    );

    let output3 = derive_one_time_public_key(
        &recipient3.view_key_pair.public_key,
        &recipient3.spend_key_pair.public_key,
        &tx_key.private_key,
        2,
    );

    let all_outputs = vec![(output1, 0u64), (output2, 1u64), (output3, 2u64)];

    // Recipient1 should only find output 0
    let owned1 = scan_outputs_for_ownership(
        &all_outputs,
        &tx_key.public_key,
        &recipient1.view_key_pair.private_key,
        &recipient1.spend_key_pair.public_key,
        &recipient1.spend_key_pair.private_key,
    );
    assert_eq!(owned1.len(), 1);
    assert_eq!(owned1[0].output_index, 0);

    // Recipient2 should only find output 1
    let owned2 = scan_outputs_for_ownership(
        &all_outputs,
        &tx_key.public_key,
        &recipient2.view_key_pair.private_key,
        &recipient2.spend_key_pair.public_key,
        &recipient2.spend_key_pair.private_key,
    );
    assert_eq!(owned2.len(), 1);
    assert_eq!(owned2[0].output_index, 1);

    // Recipient3 should only find output 2
    let owned3 = scan_outputs_for_ownership(
        &all_outputs,
        &tx_key.public_key,
        &recipient3.view_key_pair.private_key,
        &recipient3.spend_key_pair.public_key,
        &recipient3.spend_key_pair.private_key,
    );
    assert_eq!(owned3.len(), 1);
    assert_eq!(owned3[0].output_index, 2);
}

#[test]
fn test_near_intents_settlement() {
    use mobilecoin_address::{MobAddress, MobNetwork, RistrettoPublic as AddrPublic};

    // Create a recipient address
    let recipient_wallet = WalletKeys::generate();
    let recipient_address = MobAddress::new(
        AddrPublic::new(*recipient_wallet.view_key_pair.public_key.as_bytes()),
        AddrPublic::new(*recipient_wallet.spend_key_pair.public_key.as_bytes()),
        MobNetwork::Mainnet,
    );

    let intent_id = "near-intent-swap-12345";

    // Generate settlement address
    let (settlement_key, tx_key) = generate_settlement_address(&recipient_address, intent_id);

    // Verify the settlement address
    assert!(verify_settlement_address(
        &settlement_key,
        &tx_key.public_key,
        &recipient_address,
        intent_id,
    ));

    // Recipient should be able to derive the spending key
    let one_time_private = derive_one_time_private_key(
        &tx_key.public_key,
        &recipient_wallet.view_key_pair.private_key,
        &recipient_wallet.spend_key_pair.private_key,
        0,
    );

    assert_eq!(one_time_private.public_key(), settlement_key);
}

#[test]
fn test_key_image_uniqueness() {
    let wallet = WalletKeys::generate();

    // Generate multiple outputs with different transaction keys
    let mut key_images = Vec::new();

    for _ in 0..10 {
        let tx_key = generate_tx_key();

        let one_time_private = derive_one_time_private_key(
            &tx_key.public_key,
            &wallet.view_key_pair.private_key,
            &wallet.spend_key_pair.private_key,
            0,
        );

        let key_image = derive_key_image(&one_time_private);
        key_images.push(key_image);
    }

    // All key images should be unique
    for i in 0..key_images.len() {
        for j in (i + 1)..key_images.len() {
            assert_ne!(
                key_images[i], key_images[j],
                "Key images {} and {} should be unique",
                i, j
            );
        }
    }
}

#[test]
fn test_serialization_roundtrip() {
    let public_key = RistrettoPrivate::generate().public_key();

    // Hex roundtrip
    let hex = public_key.to_hex();
    let recovered = RistrettoPublic::from_hex(&hex).unwrap();
    assert_eq!(public_key, recovered);

    // Bytes roundtrip
    let bytes = public_key.as_bytes();
    let recovered2 = RistrettoPublic::new(*bytes);
    assert_eq!(public_key, recovered2);
}

// ==================== Security Tests ====================

mod security_tests {
    use super::*;
    use crate::derivation::{derive_one_time_from_receiver_safe, derive_one_time_public_key_safe};

    /// Test that safe derivation functions properly handle invalid public keys.
    #[test]
    fn test_invalid_key_handling() {
        // Create an invalid public key (random bytes not on curve)
        // Most random 32-byte arrays are not valid Ristretto points
        let invalid_bytes = [0xFFu8; 32]; // All 0xFF is almost certainly not on curve
        let invalid_key = RistrettoPublic::new(invalid_bytes);

        // If the key happens to be valid, skip this test
        // (extremely unlikely for arbitrary bytes)
        if invalid_key.is_valid() {
            return; // Skip - we need an invalid key to test
        }

        // The safe derivation function should return an error
        let valid_key = RistrettoPrivate::generate().public_key();
        let tx_private = RistrettoPrivate::generate();

        let result = derive_one_time_public_key_safe(&invalid_key, &valid_key, &tx_private, 0);
        assert!(result.is_err(), "Should return error for invalid view key");

        let result2 = derive_one_time_public_key_safe(&valid_key, &invalid_key, &tx_private, 0);
        assert!(
            result2.is_err(),
            "Should return error for invalid spend key"
        );
    }

    /// Test that the standard derivation function handles invalid keys gracefully.
    #[test]
    fn test_derivation_with_invalid_key_does_not_panic() {
        // Create an invalid public key
        let invalid_bytes = [0u8; 32];
        let invalid_key = RistrettoPublic::new(invalid_bytes);
        let valid_key = RistrettoPrivate::generate().public_key();
        let tx_private = RistrettoPrivate::generate();

        // This should NOT panic, even with invalid input
        let result = derive_one_time_public_key(&invalid_key, &valid_key, &tx_private, 0);

        // The result should still be a valid-ish point (derived deterministically)
        // We just verify it doesn't crash
        let _ = result.to_hex();
    }

    /// Test private key randomness (statistical test).
    #[test]
    fn test_private_key_randomness() {
        // Generate 100 keys and check for uniqueness
        let keys: Vec<_> = (0..100).map(|_| RistrettoPrivate::generate()).collect();

        // All keys should be unique
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(
                    keys[i].to_bytes(),
                    keys[j].to_bytes(),
                    "Keys {} and {} should be different",
                    i,
                    j
                );
            }
        }

        // Basic entropy check: no two consecutive keys should have same first byte
        let mut same_first_byte_count = 0;
        for i in 0..(keys.len() - 1) {
            if keys[i].to_bytes()[0] == keys[i + 1].to_bytes()[0] {
                same_first_byte_count += 1;
            }
        }
        // With good randomness, this should be rare (< 10 times in 99 comparisons)
        assert!(
            same_first_byte_count < 10,
            "Too many keys with same first byte, possible RNG weakness"
        );
    }

    /// Test that key derivation is deterministic.
    #[test]
    fn test_derivation_determinism() {
        let wallet = WalletKeys::generate();
        let tx_key = generate_tx_key();

        // Derive the same key multiple times
        let key1 = derive_one_time_public_key(
            &wallet.view_key_pair.public_key,
            &wallet.spend_key_pair.public_key,
            &tx_key.private_key,
            5,
        );

        let key2 = derive_one_time_public_key(
            &wallet.view_key_pair.public_key,
            &wallet.spend_key_pair.public_key,
            &tx_key.private_key,
            5,
        );

        assert_eq!(key1, key2, "Derivation should be deterministic");
    }

    /// Test that different output indices produce different keys.
    #[test]
    fn test_output_index_separation() {
        let wallet = WalletKeys::generate();
        let tx_key = generate_tx_key();

        let keys: Vec<_> = (0..256)
            .map(|i| {
                derive_one_time_public_key(
                    &wallet.view_key_pair.public_key,
                    &wallet.spend_key_pair.public_key,
                    &tx_key.private_key,
                    i,
                )
            })
            .collect();

        // All keys should be unique
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(
                    keys[i], keys[j],
                    "Output indices {} and {} should produce different keys",
                    i, j
                );
            }
        }
    }

    /// Test that key image is unique per spending key.
    #[test]
    fn test_key_image_uniqueness_security() {
        let wallet = WalletKeys::generate();

        // Same output spent twice should produce same key image
        let tx_key = generate_tx_key();
        let one_time_private = derive_one_time_private_key(
            &tx_key.public_key,
            &wallet.view_key_pair.private_key,
            &wallet.spend_key_pair.private_key,
            0,
        );

        let key_image1 = derive_key_image(&one_time_private);
        let key_image2 = derive_key_image(&one_time_private);

        assert_eq!(
            key_image1, key_image2,
            "Same spending key should produce same key image"
        );
    }

    /// Test NEAR Intents settlement verification with wrong intent ID.
    #[test]
    fn test_settlement_wrong_intent_fails() {
        use mobilecoin_address::{MobAddress, MobNetwork, RistrettoPublic as AddrPublic};

        let recipient_wallet = WalletKeys::generate();
        let recipient_address = MobAddress::new(
            AddrPublic::new(*recipient_wallet.view_key_pair.public_key.as_bytes()),
            AddrPublic::new(*recipient_wallet.spend_key_pair.public_key.as_bytes()),
            MobNetwork::Mainnet,
        );

        let intent_id = "correct-intent-id";
        let wrong_intent_id = "wrong-intent-id";

        let (settlement_key, tx_key) = generate_settlement_address(&recipient_address, intent_id);

        // Verification with correct intent should succeed
        assert!(verify_settlement_address(
            &settlement_key,
            &tx_key.public_key,
            &recipient_address,
            intent_id,
        ));

        // Verification with wrong intent should fail
        assert!(!verify_settlement_address(
            &settlement_key,
            &tx_key.public_key,
            &recipient_address,
            wrong_intent_id,
        ));
    }

    /// Test that refund address is different from settlement address.
    #[test]
    fn test_refund_settlement_separation() {
        use mobilecoin_address::{MobAddress, MobNetwork, RistrettoPublic as AddrPublic};

        let wallet = WalletKeys::generate();
        let address = MobAddress::new(
            AddrPublic::new(*wallet.view_key_pair.public_key.as_bytes()),
            AddrPublic::new(*wallet.spend_key_pair.public_key.as_bytes()),
            MobNetwork::Mainnet,
        );

        let intent_id = "same-intent-id";

        let (settlement_key, settlement_tx) = generate_settlement_address(&address, intent_id);
        let (refund_key, refund_tx) = generate_refund_address(&address, intent_id);

        // Settlement and refund should have different keys
        assert_ne!(
            settlement_key, refund_key,
            "Settlement and refund keys must differ"
        );
        assert_ne!(
            settlement_tx.public_key, refund_tx.public_key,
            "Settlement and refund tx keys must differ"
        );
    }

    /// Test hex parsing with invalid input.
    #[test]
    fn test_invalid_hex_parsing() {
        // Invalid hex characters
        let result = RistrettoPublic::from_hex(
            "gg00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        );
        assert!(result.is_err(), "Invalid hex should fail");

        // Wrong length
        let result = RistrettoPublic::from_hex("00112233");
        assert!(result.is_err(), "Wrong length should fail");

        // Empty string
        let result = RistrettoPublic::from_hex("");
        assert!(result.is_err(), "Empty string should fail");
    }
}
