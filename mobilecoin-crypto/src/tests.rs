//! Integration tests for the mobilecoin-crypto crate.

use crate::*;

#[test]
fn test_full_signing_flow() {
    // Generate key pair
    let keypair = MobKeyPair::generate();
    let public_key = keypair.public_key();

    // Create payload
    let payload = MobPayload::new(
        "test-intent-001".to_string(),
        "MOB".to_string(),
        5_000_000_000_000, // 5 MOB
        "USDC".to_string(),
        4_500_000, // 4.5 USDC (6 decimals)
        "user.near".to_string(),
        "mob_refund_addr".to_string(),
        1700000000,
    );

    // Sign the payload
    let signed = payload.sign(&keypair);

    // Verify signature
    assert!(signed.verify().unwrap());

    // Verify using raw signature verification
    let signable = payload.signable_bytes();
    assert!(verify_mob_signature(&signable, &signed.signature, &public_key).unwrap());
}

#[test]
fn test_domain_separated_signing() {
    let keypair = MobKeyPair::generate();
    let message = b"Important intent data";

    // Sign with domain
    let signature = sign_message(MOB_INTENT_DOMAIN, message, &keypair);

    // Verify with same domain
    assert!(verify_mob_signature_with_domain(
        MOB_INTENT_DOMAIN,
        message,
        &signature,
        &keypair.public_key()
    )
    .unwrap());

    // Verify without domain fails (different message)
    assert!(!verify_mob_signature(message, &signature, &keypair.public_key()).unwrap());
}

#[test]
fn test_message_hashing() {
    let intent_id = "intent-789";
    let action = "swap";
    let params = br#"{"amount": 1000000}"#;

    let message = create_signable_message(intent_id, action, params);

    // Message should be deterministic
    let message2 = create_signable_message(intent_id, action, params);
    assert_eq!(message, message2);

    // Different inputs should produce different messages
    let different_message = create_signable_message("different-id", action, params);
    assert_ne!(message, different_message);
}

#[test]
fn test_key_serialization() {
    let keypair = MobKeyPair::generate();
    let public_key = keypair.public_key();

    // Serialize to hex
    let hex_key = public_key.to_hex();

    // Deserialize
    let recovered = MobPublicKey::from_hex(&hex_key).unwrap();

    assert_eq!(public_key, recovered);
}

#[test]
fn test_signature_serialization() {
    let keypair = MobKeyPair::generate();
    let signature = keypair.sign(b"test");

    // Serialize to hex
    let hex_sig = signature.to_hex();

    // Deserialize
    let recovered = MobSignature::from_hex(&hex_sig).unwrap();

    assert_eq!(signature, recovered);
}

#[test]
fn test_signed_payload_serialization() {
    let keypair = MobKeyPair::generate();
    let payload = MobPayload::new(
        "serialization-test".to_string(),
        "MOB".to_string(),
        1_000_000_000_000,
        "wMOB".to_string(),
        990_000_000_000,
        "dest.near".to_string(),
        "refund_addr".to_string(),
        1700000000,
    );

    let signed = payload.sign(&keypair);

    // Serialize to JSON
    let json = serde_json::to_string(&signed).unwrap();

    // Deserialize
    let recovered: SignedMobPayload = serde_json::from_str(&json).unwrap();

    // Verification should still work
    assert!(recovered.verify().unwrap());

    // All fields should match
    assert_eq!(signed.payload.intent_id, recovered.payload.intent_id);
    assert_eq!(
        signed.payload.source_amount,
        recovered.payload.source_amount
    );
    assert_eq!(signed.public_key, recovered.public_key);
    assert_eq!(signed.signature, recovered.signature);
}

#[test]
fn test_multiple_signers() {
    let keypair1 = MobKeyPair::generate();
    let keypair2 = MobKeyPair::generate();
    let keypair3 = MobKeyPair::generate();

    let message = b"Multi-signature test";

    let sig1 = keypair1.sign(message);
    let sig2 = keypair2.sign(message);
    let sig3 = keypair3.sign(message);

    // Each signature should verify with its own key
    assert!(verify_mob_signature(message, &sig1, &keypair1.public_key()).unwrap());
    assert!(verify_mob_signature(message, &sig2, &keypair2.public_key()).unwrap());
    assert!(verify_mob_signature(message, &sig3, &keypair3.public_key()).unwrap());

    // Cross-verification should fail
    assert!(!verify_mob_signature(message, &sig1, &keypair2.public_key()).unwrap());
    assert!(!verify_mob_signature(message, &sig2, &keypair3.public_key()).unwrap());
    assert!(!verify_mob_signature(message, &sig3, &keypair1.public_key()).unwrap());
}

#[test]
fn test_key_restoration_from_secret() {
    let keypair1 = MobKeyPair::generate();
    let secret = keypair1.secret_key_bytes();

    // Restore keypair from secret
    let keypair2 = MobKeyPair::from_secret_key(&secret);

    // Public keys should match
    assert_eq!(keypair1.public_key(), keypair2.public_key());

    // Signatures should be identical for same message
    let message = b"Restoration test";
    let sig1 = keypair1.sign(message);
    let sig2 = keypair2.sign(message);

    assert_eq!(sig1, sig2);
}

#[test]
fn test_error_handling() {
    // Invalid hex for public key
    let result = MobPublicKey::from_hex("not_hex");
    assert!(result.is_err());

    // Wrong length for public key
    let result = MobPublicKey::from_hex("0102030405");
    assert!(result.is_err());

    // Invalid hex for signature
    let result = MobSignature::from_hex("not_hex");
    assert!(result.is_err());

    // Wrong length for signature
    let result = MobSignature::from_hex("0102030405");
    assert!(result.is_err());
}
