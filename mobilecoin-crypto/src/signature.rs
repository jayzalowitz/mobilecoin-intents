//! Ed25519 signature verification for MobileCoin.

use crate::{CryptoError, MobKeyPair, MobPublicKey, MobSignature};
use ed25519_dalek::Verifier;
use sha2::{Digest, Sha512};

/// Domain separator prefix for MobileCoin intent signatures.
pub const MOB_INTENT_DOMAIN: &str = "MobileCoin Intent v1";

/// Verify an Ed25519 signature from MobileCoin.
///
/// # Arguments
/// * `message` - The message that was signed
/// * `signature` - The 64-byte Ed25519 signature
/// * `public_key` - The 32-byte public key of the signer
///
/// # Returns
/// * `Ok(true)` - Signature is valid
/// * `Ok(false)` - Signature is invalid (but verification completed)
/// * `Err(CryptoError)` - Verification could not be performed
///
/// # Example
/// ```rust
/// use mobilecoin_crypto::{verify_mob_signature, MobKeyPair};
///
/// let keypair = MobKeyPair::generate();
/// let message = b"Hello, MobileCoin!";
/// let signature = keypair.sign(message);
///
/// assert!(verify_mob_signature(message, &signature, &keypair.public_key()).unwrap());
/// ```
pub fn verify_mob_signature(
    message: &[u8],
    signature: &MobSignature,
    public_key: &MobPublicKey,
) -> Result<bool, CryptoError> {
    let verifying_key = public_key.to_verifying_key()?;
    let sig = signature.to_signature();

    match verifying_key.verify(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify an Ed25519 signature with domain separation.
///
/// This prepends a domain separator to the message before verification,
/// which prevents signature reuse across different contexts.
///
/// # Arguments
/// * `domain` - The domain separator string
/// * `message` - The message that was signed
/// * `signature` - The 64-byte Ed25519 signature
/// * `public_key` - The 32-byte public key of the signer
///
/// # Example
/// ```rust
/// use mobilecoin_crypto::{verify_mob_signature_with_domain, MobKeyPair, sign_message};
///
/// let keypair = MobKeyPair::generate();
/// let domain = "MyApp v1";
/// let message = b"Important message";
///
/// // Sign with domain
/// let signature = sign_message(domain, message, &keypair);
///
/// // Verify with same domain
/// assert!(verify_mob_signature_with_domain(domain, message, &signature, &keypair.public_key()).unwrap());
/// ```
pub fn verify_mob_signature_with_domain(
    domain: &str,
    message: &[u8],
    signature: &MobSignature,
    public_key: &MobPublicKey,
) -> Result<bool, CryptoError> {
    let domain_message = create_domain_message(domain, message);
    verify_mob_signature(&domain_message, signature, public_key)
}

/// Sign a message with domain separation.
///
/// # Arguments
/// * `domain` - The domain separator string
/// * `message` - The message to sign
/// * `key_pair` - The signing key pair
///
/// # Returns
/// The Ed25519 signature over the domain-prefixed message.
pub fn sign_message(domain: &str, message: &[u8], key_pair: &MobKeyPair) -> MobSignature {
    let domain_message = create_domain_message(domain, message);
    key_pair.sign(&domain_message)
}

/// Create a domain-prefixed message for signing or verification.
fn create_domain_message(domain: &str, message: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(domain.len() + 1 + message.len());
    result.extend_from_slice(domain.as_bytes());
    result.push(b'\n');
    result.extend_from_slice(message);
    result
}

/// Hash a message using SHA-512 (used internally by Ed25519).
///
/// This can be used to create message digests before signing.
pub fn hash_message_sha512(message: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(message);
    let result = hasher.finalize();
    let mut output = [0u8; 64];
    output.copy_from_slice(&result);
    output
}

/// Verify multiple signatures in batch.
///
/// This is more efficient than verifying each signature individually.
///
/// # Arguments
/// * `items` - Slice of (message, signature, public_key) tuples
///
/// # Returns
/// * `Ok(())` - All signatures are valid
/// * `Err(CryptoError)` - At least one signature is invalid
pub fn verify_batch(items: &[(&[u8], &MobSignature, &MobPublicKey)]) -> Result<(), CryptoError> {
    for (message, signature, public_key) in items {
        if !verify_mob_signature(message, signature, public_key)? {
            return Err(CryptoError::VerificationFailed);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let keypair = MobKeyPair::generate();
        let message = b"Hello, MobileCoin!";

        let signature = keypair.sign(message);
        let result = verify_mob_signature(message, &signature, &keypair.public_key());

        assert!(result.unwrap());
    }

    #[test]
    fn test_wrong_message_fails() {
        let keypair = MobKeyPair::generate();
        let message = b"Hello, MobileCoin!";
        let wrong_message = b"Hello, World!";

        let signature = keypair.sign(message);
        let result = verify_mob_signature(wrong_message, &signature, &keypair.public_key());

        assert!(!result.unwrap());
    }

    #[test]
    fn test_wrong_public_key_fails() {
        let keypair1 = MobKeyPair::generate();
        let keypair2 = MobKeyPair::generate();
        let message = b"Hello, MobileCoin!";

        let signature = keypair1.sign(message);
        let result = verify_mob_signature(message, &signature, &keypair2.public_key());

        assert!(!result.unwrap());
    }

    #[test]
    fn test_domain_separation() {
        let keypair = MobKeyPair::generate();
        let message = b"Important message";
        let domain1 = "App1";
        let domain2 = "App2";

        // Sign with domain1
        let signature = sign_message(domain1, message, &keypair);

        // Should verify with same domain
        assert!(verify_mob_signature_with_domain(
            domain1,
            message,
            &signature,
            &keypair.public_key()
        )
        .unwrap());

        // Should fail with different domain
        assert!(!verify_mob_signature_with_domain(
            domain2,
            message,
            &signature,
            &keypair.public_key()
        )
        .unwrap());
    }

    #[test]
    fn test_batch_verification() {
        let keypair1 = MobKeyPair::generate();
        let keypair2 = MobKeyPair::generate();

        let msg1 = b"Message 1";
        let msg2 = b"Message 2";

        let sig1 = keypair1.sign(msg1);
        let sig2 = keypair2.sign(msg2);

        let pk1 = keypair1.public_key();
        let pk2 = keypair2.public_key();

        let items: Vec<(&[u8], &MobSignature, &MobPublicKey)> =
            vec![(msg1, &sig1, &pk1), (msg2, &sig2, &pk2)];

        assert!(verify_batch(&items).is_ok());
    }

    #[test]
    fn test_batch_verification_fails_on_invalid() {
        let keypair1 = MobKeyPair::generate();
        let keypair2 = MobKeyPair::generate();

        let msg1 = b"Message 1";
        let msg2 = b"Message 2";

        let sig1 = keypair1.sign(msg1);
        let sig2 = keypair2.sign(msg2);

        let pk1 = keypair1.public_key();

        // Use wrong public key for second item
        let items: Vec<(&[u8], &MobSignature, &MobPublicKey)> = vec![
            (msg1, &sig1, &pk1),
            (msg2, &sig2, &pk1), // Wrong key!
        ];

        assert!(verify_batch(&items).is_err());
    }

    #[test]
    fn test_empty_message() {
        let keypair = MobKeyPair::generate();
        let message: &[u8] = b"";

        let signature = keypair.sign(message);
        assert!(verify_mob_signature(message, &signature, &keypair.public_key()).unwrap());
    }

    #[test]
    fn test_large_message() {
        let keypair = MobKeyPair::generate();
        let message = vec![0xABu8; 10_000];

        let signature = keypair.sign(&message);
        assert!(verify_mob_signature(&message, &signature, &keypair.public_key()).unwrap());
    }

    // RFC 8032 Test Vector
    #[test]
    fn test_rfc8032_test_vector_1() {
        // Test vector from RFC 8032 Section 7.1
        let secret_key_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        let public_key_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let message_hex = "";
        let signature_hex = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

        let mut secret_bytes = [0u8; 32];
        hex::decode_to_slice(secret_key_hex, &mut secret_bytes).unwrap();
        let keypair = MobKeyPair::from_secret_key(&secret_bytes);

        let public_key = MobPublicKey::from_hex(public_key_hex).unwrap();
        let expected_signature = MobSignature::from_hex(signature_hex).unwrap();
        let message = hex::decode(message_hex).unwrap();

        // Verify our keypair produces the expected public key
        assert_eq!(keypair.public_key(), public_key);

        // Verify the test vector signature
        assert!(verify_mob_signature(&message, &expected_signature, &public_key).unwrap());

        // Verify our signature matches
        let our_signature = keypair.sign(&message);
        assert_eq!(our_signature, expected_signature);
    }
}
