//! Payload traits for NEAR Intents integration.

use crate::hash::create_swap_message;
use crate::{verify_mob_signature, CryptoError, MobPublicKey, MobSignature, MobSignedPayload};
use serde::{Deserialize, Serialize};

/// Trait for payloads that can be signed.
pub trait Payload: Sized {
    /// The signed payload type.
    type SignedPayload: SignedPayload<Payload = Self>;

    /// Verify that a signed payload has a valid signature.
    fn verify(&self, signed: &Self::SignedPayload) -> Result<bool, CryptoError>;

    /// Get the signable bytes for this payload.
    fn signable_bytes(&self) -> Vec<u8>;
}

/// Trait for signed payloads.
pub trait SignedPayload: Sized {
    /// The underlying payload type.
    type Payload: Payload<SignedPayload = Self>;

    /// Get the underlying payload.
    fn payload(&self) -> &Self::Payload;

    /// Get the signer's public key.
    fn signer(&self) -> &MobPublicKey;

    /// Get the signature.
    fn signature(&self) -> &MobSignature;
}

/// A MobileCoin intent payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobPayload {
    /// Unique intent identifier.
    pub intent_id: String,
    /// Source asset (e.g., "MOB", "wMOB").
    pub source_asset: String,
    /// Source amount in smallest unit (picoMOB for MOB).
    pub source_amount: u128,
    /// Destination asset.
    pub dest_asset: String,
    /// Minimum acceptable destination amount.
    pub min_dest_amount: u128,
    /// Destination address (MOB address or NEAR account).
    pub dest_address: String,
    /// Refund address (MOB address).
    pub refund_address: String,
    /// Unix timestamp deadline.
    pub deadline: u64,
}

impl MobPayload {
    /// Create a new MobileCoin intent payload.
    pub fn new(
        intent_id: String,
        source_asset: String,
        source_amount: u128,
        dest_asset: String,
        min_dest_amount: u128,
        dest_address: String,
        refund_address: String,
        deadline: u64,
    ) -> Self {
        Self {
            intent_id,
            source_asset,
            source_amount,
            dest_asset,
            min_dest_amount,
            dest_address,
            refund_address,
            deadline,
        }
    }

    /// Create a signed version of this payload.
    pub fn sign(&self, key_pair: &crate::MobKeyPair) -> SignedMobPayload {
        let signable = self.signable_bytes();
        let signature = key_pair.sign(&signable);
        let public_key = key_pair.public_key();

        SignedMobPayload {
            payload: self.clone(),
            signature,
            public_key,
        }
    }
}

impl Payload for MobPayload {
    type SignedPayload = SignedMobPayload;

    fn verify(&self, signed: &Self::SignedPayload) -> Result<bool, CryptoError> {
        let signable = self.signable_bytes();
        verify_mob_signature(&signable, &signed.signature, &signed.public_key)
    }

    fn signable_bytes(&self) -> Vec<u8> {
        create_swap_message(
            &self.intent_id,
            &self.source_asset,
            self.source_amount,
            &self.dest_asset,
            self.min_dest_amount,
            &self.dest_address,
            self.deadline,
        )
    }
}

/// A signed MobileCoin intent payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedMobPayload {
    /// The original payload.
    pub payload: MobPayload,
    /// The Ed25519 signature.
    pub signature: MobSignature,
    /// The signer's public key.
    pub public_key: MobPublicKey,
}

impl SignedMobPayload {
    /// Verify this signed payload.
    pub fn verify(&self) -> Result<bool, CryptoError> {
        self.payload.verify(self)
    }
}

impl SignedPayload for SignedMobPayload {
    type Payload = MobPayload;

    fn payload(&self) -> &Self::Payload {
        &self.payload
    }

    fn signer(&self) -> &MobPublicKey {
        &self.public_key
    }

    fn signature(&self) -> &MobSignature {
        &self.signature
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MobKeyPair;

    fn create_test_payload() -> MobPayload {
        MobPayload::new(
            "intent-123".to_string(),
            "MOB".to_string(),
            1_000_000_000_000, // 1 MOB in picoMOB
            "wMOB".to_string(),
            990_000_000_000, // 0.99 wMOB minimum
            "test.near".to_string(),
            "mob_refund_address".to_string(),
            1700000000,
        )
    }

    #[test]
    fn test_payload_sign_and_verify() {
        let keypair = MobKeyPair::generate();
        let payload = create_test_payload();

        let signed = payload.sign(&keypair);

        assert!(signed.verify().unwrap());
    }

    #[test]
    fn test_tampered_payload_fails() {
        let keypair = MobKeyPair::generate();
        let payload = create_test_payload();

        let mut signed = payload.sign(&keypair);

        // Tamper with the payload
        signed.payload.source_amount = 2_000_000_000_000;

        // Verification should fail
        assert!(!signed.verify().unwrap());
    }

    #[test]
    fn test_wrong_key_fails() {
        let keypair1 = MobKeyPair::generate();
        let keypair2 = MobKeyPair::generate();
        let payload = create_test_payload();

        let mut signed = payload.sign(&keypair1);

        // Replace public key with wrong one
        signed.public_key = keypair2.public_key();

        // Verification should fail
        assert!(!signed.verify().unwrap());
    }

    #[test]
    fn test_signable_bytes_deterministic() {
        let payload = create_test_payload();
        let bytes1 = payload.signable_bytes();
        let bytes2 = payload.signable_bytes();

        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn test_different_payloads_different_bytes() {
        let payload1 = create_test_payload();
        let mut payload2 = create_test_payload();
        payload2.intent_id = "intent-456".to_string();

        let bytes1 = payload1.signable_bytes();
        let bytes2 = payload2.signable_bytes();

        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_signed_payload_accessors() {
        let keypair = MobKeyPair::generate();
        let payload = create_test_payload();

        let signed = payload.sign(&keypair);

        assert_eq!(signed.payload().intent_id, "intent-123");
        assert_eq!(signed.signer(), &keypair.public_key());
        assert_eq!(signed.signature().as_bytes().len(), 64);
    }
}
