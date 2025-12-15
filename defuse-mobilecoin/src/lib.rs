//! NEAR Intents Verifier - MobileCoin Module
//!
//! This module extends the NEAR Intents verifier contract to support
//! MobileCoin intents, including:
//! - Address validation
//! - Signature verification
//! - Settlement routing
//! - Refund handling
//!
//! # Overview
//!
//! The verifier contract is the core of NEAR Intents. This module adds
//! MobileCoin-specific functionality while maintaining compatibility
//! with the existing intent system.

use near_sdk::json_types::U128;
use near_sdk::{env, near, AccountId, PanicOnDefault};

use mobilecoin_address::{validate_mob_address as validate_mob_addr, MobNetwork};
use mobilecoin_crypto::{verify_mob_signature, MobPublicKey, MobSignature};

/// Chain identifier for MobileCoin.
pub const MOB_CHAIN_ID: &str = "mobilecoin";

/// MobileCoin chain configuration.
#[near(serializers = [json, borsh])]
#[derive(Clone, Debug)]
pub struct MobChainConfig {
    /// wMOB token contract.
    pub wmob_token: AccountId,
    /// Bridge contract for withdrawals.
    pub bridge_contract: AccountId,
    /// Minimum swap amount (picoMOB).
    pub min_amount: u64,
    /// Maximum swap amount (picoMOB).
    pub max_amount: u64,
    /// Whether chain is active.
    pub active: bool,
}

/// MobileCoin intent structure.
#[near(serializers = [json, borsh])]
#[derive(Clone, Debug)]
pub struct MobIntent {
    /// Unique intent identifier.
    pub intent_id: String,
    /// Source asset (e.g., "MOB", "wMOB").
    pub source_asset: String,
    /// Source amount in smallest unit.
    pub source_amount: U128,
    /// Destination asset.
    pub dest_asset: String,
    /// Minimum destination amount.
    pub min_dest_amount: U128,
    /// Destination address (MOB Base58 or NEAR account).
    pub dest_address: String,
    /// Refund address (MOB Base58).
    pub refund_address: String,
    /// Deadline timestamp.
    pub deadline: u64,
    /// Signer's public key.
    pub signer_public_key: String, // Hex-encoded
}

/// Signed MobileCoin intent.
#[near(serializers = [json, borsh])]
#[derive(Clone, Debug)]
pub struct SignedMobIntent {
    /// The intent data.
    pub intent: MobIntent,
    /// Ed25519 signature (hex-encoded).
    pub signature: String,
}

/// Intent status.
#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq)]
pub enum IntentStatus {
    /// Pending resolution.
    Pending,
    /// Assigned to solver.
    Assigned { solver: AccountId },
    /// Successfully settled.
    Settled { tx_hash: String },
    /// Expired (past deadline).
    Expired,
    /// Refund in progress.
    Refunding,
    /// Refund completed.
    Refunded,
    /// Failed.
    Failed { reason: String },
}

/// Settlement types for MobileCoin.
#[near(serializers = [json, borsh])]
#[derive(Clone, Debug)]
pub enum SettlementType {
    /// MOB → wMOB (deposit flow).
    MobToWmob,
    /// wMOB → MOB (withdrawal flow).
    WmobToMob,
    /// wMOB → Other NEAR asset.
    WmobToOther,
    /// Other NEAR asset → wMOB.
    OtherToWmob,
}

/// MobileCoin settlement data.
#[near(serializers = [json, borsh])]
#[derive(Clone, Debug)]
pub struct MobSettlement {
    /// Type of settlement.
    pub settlement_type: SettlementType,
    /// Deposit proof (for MobToWmob).
    pub deposit_proof: Option<String>,
    /// wMOB amount involved.
    pub wmob_amount: U128,
    /// MOB transaction hash (for WmobToMob).
    pub mob_tx_hash: Option<String>,
}

/// Validation result for addresses.
#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct ValidationResult {
    /// Whether the validation passed.
    pub valid: bool,
    /// Error message if validation failed.
    pub error: Option<String>,
}

/// Error types for intent processing.
#[derive(Debug)]
pub enum IntentError {
    /// Invalid signature.
    InvalidSignature,
    /// Invalid address.
    InvalidAddress(String),
    /// Intent expired.
    Expired,
    /// Amount too low.
    AmountTooLow,
    /// Amount too high.
    AmountTooHigh,
    /// Chain not active.
    ChainNotActive,
    /// Intent not found.
    NotFound,
    /// Not refundable.
    NotRefundable,
    /// Invalid state.
    InvalidState,
}

/// The MobileCoin verifier module.
#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct MobVerifier {
    /// MobileCoin chain configuration.
    config: Option<MobChainConfig>,
    /// Owner account.
    owner: AccountId,
}

#[near]
impl MobVerifier {
    /// Initialize the MobileCoin verifier.
    #[init]
    pub fn new() -> Self {
        assert!(!env::state_exists(), "Already initialized");
        Self {
            config: None,
            owner: env::predecessor_account_id(),
        }
    }

    // ==================== Configuration ====================

    /// Register MobileCoin chain in verifier.
    pub fn register_mobilecoin_chain(
        &mut self,
        wmob_token: AccountId,
        bridge_contract: AccountId,
        min_amount: u64,
        max_amount: u64,
    ) {
        self.assert_owner_only();

        self.config = Some(MobChainConfig {
            wmob_token,
            bridge_contract,
            min_amount,
            max_amount,
            active: true,
        });

        env::log_str("MobileCoin chain registered");
    }

    /// Get MobileCoin configuration.
    pub fn get_mob_config(&self) -> Option<MobChainConfig> {
        self.config.clone()
    }

    // ==================== Address Validation ====================

    /// Validate a MobileCoin address.
    pub fn validate_mob_address(&self, address: String) -> bool {
        match validate_mob_addr(&address) {
            Ok(result) => result.is_valid,
            Err(_) => false,
        }
    }

    /// Parse and validate MOB address for settlement.
    /// Returns validation result or error message.
    pub fn validate_for_settlement(&self, address: String) -> ValidationResult {
        let validation = match validate_mob_addr(&address) {
            Ok(v) => v,
            Err(e) => {
                return ValidationResult {
                    valid: false,
                    error: Some(format!("{}", e)),
                }
            }
        };

        if !validation.is_valid {
            return ValidationResult {
                valid: false,
                error: Some(validation.messages.join(", ")),
            };
        }

        // Must be mainnet
        if validation.network != Some(MobNetwork::Mainnet) {
            return ValidationResult {
                valid: false,
                error: Some("Address must be mainnet".to_string()),
            };
        }

        ValidationResult {
            valid: true,
            error: None,
        }
    }

    // ==================== Signature Verification ====================

    /// Verify a MobileCoin intent signature.
    pub fn verify_intent_signature(&self, signed_intent: &SignedMobIntent) -> bool {
        // Parse public key
        let public_key = match MobPublicKey::from_hex(&signed_intent.intent.signer_public_key) {
            Ok(key) => key,
            Err(_) => return false,
        };

        // Parse signature
        let signature = match MobSignature::from_hex(&signed_intent.signature) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        // Create signable message
        let message = self.create_intent_message(&signed_intent.intent);

        // Verify
        verify_mob_signature(&message, &signature, &public_key).unwrap_or(false)
    }

    /// Create the message to sign for an intent.
    fn create_intent_message(&self, intent: &MobIntent) -> Vec<u8> {
        format!(
            "MobileCoin Intent v1\n\
            intent_id: {}\n\
            source_asset: {}\n\
            source_amount: {}\n\
            dest_asset: {}\n\
            min_dest_amount: {}\n\
            dest_address: {}\n\
            refund_address: {}\n\
            deadline: {}\n",
            intent.intent_id,
            intent.source_asset,
            intent.source_amount.0,
            intent.dest_asset,
            intent.min_dest_amount.0,
            intent.dest_address,
            intent.refund_address,
            intent.deadline
        )
        .into_bytes()
    }

    // ==================== Intent Processing ====================

    /// Process a MobileCoin swap intent.
    pub fn process_mob_intent(&mut self, signed_intent: SignedMobIntent) -> String {
        // Check chain is active
        let config = self
            .config
            .as_ref()
            .expect("MobileCoin chain not registered");
        assert!(config.active, "MobileCoin chain not active");

        // Verify signature
        assert!(
            self.verify_intent_signature(&signed_intent),
            "Invalid signature"
        );

        // Validate addresses
        if signed_intent.intent.dest_asset == "MOB" {
            assert!(
                signed_intent.intent.dest_address.len() <= 256,
                "Destination address too long"
            );
            assert!(
                self.validate_for_settlement(signed_intent.intent.dest_address.clone())
                    .valid,
                "Invalid destination address"
            );
        } else {
            // For non-MOB destinations, expect a NEAR account ID.
            signed_intent
                .intent
                .dest_address
                .parse::<AccountId>()
                .expect("Invalid NEAR destination account");
        }

        assert!(
            signed_intent.intent.refund_address.len() <= 256,
            "Refund address too long"
        );
        assert!(
            self.validate_for_settlement(signed_intent.intent.refund_address.clone())
                .valid,
            "Invalid refund address"
        );

        // Check deadline
        assert!(
            env::block_timestamp() / 1_000_000_000 < signed_intent.intent.deadline,
            "Intent expired"
        );

        // Validate amount
        let amount: u128 = signed_intent.intent.source_amount.0;
        assert!(amount >= config.min_amount as u128, "Amount too low");
        assert!(amount <= config.max_amount as u128, "Amount too high");

        // Emit event for solvers
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"near-intents\",\"version\":\"1.0.0\",\"event\":\"mob_intent\",\"data\":{{\"intent_id\":\"{}\"}}}}",
            signed_intent.intent.intent_id
        ));

        signed_intent.intent.intent_id
    }

    // ==================== Admin ====================

    /// Set chain active status.
    pub fn set_mob_active(&mut self, active: bool) {
        self.assert_owner_only();
        if let Some(ref mut config) = self.config {
            config.active = active;
        }
    }

    fn assert_owner_only(&self) {
        assert_eq!(env::predecessor_account_id(), self.owner, "Only owner");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    fn get_context(predecessor: AccountId) -> near_sdk::VMContext {
        VMContextBuilder::new()
            .predecessor_account_id(predecessor)
            .build()
    }

    #[test]
    fn test_init() {
        let context = get_context("owner.near".parse().unwrap());
        testing_env!(context);

        let contract = MobVerifier::new();
        assert!(contract.get_mob_config().is_none());
    }

    #[test]
    fn test_register_chain() {
        let context = get_context("owner.near".parse().unwrap());
        testing_env!(context);

        let mut contract = MobVerifier::new();
        contract.register_mobilecoin_chain(
            "wmob.near".parse().unwrap(),
            "bridge.near".parse().unwrap(),
            1_000_000_000,
            1_000_000_000_000_000,
        );

        let config = contract.get_mob_config().unwrap();
        assert!(config.active);
        assert_eq!(config.wmob_token, "wmob.near".parse::<AccountId>().unwrap());
    }
}
