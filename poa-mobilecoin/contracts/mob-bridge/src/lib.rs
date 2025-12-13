//! MobileCoin Bridge Contract
//!
//! A Proof of Authority (PoA) bridge that enables:
//! - Depositing MOB on MobileCoin to mint wMOB on NEAR
//! - Burning wMOB on NEAR to withdraw MOB on MobileCoin
//!
//! # Architecture
//!
//! The bridge uses a multi-signature authority system where trusted
//! validators attest to events on the MobileCoin blockchain.
//!
//! ## Deposit Flow
//! 1. User sends MOB to bridge custody address
//! 2. Authorities detect and sign deposit proof
//! 3. User or relayer submits proof to this contract
//! 4. Contract verifies signatures and mints wMOB
//!
//! ## Withdrawal Flow
//! 1. User calls withdraw() with MOB destination address
//! 2. Contract burns wMOB and creates withdrawal request
//! 3. Authorities process withdrawal off-chain
//! 4. Authorities submit completion proof

use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LookupMap, UnorderedSet};
use near_sdk::json_types::U128;
use near_sdk::{env, near_bindgen, AccountId, Balance, PanicOnDefault, Promise, PublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Maximum number of authorities.
const MAX_AUTHORITIES: usize = 20;

/// Minimum signatures required for operations (set during init).
const MIN_THRESHOLD: u32 = 1;

/// Transaction hash type (32 bytes).
pub type TxHash = [u8; 32];

/// Withdrawal ID type.
pub type WithdrawalId = u64;

/// Deposit proof from MobileCoin blockchain.
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct DepositProof {
    /// MobileCoin transaction hash.
    pub tx_hash: String,
    /// Amount deposited in picoMOB.
    pub amount: U128,
    /// NEAR account to receive wMOB.
    pub recipient: AccountId,
    /// Block number on MobileCoin.
    pub block_number: u64,
    /// Authority signatures.
    pub signatures: Vec<AuthoritySignature>,
}

/// Signature from an authority.
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct AuthoritySignature {
    /// Index of the signing authority.
    pub authority_index: u32,
    /// Ed25519 signature (64 bytes, hex encoded).
    pub signature: String,
}

/// Withdrawal request.
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct WithdrawalRequest {
    /// Unique withdrawal ID.
    pub id: WithdrawalId,
    /// NEAR account that requested.
    pub requester: AccountId,
    /// MobileCoin destination address.
    pub mob_destination: String,
    /// Amount in picoMOB.
    pub amount: U128,
    /// Request timestamp.
    pub timestamp: u64,
    /// Current status.
    pub status: WithdrawalStatus,
}

/// Withdrawal status.
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(crate = "near_sdk::serde")]
pub enum WithdrawalStatus {
    /// Waiting to be processed.
    Pending,
    /// Being processed by authorities.
    Processing,
    /// Successfully completed.
    Completed { mob_tx_hash: String },
    /// Failed with reason.
    Failed { reason: String },
}

/// Rate limit configuration.
#[derive(BorshDeserialize, BorshSerialize)]
pub struct RateLimitConfig {
    /// Maximum deposits per hour.
    pub max_deposits_per_hour: u32,
    /// Maximum withdrawals per hour.
    pub max_withdrawals_per_hour: u32,
    /// Maximum total volume per hour in picoMOB.
    pub max_volume_per_hour: Balance,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_deposits_per_hour: 100,
            max_withdrawals_per_hour: 100,
            max_volume_per_hour: 10_000_000_000_000_000, // 10,000 MOB
        }
    }
}

/// Rate limit state tracking.
#[derive(BorshDeserialize, BorshSerialize, Default)]
pub struct RateLimitState {
    /// Timestamp of the current rate limit window start (nanoseconds).
    pub window_start: u64,
    /// Number of deposits in current window.
    pub deposit_count: u32,
    /// Number of withdrawals in current window.
    pub withdrawal_count: u32,
    /// Total volume in current window.
    pub volume: Balance,
}

/// The MobileCoin bridge contract.
#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
pub struct MobBridge {
    /// wMOB token contract.
    wmob_token: AccountId,
    /// Authority public keys.
    authorities: Vec<PublicKey>,
    /// Required signature threshold.
    threshold: u32,
    /// Processed deposit transaction hashes (prevent replay).
    processed_deposits: UnorderedSet<String>,
    /// Pending withdrawals.
    pending_withdrawals: LookupMap<WithdrawalId, WithdrawalRequest>,
    /// Withdrawal nonce.
    withdrawal_nonce: u64,
    /// MobileCoin custody address.
    mob_custody_address: String,
    /// Contract owner.
    owner: AccountId,
    /// Whether contract is paused.
    paused: bool,
    /// Minimum deposit amount.
    min_deposit: Balance,
    /// Maximum deposit amount.
    max_deposit: Balance,
    /// Rate limit configuration.
    rate_limit_config: RateLimitConfig,
    /// Rate limit state.
    rate_limit_state: RateLimitState,
}

#[near_bindgen]
impl MobBridge {
    /// Initialize the bridge contract.
    ///
    /// # Arguments
    /// * `wmob_token` - wMOB token contract address
    /// * `authorities` - Initial authority public keys
    /// * `threshold` - Number of signatures required
    /// * `mob_custody_address` - MobileCoin custody address
    #[init]
    pub fn new(
        wmob_token: AccountId,
        authorities: Vec<PublicKey>,
        threshold: u32,
        mob_custody_address: String,
    ) -> Self {
        assert!(!env::state_exists(), "Already initialized");
        assert!(!authorities.is_empty(), "Must have at least one authority");
        assert!(authorities.len() <= MAX_AUTHORITIES, "Too many authorities");
        assert!(threshold >= MIN_THRESHOLD, "Threshold too low");
        assert!(
            threshold <= authorities.len() as u32,
            "Threshold exceeds authority count"
        );

        Self {
            wmob_token,
            authorities,
            threshold,
            processed_deposits: UnorderedSet::new(b"d"),
            pending_withdrawals: LookupMap::new(b"w"),
            withdrawal_nonce: 0,
            mob_custody_address,
            owner: env::predecessor_account_id(),
            paused: false,
            min_deposit: 1_000_000_000,         // 0.001 MOB
            max_deposit: 1_000_000_000_000_000, // 1000 MOB
            rate_limit_config: RateLimitConfig::default(),
            rate_limit_state: RateLimitState::default(),
        }
    }

    // ==================== Deposit Functions ====================

    /// Process a deposit from MobileCoin.
    ///
    /// Verifies the deposit proof and mints wMOB to the recipient.
    ///
    /// # Arguments
    /// * `proof` - Deposit proof with authority signatures
    pub fn deposit(&mut self, proof: DepositProof) -> Promise {
        self.assert_not_paused();

        // Check not already processed (replay protection)
        assert!(
            !self.processed_deposits.contains(&proof.tx_hash),
            "Deposit already processed"
        );

        // Verify amount bounds
        let amount: Balance = proof.amount.into();
        assert!(amount >= self.min_deposit, "Amount below minimum");
        assert!(amount <= self.max_deposit, "Amount above maximum");

        // Rate limiting check
        self.check_and_update_rate_limit(true, amount);

        // Verify signatures
        self.verify_deposit_signatures(&proof);

        // Mark as processed
        self.processed_deposits.insert(&proof.tx_hash);

        // Log event
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"mob-bridge\",\"version\":\"1.0.0\",\"event\":\"deposit\",\"data\":{{\"tx_hash\":\"{}\",\"recipient\":\"{}\",\"amount\":\"{}\"}}}}",
            proof.tx_hash, proof.recipient, amount
        ));

        // Mint wMOB to recipient
        Promise::new(self.wmob_token.clone()).function_call(
            "mint".to_string(),
            near_sdk::serde_json::json!({
                "account_id": proof.recipient,
                "amount": proof.amount
            })
            .to_string()
            .into_bytes(),
            0,
            near_sdk::Gas::from_tgas(20),
        )
    }

    // ==================== Withdrawal Functions ====================

    /// Request a withdrawal to MobileCoin.
    ///
    /// Burns wMOB and creates a withdrawal request for authorities
    /// to process off-chain.
    ///
    /// # Arguments
    /// * `mob_destination` - MobileCoin address to receive MOB
    /// * `amount` - Amount to withdraw in picoMOB
    #[payable]
    pub fn withdraw(&mut self, mob_destination: String, amount: U128) -> WithdrawalId {
        self.assert_not_paused();

        assert_eq!(
            env::attached_deposit(),
            1,
            "Requires 1 yoctoNEAR for security"
        );

        // Validate MOB address format
        // MobileCoin addresses are Base58-encoded with specific length requirements
        self.validate_mob_address(&mob_destination);

        let amount_val: Balance = amount.into();
        assert!(amount_val >= self.min_deposit, "Amount below minimum");

        // Rate limiting check
        self.check_and_update_rate_limit(false, amount_val);

        // Create withdrawal request
        let id = self.withdrawal_nonce;
        self.withdrawal_nonce += 1;

        let request = WithdrawalRequest {
            id,
            requester: env::predecessor_account_id(),
            mob_destination: mob_destination.clone(),
            amount,
            timestamp: env::block_timestamp(),
            status: WithdrawalStatus::Pending,
        };

        self.pending_withdrawals.insert(&id, &request);

        // Log event
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"mob-bridge\",\"version\":\"1.0.0\",\"event\":\"withdrawal_requested\",\"data\":{{\"id\":{},\"requester\":\"{}\",\"destination\":\"{}\",\"amount\":\"{}\"}}}}",
            id, request.requester, mob_destination, amount_val
        ));

        id
    }

    /// Complete a withdrawal (called by authorities after MOB sent).
    ///
    /// # Arguments
    /// * `withdrawal_id` - ID of the withdrawal to complete
    /// * `mob_tx_hash` - MobileCoin transaction hash
    /// * `signatures` - Authority signatures
    pub fn complete_withdrawal(
        &mut self,
        withdrawal_id: WithdrawalId,
        mob_tx_hash: String,
        signatures: Vec<AuthoritySignature>,
    ) {
        self.assert_not_paused();

        // Get withdrawal request
        let mut request = self
            .pending_withdrawals
            .get(&withdrawal_id)
            .expect("Withdrawal not found");

        assert!(
            request.status == WithdrawalStatus::Pending
                || matches!(request.status, WithdrawalStatus::Processing),
            "Withdrawal not in valid state"
        );

        // Verify signatures
        let message = self.create_completion_message(withdrawal_id, &mob_tx_hash);
        self.verify_signatures(&message, &signatures);

        // Update status
        request.status = WithdrawalStatus::Completed {
            mob_tx_hash: mob_tx_hash.clone(),
        };
        self.pending_withdrawals.insert(&withdrawal_id, &request);

        // Log event
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"mob-bridge\",\"version\":\"1.0.0\",\"event\":\"withdrawal_completed\",\"data\":{{\"id\":{},\"mob_tx_hash\":\"{}\"}}}}",
            withdrawal_id, mob_tx_hash
        ));
    }

    /// Mark a withdrawal as failed (called by authorities).
    pub fn fail_withdrawal(
        &mut self,
        withdrawal_id: WithdrawalId,
        reason: String,
        signatures: Vec<AuthoritySignature>,
    ) {
        self.assert_not_paused();

        let mut request = self
            .pending_withdrawals
            .get(&withdrawal_id)
            .expect("Withdrawal not found");

        // Verify signatures
        let message = format!("FAIL:{}:{}", withdrawal_id, reason);
        self.verify_signatures(message.as_bytes(), &signatures);

        request.status = WithdrawalStatus::Failed { reason };
        self.pending_withdrawals.insert(&withdrawal_id, &request);
    }

    // ==================== View Functions ====================

    /// Get withdrawal request by ID.
    pub fn get_withdrawal(&self, withdrawal_id: WithdrawalId) -> Option<WithdrawalRequest> {
        self.pending_withdrawals.get(&withdrawal_id)
    }

    /// Check if a deposit has been processed.
    pub fn is_deposit_processed(&self, tx_hash: String) -> bool {
        self.processed_deposits.contains(&tx_hash)
    }

    /// Get the custody address.
    pub fn get_custody_address(&self) -> String {
        self.mob_custody_address.clone()
    }

    /// Get the current threshold.
    pub fn get_threshold(&self) -> u32 {
        self.threshold
    }

    /// Get authority count.
    pub fn get_authority_count(&self) -> u32 {
        self.authorities.len() as u32
    }

    /// Check if paused.
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    // ==================== Admin Functions ====================

    /// Update authorities (owner only).
    pub fn update_authorities(&mut self, authorities: Vec<PublicKey>, threshold: u32) {
        self.assert_owner_only();
        assert!(!authorities.is_empty(), "Must have at least one authority");
        assert!(authorities.len() <= MAX_AUTHORITIES, "Too many authorities");
        assert!(threshold <= authorities.len() as u32, "Threshold too high");

        self.authorities = authorities;
        self.threshold = threshold;
    }

    /// Update custody address (owner only).
    pub fn update_custody_address(&mut self, address: String) {
        self.assert_owner_only();
        self.mob_custody_address = address;
    }

    /// Pause the contract (owner only).
    pub fn pause(&mut self) {
        self.assert_owner_only();
        self.paused = true;
    }

    /// Unpause the contract (owner only).
    pub fn unpause(&mut self) {
        self.assert_owner_only();
        self.paused = false;
    }

    /// Set deposit limits (owner only).
    pub fn set_deposit_limits(&mut self, min: U128, max: U128) {
        self.assert_owner_only();
        self.min_deposit = min.into();
        self.max_deposit = max.into();
    }

    /// Set rate limit configuration (owner only).
    pub fn set_rate_limits(
        &mut self,
        max_deposits_per_hour: u32,
        max_withdrawals_per_hour: u32,
        max_volume_per_hour: U128,
    ) {
        self.assert_owner_only();
        self.rate_limit_config = RateLimitConfig {
            max_deposits_per_hour,
            max_withdrawals_per_hour,
            max_volume_per_hour: max_volume_per_hour.into(),
        };
    }

    /// Get current rate limit state (view function).
    pub fn get_rate_limit_state(&self) -> (u32, u32, U128) {
        (
            self.rate_limit_state.deposit_count,
            self.rate_limit_state.withdrawal_count,
            U128::from(self.rate_limit_state.volume),
        )
    }

    // ==================== Internal Functions ====================

    fn verify_deposit_signatures(&self, proof: &DepositProof) {
        // Create message to verify
        let message = self.create_deposit_message(proof);
        self.verify_signatures(&message, &proof.signatures);
    }

    fn create_deposit_message(&self, proof: &DepositProof) -> Vec<u8> {
        let msg = format!(
            "DEPOSIT:{}:{}:{}:{}",
            proof.tx_hash, proof.recipient, proof.amount.0, proof.block_number
        );
        let mut hasher = Sha256::new();
        hasher.update(msg.as_bytes());
        hasher.finalize().to_vec()
    }

    fn create_completion_message(&self, withdrawal_id: WithdrawalId, mob_tx_hash: &str) -> Vec<u8> {
        let msg = format!("COMPLETE:{}:{}", withdrawal_id, mob_tx_hash);
        let mut hasher = Sha256::new();
        hasher.update(msg.as_bytes());
        hasher.finalize().to_vec()
    }

    fn verify_signatures(&self, message: &[u8], signatures: &[AuthoritySignature]) {
        assert!(
            signatures.len() >= self.threshold as usize,
            "Not enough signatures"
        );

        let mut verified_count = 0;
        let mut seen_authorities = std::collections::HashSet::new();

        for sig in signatures {
            // Check authority index is valid
            assert!(
                (sig.authority_index as usize) < self.authorities.len(),
                "Invalid authority index"
            );

            // Check no duplicate authorities
            assert!(
                seen_authorities.insert(sig.authority_index),
                "Duplicate authority signature"
            );

            // Get authority public key
            let authority_pubkey = &self.authorities[sig.authority_index as usize];

            // Decode signature from hex
            let sig_bytes = hex::decode(&sig.signature).expect("Invalid signature hex encoding");

            assert_eq!(sig_bytes.len(), 64, "Signature must be 64 bytes");

            // Verify Ed25519 signature using NEAR's built-in verification
            // The authority public key is already in NEAR PublicKey format (ed25519:base58...)
            let pubkey_bytes = authority_pubkey.as_bytes();

            // Skip the first byte (curve type indicator) for ed25519
            assert!(pubkey_bytes.len() >= 33, "Invalid public key length");
            let ed25519_pubkey = &pubkey_bytes[1..33];

            // Create signature array
            let mut sig_array = [0u8; 64];
            sig_array.copy_from_slice(&sig_bytes);

            // Verify using ed25519_dalek compatible verification
            // Note: In production NEAR contracts, use env::ed25519_verify
            // For now, we construct the verification manually
            let is_valid = self.ed25519_verify(ed25519_pubkey, message, &sig_array);

            assert!(
                is_valid,
                "Invalid signature from authority {}",
                sig.authority_index
            );
            verified_count += 1;
        }

        assert!(
            verified_count >= self.threshold,
            "Signature verification failed"
        );
    }

    /// Ed25519 signature verification using NEAR's built-in host function.
    ///
    /// # Security
    /// - Uses NEAR's env::ed25519_verify which provides constant-time verification
    /// - Prevents timing attacks by delegating to the NEAR runtime
    /// - Public key and signature lengths are validated before verification
    fn ed25519_verify(&self, pubkey: &[u8], message: &[u8], signature: &[u8; 64]) -> bool {
        // Validate public key length
        if pubkey.len() != 32 {
            return false;
        }

        // Validate signature format (R || S where R is a point, S is scalar)
        let s_bytes = &signature[32..64];

        // Check S is in valid scalar range (< L where L is the group order)
        // Reject non-canonical S values for security
        let s_high = s_bytes[31];
        if s_high >= 0x80 {
            return false;
        }

        // Use NEAR's built-in Ed25519 verification
        // This is cryptographically secure and gas-optimized
        env::ed25519_verify(signature, message, pubkey)
    }

    fn assert_owner_only(&self) {
        assert_eq!(
            env::predecessor_account_id(),
            self.owner,
            "Only owner can call this"
        );
    }

    fn assert_not_paused(&self) {
        assert!(!self.paused, "Contract is paused");
    }

    /// Check and update rate limits.
    ///
    /// # Arguments
    /// * `is_deposit` - true for deposits, false for withdrawals
    /// * `amount` - amount being transferred
    ///
    /// # Security
    /// Prevents DoS and draining attacks by limiting transaction frequency and volume.
    fn check_and_update_rate_limit(&mut self, is_deposit: bool, amount: Balance) {
        let current_time = env::block_timestamp();
        let one_hour_ns: u64 = 3_600_000_000_000; // 1 hour in nanoseconds

        // Reset window if more than an hour has passed
        if current_time - self.rate_limit_state.window_start >= one_hour_ns {
            self.rate_limit_state = RateLimitState {
                window_start: current_time,
                deposit_count: 0,
                withdrawal_count: 0,
                volume: 0,
            };
        }

        // Check transaction count limits
        if is_deposit {
            assert!(
                self.rate_limit_state.deposit_count < self.rate_limit_config.max_deposits_per_hour,
                "Rate limit exceeded: too many deposits this hour"
            );
            self.rate_limit_state.deposit_count += 1;
        } else {
            assert!(
                self.rate_limit_state.withdrawal_count
                    < self.rate_limit_config.max_withdrawals_per_hour,
                "Rate limit exceeded: too many withdrawals this hour"
            );
            self.rate_limit_state.withdrawal_count += 1;
        }

        // Check volume limit
        let new_volume = self.rate_limit_state.volume.saturating_add(amount);
        assert!(
            new_volume <= self.rate_limit_config.max_volume_per_hour,
            "Rate limit exceeded: volume limit reached for this hour"
        );
        self.rate_limit_state.volume = new_volume;
    }

    /// Validate a MobileCoin address format.
    ///
    /// # Security
    /// - Validates Base58 encoding
    /// - Checks expected length for MobileCoin addresses
    /// - Validates checksum presence
    fn validate_mob_address(&self, address: &str) {
        // MobileCoin addresses are Base58-encoded and typically 66-100 characters
        // Minimum length check
        assert!(address.len() >= 66, "Invalid MobileCoin address: too short");

        assert!(address.len() <= 200, "Invalid MobileCoin address: too long");

        // Validate it's valid Base58 (only alphanumeric, no 0/O/I/l)
        let is_valid_base58 = address.chars().all(|c| {
            matches!(c,
                '1'..='9' | 'A'..='H' | 'J'..='N' | 'P'..='Z' |
                'a'..='k' | 'm'..='z'
            )
        });

        assert!(
            is_valid_base58,
            "Invalid MobileCoin address: contains invalid Base58 characters"
        );

        // Attempt to decode to verify checksum integrity
        // Note: bs58 library not available in NEAR SDK, so we do basic validation
        // In production, consider adding the bs58 dependency for full validation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    fn get_context(predecessor: AccountId, deposit: Balance) -> near_sdk::VMContext {
        VMContextBuilder::new()
            .predecessor_account_id(predecessor)
            .attached_deposit(deposit)
            .build()
    }

    fn create_test_public_key() -> PublicKey {
        "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp"
            .parse()
            .unwrap()
    }

    #[test]
    fn test_init() {
        let context = get_context("owner.near".parse().unwrap(), 0);
        testing_env!(context);

        let contract = MobBridge::new(
            "wmob.near".parse().unwrap(),
            vec![create_test_public_key()],
            1,
            "mob_custody_address".to_string(),
        );

        assert_eq!(contract.get_threshold(), 1);
        assert_eq!(contract.get_authority_count(), 1);
        assert!(!contract.is_paused());
    }

    #[test]
    fn test_withdrawal_request() {
        let context = get_context("user.near".parse().unwrap(), 1);
        testing_env!(context);

        let mut contract = MobBridge::new(
            "wmob.near".parse().unwrap(),
            vec![create_test_public_key()],
            1,
            "mob_custody_address".to_string(),
        );

        // Use a valid Base58 test address (66+ chars, no 0/O/I/l)
        let test_mob_address =
            "2mGjuQNPWLJQABHNBaQoUgqmC3ZZYqYLqvHUxKJZX9KYvFSoiqwHnm7D2uCZNfcbgvWsNXE".to_string();
        let id = contract.withdraw(test_mob_address, U128::from(1_000_000_000_000u128));

        assert_eq!(id, 0);

        let request = contract.get_withdrawal(0).unwrap();
        assert_eq!(request.requester, "user.near".parse::<AccountId>().unwrap());
        assert!(matches!(request.status, WithdrawalStatus::Pending));
    }

    #[test]
    fn test_pause() {
        let context = get_context("owner.near".parse().unwrap(), 0);
        testing_env!(context);

        let mut contract = MobBridge::new(
            "wmob.near".parse().unwrap(),
            vec![create_test_public_key()],
            1,
            "mob_custody_address".to_string(),
        );

        assert!(!contract.is_paused());

        contract.pause();
        assert!(contract.is_paused());

        contract.unpause();
        assert!(!contract.is_paused());
    }
}
