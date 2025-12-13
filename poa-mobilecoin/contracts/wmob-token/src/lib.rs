//! Wrapped MobileCoin (wMOB) Token Contract
//!
//! A NEP-141 compliant fungible token representing MobileCoin (MOB)
//! on the NEAR blockchain for use with NEAR Intents.
//!
//! # Overview
//!
//! This contract implements the NEP-141 standard with additional
//! functionality for the MobileCoin bridge:
//! - Minting (only by bridge contract)
//! - Burning (only by bridge contract)
//! - Standard transfers
//! - Balance queries
//!
//! # Security
//!
//! - Only the designated bridge contract can mint/burn tokens
//! - All standard NEP-141 transfer safety checks apply

use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::collections::LookupMap;
use near_sdk::json_types::U128;
use near_sdk::{env, near_bindgen, AccountId, Balance, PanicOnDefault, Promise, PromiseOrValue};
use serde::{Deserialize, Serialize};

/// Metadata for the wMOB token.
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct FungibleTokenMetadata {
    pub spec: String,
    pub name: String,
    pub symbol: String,
    pub icon: Option<String>,
    pub reference: Option<String>,
    pub reference_hash: Option<String>,
    pub decimals: u8,
}

impl Default for FungibleTokenMetadata {
    fn default() -> Self {
        Self {
            spec: "ft-1.0.0".to_string(),
            name: "Wrapped MobileCoin".to_string(),
            symbol: "wMOB".to_string(),
            icon: None,
            reference: None,
            reference_hash: None,
            decimals: 12, // MobileCoin uses 12 decimal places (picoMOB)
        }
    }
}

/// The wMOB token contract.
#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
pub struct WMobToken {
    /// Token balances by account.
    balances: LookupMap<AccountId, Balance>,
    /// Total supply of wMOB tokens.
    total_supply: Balance,
    /// The bridge contract that can mint/burn.
    bridge_contract: AccountId,
    /// Token metadata.
    metadata: FungibleTokenMetadata,
    /// Owner account for administrative functions.
    owner: AccountId,
    /// Whether the contract is paused.
    paused: bool,
}

#[near_bindgen]
impl WMobToken {
    /// Initialize the wMOB token contract.
    ///
    /// # Arguments
    /// * `bridge_contract` - Account ID of the MOB bridge contract
    /// * `owner` - Account ID of the contract owner
    #[init]
    pub fn new(bridge_contract: AccountId, owner: AccountId) -> Self {
        assert!(!env::state_exists(), "Already initialized");

        Self {
            balances: LookupMap::new(b"b"),
            total_supply: 0,
            bridge_contract,
            metadata: FungibleTokenMetadata::default(),
            owner,
            paused: false,
        }
    }

    // ==================== Bridge Functions ====================

    /// Mint new wMOB tokens (only callable by bridge).
    ///
    /// # Arguments
    /// * `account_id` - Account to receive tokens
    /// * `amount` - Amount to mint in picoMOB
    pub fn mint(&mut self, account_id: AccountId, amount: U128) {
        self.assert_not_paused();
        self.assert_bridge_only();

        let amount: Balance = amount.into();

        let current_balance = self.balances.get(&account_id).unwrap_or(0);
        self.balances.insert(&account_id, &(current_balance + amount));
        self.total_supply += amount;

        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"nep141\",\"version\":\"1.0.0\",\"event\":\"ft_mint\",\"data\":[{{\"owner_id\":\"{}\",\"amount\":\"{}\"}}]}}",
            account_id, amount
        ));
    }

    /// Burn wMOB tokens (only callable by bridge).
    ///
    /// # Arguments
    /// * `account_id` - Account to burn from
    /// * `amount` - Amount to burn in picoMOB
    pub fn burn(&mut self, account_id: AccountId, amount: U128) {
        self.assert_not_paused();
        self.assert_bridge_only();

        let amount: Balance = amount.into();

        let current_balance = self.balances.get(&account_id).unwrap_or(0);
        assert!(current_balance >= amount, "Insufficient balance to burn");

        self.balances.insert(&account_id, &(current_balance - amount));
        self.total_supply -= amount;

        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"nep141\",\"version\":\"1.0.0\",\"event\":\"ft_burn\",\"data\":[{{\"owner_id\":\"{}\",\"amount\":\"{}\"}}]}}",
            account_id, amount
        ));
    }

    // ==================== NEP-141 Core Functions ====================

    /// Transfer tokens to a receiver.
    ///
    /// # Arguments
    /// * `receiver_id` - Account to receive tokens
    /// * `amount` - Amount to transfer
    /// * `memo` - Optional memo
    #[payable]
    pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
        self.assert_not_paused();
        assert_eq!(
            env::attached_deposit(),
            1,
            "Requires attached deposit of exactly 1 yoctoNEAR"
        );

        let sender_id = env::predecessor_account_id();
        let amount: Balance = amount.into();

        self.internal_transfer(&sender_id, &receiver_id, amount, memo);
    }

    /// Transfer tokens and call a method on the receiver.
    ///
    /// # Arguments
    /// * `receiver_id` - Account to receive tokens
    /// * `amount` - Amount to transfer
    /// * `memo` - Optional memo
    /// * `msg` - Message to pass to receiver's ft_on_transfer
    #[payable]
    pub fn ft_transfer_call(
        &mut self,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
        msg: String,
    ) -> PromiseOrValue<U128> {
        self.assert_not_paused();
        assert_eq!(
            env::attached_deposit(),
            1,
            "Requires attached deposit of exactly 1 yoctoNEAR"
        );

        let sender_id = env::predecessor_account_id();
        let amount: Balance = amount.into();

        self.internal_transfer(&sender_id, &receiver_id, amount, memo);

        // Call ft_on_transfer on receiver
        Promise::new(receiver_id.clone())
            .function_call(
                "ft_on_transfer".to_string(),
                near_sdk::serde_json::json!({
                    "sender_id": sender_id,
                    "amount": U128::from(amount),
                    "msg": msg
                })
                .to_string()
                .into_bytes(),
                0,
                near_sdk::Gas::from_tgas(30),
            )
            .then(
                Promise::new(env::current_account_id()).function_call(
                    "ft_resolve_transfer".to_string(),
                    near_sdk::serde_json::json!({
                        "sender_id": sender_id,
                        "receiver_id": receiver_id,
                        "amount": U128::from(amount)
                    })
                    .to_string()
                    .into_bytes(),
                    0,
                    near_sdk::Gas::from_tgas(10),
                ),
            )
            .into()
    }

    /// Get the total supply of wMOB tokens.
    pub fn ft_total_supply(&self) -> U128 {
        U128::from(self.total_supply)
    }

    /// Get the balance of an account.
    pub fn ft_balance_of(&self, account_id: AccountId) -> U128 {
        U128::from(self.balances.get(&account_id).unwrap_or(0))
    }

    // ==================== NEP-145 Storage Functions ====================

    /// Register storage for an account (simplified version).
    #[payable]
    pub fn storage_deposit(&mut self, account_id: Option<AccountId>) -> StorageBalance {
        let account = account_id.unwrap_or_else(env::predecessor_account_id);
        let deposit = env::attached_deposit();
        let min_balance = self.storage_balance_bounds().min.0;

        assert!(deposit >= min_balance, "Deposit too small");

        // Initialize balance if not exists
        if self.balances.get(&account).is_none() {
            self.balances.insert(&account, &0);
        }

        StorageBalance {
            total: U128::from(min_balance),
            available: U128::from(0),
        }
    }

    /// Get storage balance bounds.
    pub fn storage_balance_bounds(&self) -> StorageBalanceBounds {
        // Minimal storage for one account entry
        let min = 125 * env::storage_byte_cost();
        StorageBalanceBounds {
            min: U128::from(min),
            max: Some(U128::from(min)),
        }
    }

    // ==================== Metadata Functions ====================

    /// Get token metadata.
    pub fn ft_metadata(&self) -> FungibleTokenMetadata {
        self.metadata.clone()
    }

    // ==================== Admin Functions ====================

    /// Update the bridge contract address (owner only).
    pub fn set_bridge_contract(&mut self, bridge_contract: AccountId) {
        self.assert_owner_only();
        self.bridge_contract = bridge_contract;
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

    /// Get the bridge contract address.
    pub fn get_bridge_contract(&self) -> AccountId {
        self.bridge_contract.clone()
    }

    /// Check if contract is paused.
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    // ==================== Internal Functions ====================

    fn internal_transfer(
        &mut self,
        sender_id: &AccountId,
        receiver_id: &AccountId,
        amount: Balance,
        memo: Option<String>,
    ) {
        assert_ne!(sender_id, receiver_id, "Sender and receiver cannot be the same");
        assert!(amount > 0, "Amount must be positive");

        let sender_balance = self.balances.get(sender_id).unwrap_or(0);
        assert!(sender_balance >= amount, "Insufficient balance");

        self.balances.insert(sender_id, &(sender_balance - amount));

        let receiver_balance = self.balances.get(receiver_id).unwrap_or(0);
        self.balances.insert(receiver_id, &(receiver_balance + amount));

        let memo_str = memo.unwrap_or_default();
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"nep141\",\"version\":\"1.0.0\",\"event\":\"ft_transfer\",\"data\":[{{\"old_owner_id\":\"{}\",\"new_owner_id\":\"{}\",\"amount\":\"{}\",\"memo\":\"{}\"}}]}}",
            sender_id, receiver_id, amount, memo_str
        ));
    }

    fn assert_bridge_only(&self) {
        assert_eq!(
            env::predecessor_account_id(),
            self.bridge_contract,
            "Only bridge can call this function"
        );
    }

    fn assert_owner_only(&self) {
        assert_eq!(
            env::predecessor_account_id(),
            self.owner,
            "Only owner can call this function"
        );
    }

    fn assert_not_paused(&self) {
        assert!(!self.paused, "Contract is paused");
    }

    /// Callback for ft_transfer_call to handle refunds.
    #[private]
    pub fn ft_resolve_transfer(
        &mut self,
        sender_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
    ) -> U128 {
        let amount: Balance = amount.into();

        // Check the promise result
        let unused_amount = match env::promise_result(0) {
            near_sdk::PromiseResult::Successful(value) => {
                if let Ok(unused) = near_sdk::serde_json::from_slice::<U128>(&value) {
                    std::cmp::min(amount, unused.0)
                } else {
                    0
                }
            }
            _ => amount, // If call failed, refund everything
        };

        if unused_amount > 0 {
            // Refund unused tokens
            let receiver_balance = self.balances.get(&receiver_id).unwrap_or(0);
            if receiver_balance >= unused_amount {
                self.balances.insert(&receiver_id, &(receiver_balance - unused_amount));

                let sender_balance = self.balances.get(&sender_id).unwrap_or(0);
                self.balances.insert(&sender_id, &(sender_balance + unused_amount));
            }
        }

        U128::from(amount - unused_amount)
    }
}

/// Storage balance for an account.
#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct StorageBalance {
    pub total: U128,
    pub available: U128,
}

/// Storage balance bounds.
#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct StorageBalanceBounds {
    pub min: U128,
    pub max: Option<U128>,
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

    #[test]
    fn test_init() {
        let context = get_context("owner.near".parse().unwrap(), 0);
        testing_env!(context);

        let contract = WMobToken::new(
            "bridge.near".parse().unwrap(),
            "owner.near".parse().unwrap(),
        );

        assert_eq!(contract.ft_total_supply().0, 0);
        assert_eq!(contract.get_bridge_contract(), "bridge.near".parse::<AccountId>().unwrap());
    }

    #[test]
    fn test_mint() {
        let context = get_context("bridge.near".parse().unwrap(), 0);
        testing_env!(context);

        let mut contract = WMobToken::new(
            "bridge.near".parse().unwrap(),
            "owner.near".parse().unwrap(),
        );

        contract.mint("alice.near".parse().unwrap(), U128::from(1_000_000_000_000u128));

        assert_eq!(contract.ft_total_supply().0, 1_000_000_000_000);
        assert_eq!(
            contract.ft_balance_of("alice.near".parse().unwrap()).0,
            1_000_000_000_000
        );
    }

    #[test]
    #[should_panic(expected = "Only bridge can call this function")]
    fn test_mint_unauthorized() {
        let context = get_context("hacker.near".parse().unwrap(), 0);
        testing_env!(context);

        let mut contract = WMobToken::new(
            "bridge.near".parse().unwrap(),
            "owner.near".parse().unwrap(),
        );

        contract.mint("alice.near".parse().unwrap(), U128::from(1_000u128));
    }
}
