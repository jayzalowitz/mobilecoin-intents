---
layout: default
title: API Reference
---

# API Reference

This page provides an overview of the public APIs in MobileCoin Intents.

## Modules

### mobilecoin-crypto

Cryptographic primitives for MobileCoin signature verification.

#### Types

```rust
/// 32-byte Ed25519 public key
pub struct MobPublicKey([u8; 32]);

/// 64-byte Ed25519 signature
pub struct MobSignature([u8; 64]);

/// Signing key pair
pub struct MobKeyPair {
    secret: ed25519_dalek::SigningKey,
    public: MobPublicKey,
}

/// Signed payload container
pub struct MobSignedPayload {
    pub payload: Vec<u8>,
    pub signature: MobSignature,
    pub public_key: MobPublicKey,
}
```

#### Functions

```rust
/// Verify an Ed25519 signature
pub fn verify_mob_signature(
    public_key: &MobPublicKey,
    message: &[u8],
    signature: &MobSignature,
) -> Result<bool, CryptoError>;

/// Verify with domain separation
pub fn verify_mob_signature_with_domain(
    public_key: &MobPublicKey,
    domain: &str,
    message: &[u8],
    signature: &MobSignature,
) -> Result<bool, CryptoError>;

/// Batch verification (more efficient)
pub fn verify_batch(
    items: &[(MobPublicKey, Vec<u8>, MobSignature)],
) -> Result<bool, CryptoError>;

/// SHA-512 hash
pub fn hash_message_sha512(message: &[u8]) -> [u8; 64];
```

---

### mobilecoin-address

MobileCoin address parsing and validation.

#### Types

```rust
/// Full MobileCoin address
pub struct MobAddress {
    view_public_key: RistrettoPublic,
    spend_public_key: RistrettoPublic,
    fog_info: Option<FogInfo>,
    network: Network,
}

/// Network identifier
pub enum Network {
    Mainnet,
    Testnet,
}

/// Fog metadata
pub struct FogInfo {
    report_url: String,
    report_id: String,
    authority_spki: Vec<u8>,
}
```

#### Methods

```rust
impl MobAddress {
    /// Parse from Base58Check string
    pub fn from_str(s: &str) -> Result<Self, AddressError>;

    /// Serialize to Base58Check
    pub fn to_string(&self) -> String;

    /// Get view public key
    pub fn view_public_key(&self) -> &RistrettoPublic;

    /// Get spend public key
    pub fn spend_public_key(&self) -> &RistrettoPublic;

    /// Check if mainnet address
    pub fn is_mainnet(&self) -> bool;

    /// Check if testnet address
    pub fn is_testnet(&self) -> bool;

    /// Get fog info if present
    pub fn fog_info(&self) -> Option<&FogInfo>;

    /// Convert to NEAR-compatible format
    pub fn to_near_string(&self) -> String;
}
```

---

### mobilecoin-keys

CryptoNote stealth address implementation.

#### Types

```rust
/// Wallet key pairs (view + spend)
pub struct WalletKeys {
    view_private: RistrettoPrivate,
    view_public: RistrettoPublic,
    spend_private: RistrettoPrivate,
    spend_public: RistrettoPublic,
}

/// Transaction key for one-time addresses
pub struct TxKey {
    private: RistrettoPrivate,
    public: RistrettoPublic,
}

/// Ristretto point (public key)
pub struct RistrettoPublic(CompressedRistretto);

/// Ristretto scalar (private key)
pub struct RistrettoPrivate(Scalar);
```

#### Functions

```rust
/// Derive one-time public key (stealth address)
/// P = Hs(r*A)*G + B
pub fn derive_one_time_public_key(
    view_public: &RistrettoPublic,
    spend_public: &RistrettoPublic,
    tx_public_key: &RistrettoPublic,
    output_index: u64,
) -> Result<RistrettoPublic, KeyError>;

/// Derive matching private key
/// x = Hs(a*R) + b
pub fn derive_one_time_private_key(
    view_private: &RistrettoPrivate,
    spend_private: &RistrettoPrivate,
    tx_public_key: &RistrettoPublic,
    output_index: u64,
) -> Result<RistrettoPrivate, KeyError>;

/// Check if output belongs to wallet
pub fn check_output_ownership(
    wallet: &WalletKeys,
    tx_public_key: &RistrettoPublic,
    output_public_key: &RistrettoPublic,
    output_index: u64,
) -> bool;

/// Derive key image for double-spend prevention
pub fn derive_key_image(
    one_time_private: &RistrettoPrivate,
) -> RistrettoPublic;

/// Generate settlement address for NEAR Intents
pub fn generate_settlement_address(
    wallet: &WalletKeys,
    intent_id: &str,
) -> Result<(RistrettoPublic, TxKey), KeyError>;

/// Verify settlement address
pub fn verify_settlement_address(
    wallet: &WalletKeys,
    address: &RistrettoPublic,
    tx_key: &TxKey,
    intent_id: &str,
) -> bool;
```

---

### defuse-mobilecoin (NEAR Contract)

NEAR smart contract for intent verification.

#### Types

```rust
/// MobileCoin swap intent
pub struct MobIntent {
    pub intent_id: String,
    pub source_asset: String,
    pub source_amount: U128,
    pub destination_asset: String,
    pub min_destination_amount: U128,
    pub deadline: u64,
    pub user_mob_address: Option<String>,
    pub user_near_account: AccountId,
}

/// Signed intent
pub struct SignedMobIntent {
    pub intent: MobIntent,
    pub signature: String,  // hex-encoded
    pub public_key: String, // hex-encoded
}

/// Intent status
pub enum IntentStatus {
    Pending,
    Assigned { solver_id: String },
    Settled,
    Expired,
    Cancelled,
}

/// Settlement type
pub enum SettlementType {
    MobToWmob,   // Deposit
    WmobToMob,   // Withdrawal
    WmobToOther, // Cross-asset
    OtherToWmob, // Reverse cross-asset
}
```

#### Methods

```rust
/// Submit a new intent
#[payable]
pub fn submit_intent(&mut self, signed_intent: SignedMobIntent) -> String;

/// Get intent status
pub fn get_intent(&self, intent_id: String) -> Option<IntentStatus>;

/// Cancel an intent (user only)
pub fn cancel_intent(&mut self, intent_id: String);

/// Submit quote (solver only)
pub fn submit_quote(&mut self, intent_id: String, quote: Quote);

/// Settle an intent
pub fn settle(&mut self, intent_id: String, settlement: Settlement);
```

---

### mob-bridge (NEAR Contract)

Proof-of-Authority bridge contract.

#### Types

```rust
/// Deposit proof from authorities
pub struct DepositProof {
    pub tx_hash: String,
    pub amount: U128,
    pub recipient: AccountId,
    pub signatures: Vec<AuthoritySignature>,
}

/// Withdrawal request
pub struct WithdrawalRequest {
    pub id: u64,
    pub amount: U128,
    pub mob_address: String,
    pub requester: AccountId,
    pub status: WithdrawalStatus,
}

/// Authority signature
pub struct AuthoritySignature {
    pub authority: AccountId,
    pub signature: String,
}

/// Rate limit configuration
pub struct RateLimitConfig {
    pub max_deposits_per_hour: u32,
    pub max_withdrawals_per_hour: u32,
    pub max_volume_per_hour: U128,
    pub min_amount: U128,
    pub max_amount: U128,
}
```

#### Methods

```rust
/// Initialize bridge
#[init]
pub fn new(
    token_account_id: AccountId,
    authority_threshold: u8,
    authorities: Vec<AccountId>,
) -> Self;

/// Submit deposit proof (mints wMOB)
pub fn submit_deposit_proof(&mut self, proof: DepositProof);

/// Request withdrawal (burns wMOB)
#[payable]
pub fn request_withdrawal(
    &mut self,
    amount: U128,
    mob_address: String,
) -> u64;

/// Process withdrawal (authorities)
pub fn process_withdrawal(
    &mut self,
    withdrawal_id: u64,
    signatures: Vec<AuthoritySignature>,
);

/// Add authority (admin)
pub fn add_authority(&mut self, account_id: AccountId);

/// Remove authority (admin)
pub fn remove_authority(&mut self, account_id: AccountId);

/// Pause bridge (admin)
pub fn pause(&mut self);

/// Unpause bridge (admin)
pub fn unpause(&mut self);
```

---

### wmob-token (NEAR Contract)

NEP-141 wrapped MOB token.

#### Metadata

```json
{
  "name": "Wrapped MobileCoin",
  "symbol": "wMOB",
  "decimals": 12
}
```

#### Methods (NEP-141 Standard)

```rust
/// Transfer tokens
#[payable]
pub fn ft_transfer(
    &mut self,
    receiver_id: AccountId,
    amount: U128,
    memo: Option<String>,
);

/// Transfer with callback
#[payable]
pub fn ft_transfer_call(
    &mut self,
    receiver_id: AccountId,
    amount: U128,
    memo: Option<String>,
    msg: String,
) -> PromiseOrValue<U128>;

/// Get balance
pub fn ft_balance_of(&self, account_id: AccountId) -> U128;

/// Get total supply
pub fn ft_total_supply(&self) -> U128;

/// Get metadata
pub fn ft_metadata(&self) -> FungibleTokenMetadata;
```

#### Bridge-Only Methods

```rust
/// Mint tokens (bridge only)
pub fn mint(&mut self, account_id: AccountId, amount: U128);

/// Burn tokens (bridge only)
pub fn burn(&mut self, account_id: AccountId, amount: U128);
```

---

## Solver Protocol Messages

### WebSocket Messages

#### From Solver Bus → Solver

```typescript
// New intent available
interface IntentRequest {
  type: "IntentRequest";
  intent_id: string;
  source_asset: string;
  source_amount: string;
  destination_asset: string;
  deadline: number;
  user_account: string;
}

// Solver won the intent
interface IntentAssigned {
  type: "IntentAssigned";
  intent_id: string;
  solver_id: string;
}

// Settlement request
interface SettleRequest {
  type: "SettleRequest";
  intent_id: string;
}
```

#### From Solver → Solver Bus

```typescript
// Quote submission
interface QuoteResponse {
  type: "QuoteResponse";
  intent_id: string;
  solver_id: string;
  destination_amount: string;
  expiry: number;
  signature: string;
}

// Settlement result
interface SettleResult {
  type: "SettleResult";
  intent_id: string;
  success: boolean;
  tx_hash?: string;
  error?: string;
}
```

---

## Error Types

```rust
/// Cryptographic errors
pub enum CryptoError {
    InvalidPublicKey,
    InvalidSignature,
    VerificationFailed,
    InvalidHex(String),
}

/// Address errors
pub enum AddressError {
    InvalidChecksum,
    InvalidLength,
    InvalidVersion,
    DecodeError(String),
}

/// Key derivation errors
pub enum KeyError {
    InvalidScalar,
    InvalidPoint,
    DerivationFailed,
}
```

---

## Full Documentation

For complete API documentation with examples, generate the rustdocs:

```bash
cargo doc --no-deps --open
```

This will open the full API reference in your browser with:
- All public types and functions
- Documentation comments
- Usage examples
- Cross-references
