# MobileCoin-NEAR Intent Bridge: Mainnet Deployment Plan

## Overview

Deploy the MOB ↔ wMOB bridge system to NEAR mainnet using pseudonymous accounts, then demonstrate a live intent flow between MobileCoin and NEAR.

---

## Phase 1: Pseudonymous Account Setup

### 1.1 Create NEAR Mainnet Accounts

We'll create memorable but pseudonymous `.near` accounts:

```bash
# Option A: Use near-cli to create named accounts
near create-account marseille-bridge.near --useFaucet
near create-account marseille-wmob.near --useFaucet
near create-account marseille-verifier.near --useFaucet
near create-account marseille-solver.near --useFaucet
near create-account marseille-admin.near --useFaucet

# Option B: Create implicit accounts (fully pseudonymous)
# Generate keypairs and fund them directly
near generate-key marseille-bridge
near generate-key marseille-wmob
near generate-key marseille-verifier
near generate-key marseille-solver
near generate-key marseille-admin
```

### 1.2 Account Naming Convention

| Account | Purpose | Suggested Name |
|---------|---------|----------------|
| Admin/Owner | Contract administration | `marseille-admin.near` or `mob-marseille.near` |
| wMOB Token | NEP-141 wrapped token | `wmob.marseille.near` or `wmob-marseille.near` |
| Bridge | PoA bridge contract | `bridge.marseille.near` or `mob-bridge-marseille.near` |
| Verifier | Intent verifier | `verifier.marseille.near` |
| Solver | Market maker account | `solver.marseille.near` |

### 1.3 Generate Authority Keys

For the PoA bridge, generate 3-5 authority keypairs:

```bash
# Generate Ed25519 keypairs for bridge authorities
# Use a secure method (e.g., near-cli or openssl)

# Authority 1
near generate-key authority1-marseille
# Authority 2
near generate-key authority2-marseille
# Authority 3
near generate-key authority3-marseille

# Store public keys for contract initialization
# Format: ed25519:<base58_pubkey>
```

---

## Phase 2: Build Contracts

### 2.1 Build WASM Binaries

```bash
cd /Users/jayzalowitz/conductor/workspaces/mobilecoin-intents/marseille

# Install cargo-near if needed
cargo install cargo-near

# Build optimized WASM contracts
RUSTFLAGS='-C link-arg=-s' cargo build \
    --release \
    --target wasm32-unknown-unknown \
    -p wmob-token \
    -p mob-bridge \
    -p defuse-mobilecoin

# Contracts will be in:
# target/wasm32-unknown-unknown/release/wmob_token.wasm
# target/wasm32-unknown-unknown/release/mob_bridge.wasm
# target/wasm32-unknown-unknown/release/defuse_mobilecoin.wasm
```

### 2.2 Verify Contract Size

```bash
# NEAR contracts must be < 4MB
ls -la target/wasm32-unknown-unknown/release/*.wasm
```

---

## Phase 3: Deploy Contracts to Mainnet

### 3.1 Deploy wMOB Token Contract

```bash
# Set environment
export NEAR_ENV=mainnet

# Deploy wMOB token
near deploy wmob.marseille.near \
    target/wasm32-unknown-unknown/release/wmob_token.wasm \
    --initFunction new \
    --initArgs '{
        "bridge_contract": "bridge.marseille.near",
        "owner": "marseille-admin.near"
    }' \
    --accountId marseille-admin.near
```

### 3.2 Deploy Bridge Contract

```bash
# Deploy bridge with authorities
near deploy bridge.marseille.near \
    target/wasm32-unknown-unknown/release/mob_bridge.wasm \
    --initFunction new \
    --initArgs '{
        "wmob_token": "wmob.marseille.near",
        "authorities": [
            "ed25519:AUTHORITY1_PUBKEY",
            "ed25519:AUTHORITY2_PUBKEY",
            "ed25519:AUTHORITY3_PUBKEY"
        ],
        "threshold": 2,
        "mob_custody_address": "MOB_CUSTODY_ADDRESS_HERE"
    }' \
    --accountId marseille-admin.near
```

### 3.3 Deploy Verifier Contract

```bash
near deploy verifier.marseille.near \
    target/wasm32-unknown-unknown/release/defuse_mobilecoin.wasm \
    --initFunction new \
    --initArgs '{}' \
    --accountId marseille-admin.near

# Register MobileCoin chain
near call verifier.marseille.near register_mobilecoin_chain '{
    "wmob_token": "wmob.marseille.near",
    "bridge_contract": "bridge.marseille.near",
    "min_amount": 1000000000,
    "max_amount": 1000000000000000
}' --accountId marseille-admin.near
```

### 3.4 Register Storage for Key Accounts

```bash
# Register storage on wMOB token for solver and demo accounts
near call wmob.marseille.near storage_deposit '{"account_id": "solver.marseille.near"}' \
    --accountId solver.marseille.near --deposit 0.01

near call wmob.marseille.near storage_deposit '{"account_id": "demo-user.near"}' \
    --accountId demo-user.near --deposit 0.01
```

---

## Phase 4: Configure Solver Infrastructure

### 4.1 Environment Configuration

Create `solver.env`:

```bash
# Solver configuration
export SOLVER_ID="marseille-solver-1"
export SOLVER_BUS_URL="wss://solver-bus.near-intents.org"
export NEAR_RPC_URL="https://rpc.mainnet.near.org"
export MOB_NODE_URL="https://node.mobilecoin.com"

# Trading parameters
export MIN_PROFIT_BPS="50"      # 0.5% minimum profit
export MAX_SLIPPAGE_BPS="100"   # 1% max slippage
export QUOTE_TIMEOUT_MS="2500"  # 2.5 second quotes

# Security (production)
export ALLOW_INSECURE_URLS="0"
```

### 4.2 Run Solver

```bash
source solver.env
cd /Users/jayzalowitz/conductor/workspaces/mobilecoin-intents/marseille

# Run production solver
cargo run --release -p solver-mobilecoin

# Or run example solver for testing
cargo run --release --example simple-solver
```

---

## Phase 5: Demonstration Flow

### Demo 1: MOB → wMOB (Deposit Flow)

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   User      │     │  Verifier   │     │   Solver    │     │   Bridge    │
│  (MOB+NEAR) │     │  Contract   │     │  (Market)   │     │  Contract   │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │                   │
       │ 1. Create Intent  │                   │                   │
       │──────────────────>│                   │                   │
       │                   │ 2. Broadcast      │                   │
       │                   │──────────────────>│                   │
       │                   │                   │ 3. Quote          │
       │                   │<──────────────────│                   │
       │ 4. Accept Quote   │                   │                   │
       │──────────────────>│                   │                   │
       │                   │ 5. Assign Solver  │                   │
       │                   │──────────────────>│                   │
       │                   │                   │                   │
       │ 6. Send MOB to Custody                │                   │
       │─────────────────────────────────────────────────────────>│
       │                   │                   │ 7. Verify MOB     │
       │                   │                   │──────────────────>│
       │                   │                   │                   │
       │                   │                   │ 8. Submit Proof   │
       │                   │                   │──────────────────>│
       │                   │                   │                   │
       │ 9. Receive wMOB   │                   │   (Mint wMOB)     │
       │<─────────────────────────────────────────────────────────│
       │                   │                   │                   │
```

### Demo 2: wMOB → MOB (Withdrawal Flow)

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   User      │     │  Verifier   │     │   Solver    │     │   Bridge    │
│  (wMOB)     │     │  Contract   │     │  (Market)   │     │  Contract   │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │                   │
       │ 1. Lock wMOB      │                   │                   │
       │──────────────────────────────────────────────────────────>│
       │                   │                   │                   │
       │ 2. Create Intent  │                   │                   │
       │──────────────────>│                   │                   │
       │                   │ 3. Broadcast      │                   │
       │                   │──────────────────>│                   │
       │                   │                   │ 4. Quote          │
       │                   │<──────────────────│                   │
       │ 5. Accept Quote   │                   │                   │
       │──────────────────>│                   │                   │
       │                   │                   │                   │
       │                   │                   │ 6. Burn wMOB      │
       │                   │                   │──────────────────>│
       │                   │                   │                   │
       │                   │                   │ 7. Send MOB       │
       │ 8. Receive MOB    │                   │<──────────────────│
       │<──────────────────────────────────────│ (to stealth addr) │
       │                   │                   │                   │
       │                   │                   │ 9. Submit Proof   │
       │                   │                   │──────────────────>│
       │                   │                   │                   │
```

---

## Phase 6: Run Live Demo

### 6.1 Prerequisites

1. NEAR account with some NEAR for gas
2. MobileCoin wallet with MOB
3. All contracts deployed
4. Solver running

### 6.2 Execute Demo Script

```bash
# Run the demonstration
./scripts/demo_intent_flow.sh
```

---

## Security Checklist

- [ ] All authority private keys stored securely (HSM or hardware wallet)
- [ ] Bridge threshold set appropriately (e.g., 2-of-3 or 3-of-5)
- [ ] Rate limits configured on bridge contract
- [ ] Minimum/maximum deposit amounts set
- [ ] Emergency pause function tested
- [ ] All contracts use secure HTTPS/WSS endpoints
- [ ] No hardcoded secrets in deployed code

---

## Monitoring

```bash
# Monitor bridge contract events
near view bridge.marseille.near get_rate_limit_state '{}'

# Check wMOB supply
near view wmob.marseille.near ft_total_supply '{}'

# View pending withdrawals
near view bridge.marseille.near get_withdrawal '{"withdrawal_id": 0}'
```

---

## Cost Estimates

| Item | Cost |
|------|------|
| Account creation (5 accounts) | ~0.5 NEAR |
| Contract deployment (3 contracts) | ~5-10 NEAR |
| Storage deposits | ~0.1 NEAR each |
| Gas for transactions | ~0.01 NEAR each |
| **Total estimated** | **~10-15 NEAR** |

---

## Troubleshooting

### Contract deployment fails
```bash
# Check account has enough NEAR
near state marseille-admin.near

# Verify WASM file exists and is valid
wasm-opt --version
```

### Solver won't connect
```bash
# Check URL security
export ALLOW_INSECURE_URLS=0  # Should be 0 for production

# Verify WebSocket endpoint
websocat wss://solver-bus.near-intents.org
```

### Bridge deposit fails
```bash
# Check if deposit already processed
near view bridge.marseille.near is_deposit_processed '{"tx_hash": "..."}'

# Check rate limits
near view bridge.marseille.near get_rate_limit_state '{}'
```
