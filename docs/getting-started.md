---
layout: default
title: Getting Started
---

# Getting Started

This guide will help you set up MobileCoin Intents for development or running a solver.

## Prerequisites

- **Rust 1.70+** - [Install Rust](https://rustup.rs/)
- **NEAR CLI** - For contract deployment
- **Git** - Version control

### Optional (for production solvers)
- MobileCoin node access
- NEAR account with funds
- WebSocket endpoint access

## Installation

### Clone the Repository

```bash
git clone https://github.com/jayzalowitz/mobilecoin-intents.git
cd mobilecoin-intents
```

### Build All Modules

```bash
# Build in release mode
cargo build --release
```

### Build WASM Contracts

```bash
# Install cargo-near (recommended by near-sdk)
cargo install cargo-near

# Build contracts
cargo near build -p wmob-token
cargo near build -p mob-bridge
cargo near build -p defuse-mobilecoin
```

## Running Tests

```bash
# Run all tests
cargo test

# Run tests for a specific module
cargo test -p mobilecoin-crypto
cargo test -p mobilecoin-address
cargo test -p mobilecoin-keys

# Run with verbose output
cargo test -- --nocapture
```

## Project Structure

```
mobilecoin-intents/
├── mobilecoin-crypto/     # Cryptographic primitives
│   └── src/lib.rs
├── mobilecoin-address/    # Address handling
│   └── src/lib.rs
├── mobilecoin-keys/       # Key derivation
│   └── src/lib.rs
├── defuse-mobilecoin/     # NEAR verifier contract
│   └── src/lib.rs
├── poa-mobilecoin/
│   └── contracts/
│       ├── wmob-token/    # NEP-141 token
│       └── mob-bridge/    # Bridge contract
├── solver-mobilecoin/     # Production solver
│   └── src/
├── examples/
│   └── simple-solver/     # Example solver
└── docs/                  # Documentation
```

## Quick Start: Running the Example Solver

The fastest way to understand the system is to run the example solver:

```bash
cd examples/simple-solver

# Copy environment template
cp .env.example .env

# Edit configuration (use your editor)
# Set SOLVER_ID, SOLVER_BUS_URL, etc.

# Run the solver
cargo run --release
```

See the [Solver Guide](./solver-guide) for detailed configuration.

## Using the Libraries

### Signature Verification

```rust
use mobilecoin_crypto::{MobPublicKey, MobSignature, verify_mob_signature};

let public_key = MobPublicKey::from_hex("...")?;
let signature = MobSignature::from_hex("...")?;
let message = b"Hello, MobileCoin!";

let is_valid = verify_mob_signature(message, &signature, &public_key)?;
```

### Address Parsing

```rust
use mobilecoin_address::parse_mob_address;

let address_str = "..."; // Base58Check encoded
let address = parse_mob_address(address_str)?;

// Access components
let view_key = address.view_public_key;
let spend_key = address.spend_public_key;
let network = address.network;
```

### Key Derivation

```rust
use mobilecoin_keys::{derive_one_time_public_key, generate_tx_key, WalletKeys};

// Generate stealth address
let wallet = WalletKeys::generate();
let tx_key = generate_tx_key();
let output_index = 0u64;

let one_time_key = derive_one_time_public_key(
    &wallet.view_key_pair.public_key,
    &wallet.spend_key_pair.public_key,
    &tx_key.private_key,
    output_index,
);
```

## Deploying Contracts

### Storage Registration (NEP-145)

Accounts must register storage on the `wmob-token` contract before they can receive minted or transferred wMOB:

```bash
# Example: register yourself
near call <wmob-token-account> storage_deposit '{"account_id": "<your.near>"}' --accountId <your.near> --deposit 0.01
```

### Deploy wMOB Token

```bash
# Build the contract (prints the .wasm output path)
cargo near build -p wmob-token

# Deploy to NEAR
near deploy wmob.testnet \
    <PATH_TO_WMOB_WASM> \
    --initFunction new \
    --initArgs '{"bridge_contract": "bridge.testnet", "owner": "owner.testnet"}'
```

### Deploy Bridge Contract

```bash
# Build the contract (prints the .wasm output path)
cargo near build -p mob-bridge

# Deploy to NEAR
near deploy bridge.testnet \
    <PATH_TO_MOB_BRIDGE_WASM> \
    --initFunction new \
    --initArgs '{
        "wmob_token": "wmob.testnet",
        "authorities": [
            "ed25519:<PUBKEY1>",
            "ed25519:<PUBKEY2>",
            "ed25519:<PUBKEY3>"
        ],
        "threshold": 2,
        "mob_custody_address": "<MOBILECOIN_CUSTODY_ADDRESS>"
    }'
```

## Configuration Reference

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `SOLVER_ID` | Unique solver identifier | Yes |
| `SOLVER_BUS_URL` | WebSocket endpoint | Yes |
| `NEAR_RPC_URL` | NEAR RPC endpoint | Yes |
| `MOB_NODE_URL` | MobileCoin node | Production |
| `MIN_PROFIT_BPS` | Minimum profit margin | No (default: 50) |
| `MAX_SLIPPAGE_BPS` | Slippage tolerance | No (default: 100) |
| `QUOTE_TIMEOUT_MS` | Quote validity | No (default: 5000) |

## Next Steps

- [Architecture Overview](./architecture) - Understand the system design
- [Solver Guide](./solver-guide) - Run a market maker
- [API Reference](./api) - Detailed API documentation

## Troubleshooting

### Build Errors

**"wasm32-unknown-unknown target not installed"**
```bash
rustup target add wasm32-unknown-unknown
```

**"ed25519-dalek version conflict"**
```bash
cargo update
```

### Runtime Errors

**"Connection refused to solver bus"**
- Check `SOLVER_BUS_URL` is correct
- Verify network connectivity
- Ensure WebSocket port is open

**"Invalid signature"**
- Verify the message hasn't been modified
- Check public key matches the signer
- Ensure domain separation is consistent

## Support

- [GitHub Issues](https://github.com/jayzalowitz/mobilecoin-intents/issues)
- [Architecture Documentation](./architecture)
