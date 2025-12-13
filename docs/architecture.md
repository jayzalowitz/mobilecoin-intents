---
layout: default
title: Architecture
---

# MobileCoin Integration Architecture

## Overview

This repository implements the integration of MobileCoin (MOB) into the NEAR Intents cross-chain transaction protocol. The integration enables users to swap MOB to/from other assets via NEAR Intents.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              User                                           │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐        │
│  │ MobileCoin      │    │ NEAR            │    │ Other Chains    │        │
│  │ Wallet          │    │ Wallet          │    │ (ETH, SOL, etc) │        │
│  └────────┬────────┘    └────────┬────────┘    └────────┬────────┘        │
└───────────┼─────────────────────┼─────────────────────┼──────────────────┘
            │                      │                      │
            ▼                      ▼                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          NEAR Intents Protocol                               │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │                         Solver Bus (WebSocket)                         │ │
│  │   Intent Broadcast ──────► Quote Collection ──────► Best Quote Selection │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                      │                                       │
│  ┌────────────┐  ┌────────────────┐  │  ┌────────────────┐                 │
│  │ Verifier   │  │ MOB Bridge     │  │  │ Chain          │                 │
│  │ Contract   │  │ Contract       │◄─┴─►│ Signatures     │                 │
│  │ (defuse)   │  │                │     │ (MPC)          │                 │
│  └────────────┘  └───────┬────────┘     └────────────────┘                 │
│                          │                                                  │
│  ┌────────────┐  ┌───────┴────────┐                                        │
│  │ wMOB Token │◄─┤ Authority      │                                        │
│  │ (NEP-141)  │  │ Validators     │                                        │
│  └────────────┘  └───────┬────────┘                                        │
└──────────────────────────┼──────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         MobileCoin Network                                   │
│  ┌────────────────┐    ┌────────────────┐    ┌────────────────┐            │
│  │ Custody        │    │ Transaction    │    │ Consensus      │            │
│  │ Address        │◄───┤ Monitor        │◄───┤ Validators     │            │
│  └────────────────┘    └────────────────┘    └────────────────┘            │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Components

### 1. Cryptographic Module (`mobilecoin-crypto`)

Provides Ed25519 signature verification for MobileCoin:

- `MobPublicKey` - 32-byte public key
- `MobSignature` - 64-byte signature
- `verify_mob_signature()` - Signature verification
- `MobPayload` - Intent payload with signing support

### 2. Address Module (`mobilecoin-address`)

Handles MobileCoin address parsing and validation:

- Base58Check encoding/decoding
- View and spend key extraction
- Fog metadata parsing
- Network (mainnet/testnet) validation
- NEAR-compatible string format

### 3. One-Time Keys Module (`mobilecoin-keys`)

Implements CryptoNote stealth addresses:

- `WalletKeys` - View and spend key pairs
- `derive_one_time_public_key()` - Stealth address derivation
- `check_output_ownership()` - Output scanning
- `derive_key_image()` - Double-spend prevention
- `generate_settlement_address()` - NEAR Intents integration

### 4. wMOB Token (`poa-mobilecoin/wmob-token`)

NEP-141 fungible token representing MOB on NEAR:

- Mint (bridge only)
- Burn (bridge only)
- Standard transfers
- 12 decimal places (picoMOB)

### 5. MOB Bridge (`poa-mobilecoin/mob-bridge`)

Proof of Authority bridge for cross-chain transfers:

- Deposit verification with multi-sig
- Withdrawal request queue
- Authority management
- Emergency pause capability

### 6. Verifier Module (`defuse-mobilecoin`)

NEAR Intents verifier updates for MobileCoin:

- Address validation
- Signature verification
- Intent processing
- Settlement routing

### 7. Solver (`solver-mobilecoin`)

Market maker for MOB liquidity:

- Solver bus WebSocket client
- Quote generation
- Settlement execution
- Liquidity management
- Price feeds

## Data Flow

### Deposit Flow (MOB → wMOB)

```
1. User creates intent: MOB → wMOB
2. User signs intent with MobileCoin wallet
3. Intent submitted to NEAR Intents verifier
4. Solver quotes and wins intent
5. User sends MOB to custody address
6. Monitor detects deposit
7. Authorities sign deposit proof
8. Proof submitted to bridge
9. Bridge mints wMOB to user
```

### Withdrawal Flow (wMOB → MOB)

```
1. User creates intent: wMOB → MOB
2. User deposits wMOB to verifier
3. Solver quotes and wins intent
4. Solver requests withdrawal from bridge
5. Bridge burns wMOB
6. Authorities process withdrawal
7. MOB sent to user's one-time address
8. Authorities submit completion proof
```

## Security Model

### Multi-Signature Authority

- 3-of-5 (or similar) authority threshold
- Ed25519 signatures
- Key rotation capability
- No single point of failure

### Replay Protection

- Deposit transaction hashes tracked
- Withdrawal IDs unique
- Nonce for each operation

### Emergency Controls

- Pause/unpause capability
- Amount limits
- Authority timeout

## Development

### Build

```bash
cargo build --release
```

### Test

```bash
cargo test
```

### Deploy Contracts

```bash
# Build WASM
cargo build --target wasm32-unknown-unknown --release

# Deploy wMOB token
near deploy wmob.near ./target/wasm32-unknown-unknown/release/wmob_token.wasm

# Deploy bridge
near deploy bridge.near ./target/wasm32-unknown-unknown/release/mob_bridge.wasm
```

### Run Solver

```bash
export SOLVER_ID=mob-solver-1
export SOLVER_BUS_URL=wss://solver-bus.near-intents.org
cargo run --bin mob-solver
```

## References

- [NEAR Intents Documentation](https://docs.near-intents.org)
- [MobileCoin GitHub](https://github.com/mobilecoinfoundation/mobilecoin)
- [CryptoNote Whitepaper](https://cryptonote.org/whitepaper.pdf)
- [NEP-141 Standard](https://nomicon.io/Standards/Tokens/FungibleToken/Core)
