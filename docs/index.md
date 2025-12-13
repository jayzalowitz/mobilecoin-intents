---
layout: default
title: Home
---

# MobileCoin Intents

A cross-chain swap protocol enabling seamless exchanges between MobileCoin (MOB) and assets on the NEAR blockchain.

## What is MobileCoin Intents?

MobileCoin Intents bridges MobileCoin's privacy-focused blockchain with NEAR's intent-based cross-chain transaction system. The protocol enables:

- **Deposits**: Convert MOB to wrapped MOB (wMOB) on NEAR
- **Withdrawals**: Convert wMOB back to MOB
- **Swaps**: Exchange MOB/wMOB for USDC, NEAR, and other assets

## How It Works

```
User Intent → Solver Auction → Best Quote Wins → Settlement
```

1. **Create Intent**: User specifies what they want to swap (e.g., "10 MOB for wMOB")
2. **Solver Competition**: Market makers compete to offer the best rate
3. **Execution**: Winning solver facilitates the cross-chain transfer
4. **Settlement**: Assets are delivered via the bridge protocol

## Key Features

### Privacy-Preserving
- CryptoNote stealth addresses for MobileCoin transactions
- One-time keys per transaction
- No transaction graph analysis possible

### Secure
- Multi-signature bridge authorities (3-of-5)
- Ed25519 cryptographic signatures
- Rate limiting and amount validation
- Emergency pause capability

### Competitive Pricing
- Real-time solver auction via WebSocket
- Multiple market makers competing
- Best price wins automatically

### Developer-Friendly
- Modular Rust architecture
- Comprehensive example solver
- Full API documentation

## Quick Links

| Resource | Description |
|----------|-------------|
| [Getting Started](./getting-started) | Installation and setup guide |
| [Architecture](./architecture) | System design and data flows |
| [Solver Guide](./solver-guide) | How to run a market maker |
| [API Reference](./api) | Rustdoc API documentation |

## Supported Trading Pairs

| From | To | Type |
|------|-----|------|
| MOB | wMOB | Bridge deposit |
| wMOB | MOB | Bridge withdrawal |
| MOB | USDC | Cross-chain swap |
| MOB | NEAR | Cross-chain swap |
| wMOB | USDC | NEAR-side swap |
| wMOB | NEAR | NEAR-side swap |

## Architecture Overview

```
┌──────────────────────────────────────────────────────────┐
│                    User Wallet                            │
│             (MobileCoin + NEAR accounts)                 │
└─────────────────────────┬────────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────────┐
│                 NEAR Intents Protocol                     │
│           (Intent submission & broadcasting)              │
└─────────────────────────┬────────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────────┐
│            Verifier Contract (defuse-mobilecoin)          │
│          Intent validation & signature verification       │
└─────────────────────────┬────────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────────┐
│                 Solver Bus (WebSocket)                    │
│             Real-time auction for best quotes             │
└─────────────────────────┬────────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────────┐
│              Solver Implementations                       │
│         (solver-mobilecoin, simple-solver)                │
└─────────────────────────┬────────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────────┐
│               Bridge & Token Layer                        │
│          (POA Bridge + wMOB NEP-141 Token)               │
└──────────────────────────────────────────────────────────┘
```

## Project Modules

| Module | Description |
|--------|-------------|
| `mobilecoin-crypto` | Ed25519 signature verification |
| `mobilecoin-address` | MobileCoin address parsing |
| `mobilecoin-keys` | CryptoNote stealth addresses |
| `defuse-mobilecoin` | NEAR verifier contract |
| `poa-mobilecoin` | Bridge and wMOB token |
| `solver-mobilecoin` | Production solver |
| `simple-solver` | Example implementation |

## Getting Help

- [GitHub Issues](https://github.com/jayzalowitz/mobilecoin-intents/issues) - Bug reports and feature requests
- [Architecture Docs](./architecture) - Technical deep-dive
- [Solver Guide](./solver-guide) - Running a market maker

## License

MIT OR Apache-2.0
