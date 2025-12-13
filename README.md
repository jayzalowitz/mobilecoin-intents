# MobileCoin Intents

[![License](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

A cross-chain swap protocol enabling seamless exchanges between MobileCoin (MOB) and assets on the NEAR blockchain through the NEAR Intents platform.

## Overview

MobileCoin Intents bridges MobileCoin's privacy-focused blockchain with NEAR's intent-based cross-chain transaction system. Users can:

- **Deposit**: Convert MOB to wrapped MOB (wMOB) on NEAR
- **Withdraw**: Convert wMOB back to MOB
- **Swap**: Exchange MOB/wMOB for other NEAR-based assets (USDC, NEAR, etc.)

The protocol uses a competitive solver auction to ensure users get the best prices for their swaps.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            User Wallet                                   │
│                    (MobileCoin + NEAR accounts)                         │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      NEAR Intents Protocol                               │
│              (Intent submission & broadcasting)                          │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    Verifier Contract (defuse-mobilecoin)                 │
│                    Intent validation & signature verification            │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                          Solver Bus (WebSocket)                          │
│                    Real-time auction for best quotes                     │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    Solver Implementations                                │
│                    (solver-mobilecoin, simple-solver)                    │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    Bridge & Token Layer                                  │
│              (POA Bridge + wMOB NEP-141 Token)                          │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    Blockchain Layer                                       │
│              (NEAR Protocol  ←──────→  MobileCoin)                       │
└──────────────────────────────────────────────────────────────────────────┘
```

## Modules

| Module | Description |
|--------|-------------|
| [`mobilecoin-crypto`](./mobilecoin-crypto) | Ed25519 signature verification, domain-separated signing, batch verification |
| [`mobilecoin-address`](./mobilecoin-address) | MobileCoin address parsing, validation, and Base58Check encoding |
| [`mobilecoin-keys`](./mobilecoin-keys) | CryptoNote stealth address derivation and one-time key generation |
| [`defuse-mobilecoin`](./defuse-mobilecoin) | NEAR smart contract for intent verification and routing |
| [`poa-mobilecoin`](./poa-mobilecoin) | Proof-of-Authority bridge and wMOB NEP-141 token contracts |
| [`solver-mobilecoin`](./solver-mobilecoin) | Production solver implementation for market makers |
| [`examples/simple-solver`](./examples/simple-solver) | Educational example solver with extensive documentation |

## Quick Start

### Prerequisites

- Rust 1.70 or higher
- NEAR CLI (for contract deployment)
- Access to MobileCoin node (for production solvers)

### Building

```bash
# Clone the repository
git clone https://github.com/jayzalowitz/mobilecoin-intents.git
cd mobilecoin-intents

# Build all modules
cargo build --release

# Build WASM contracts
cargo build --release --target wasm32-unknown-unknown -p wmob-token -p mob-bridge -p defuse-mobilecoin
```

### Running Tests

```bash
# Run all tests
cargo test

# Run tests for a specific module
cargo test -p mobilecoin-crypto
cargo test -p mobilecoin-keys
```

### Running the Example Solver

```bash
cd examples/simple-solver

# Copy and configure environment
cp .env.example .env
# Edit .env with your settings

# Run the solver
cargo run --release
```

## How It Works

### Deposit Flow (MOB → wMOB)

1. **Create Intent**: User signs an intent specifying the MOB amount and destination NEAR account
2. **Submit Intent**: Intent is broadcast to the NEAR Intents verifier contract
3. **Solver Auction**: Solvers compete by submitting quotes via the solver bus
4. **Winner Selection**: Best quote wins; solver receives assignment notification
5. **Settlement**:
   - User sends MOB to the bridge custody address
   - Bridge authorities verify the deposit (3-of-5 multi-sig)
   - wMOB is minted to the user's NEAR account

### Withdrawal Flow (wMOB → MOB)

1. **Create Intent**: User creates an intent to convert wMOB to MOB
2. **Lock wMOB**: User's wMOB is locked in the verifier contract
3. **Solver Processing**: Winning solver initiates withdrawal via the bridge
4. **Bridge Processing**:
   - wMOB is burned
   - Authorities send MOB to user's stealth address
   - Completion proof is submitted to the bridge

### Solver Flow

```
IntentRequest (from verifier)
        │
        ▼
┌───────────────────┐
│  Calculate Quote  │ ← Price feed + liquidity check
└───────────────────┘
        │
        ▼
QuoteResponse (to solver bus)
        │
        ▼
IntentAssigned (if won)
        │
        ▼
┌───────────────────┐
│ Execute Settlement│ ← Bridge interaction
└───────────────────┘
        │
        ▼
SettleResult (completion)
```

## Security Features

### Cryptographic Security

- **Ed25519 Signatures**: RFC 8032 compliant signature verification
- **Domain Separation**: Prevents cross-context signature attacks
- **CryptoNote Stealth Addresses**: One-time keys per transaction for privacy
- **Secure Memory**: Key material is zeroized after use

### Bridge Security

- **Multi-Signature Authority**: Configurable threshold (e.g., 3-of-5)
- **Replay Protection**: Transaction hash and nonce tracking
- **Rate Limiting**: Per-hour limits on deposits, withdrawals, and volume
- **Emergency Controls**: Pause/unpause capability for incident response
- **Amount Validation**: Min/max limits per transaction

### Smart Contract Security

- **Overflow Protection**: Checked arithmetic throughout
- **Input Sanitization**: Address and amount validation
- **Access Control**: Role-based authority management

## Configuration

### Solver Configuration

| Variable | Description | Example |
|----------|-------------|---------|
| `SOLVER_ID` | Unique solver identifier | `my-solver-1` |
| `SOLVER_BUS_URL` | WebSocket endpoint | `wss://solver-bus.near-intents.org` |
| `NEAR_RPC_URL` | NEAR RPC endpoint | `https://rpc.mainnet.near.org` |
| `MOB_NODE_URL` | MobileCoin node URL | `https://mob.node.example.com` |
| `MIN_PROFIT_BPS` | Minimum spread (basis points) | `50` (0.5%) |
| `MAX_SLIPPAGE_BPS` | Slippage tolerance | `100` (1%) |
| `QUOTE_TIMEOUT_MS` | Quote validity period | `5000` |

### Bridge Configuration

```rust
RateLimitConfig {
    max_deposits_per_hour: 100,
    max_withdrawals_per_hour: 100,
    max_volume_per_hour: 1_000_000_000_000_000, // 1000 MOB
    min_amount: 1_000_000,                       // 0.000001 MOB
    max_amount: 100_000_000_000_000,            // 100 MOB
}
```

## Supported Trading Pairs

| From | To | Flow |
|------|-----|------|
| MOB | wMOB | Deposit via bridge |
| wMOB | MOB | Withdrawal via bridge |
| MOB | USDC | Cross-chain swap |
| MOB | NEAR | Cross-chain swap |
| wMOB | USDC | NEAR-side swap |
| wMOB | NEAR | NEAR-side swap |

## Development

### Project Structure

```
mobilecoin-intents/
├── mobilecoin-crypto/     # Cryptographic primitives
├── mobilecoin-address/    # Address handling
├── mobilecoin-keys/       # Key derivation (CryptoNote)
├── defuse-mobilecoin/     # NEAR verifier contract
├── poa-mobilecoin/
│   └── contracts/
│       ├── wmob-token/    # NEP-141 wMOB token
│       └── mob-bridge/    # POA bridge contract
├── solver-mobilecoin/     # Production solver
├── examples/
│   └── simple-solver/     # Example implementation
└── docs/                  # Documentation
```

### Building for Production

```bash
# Optimize contracts for size
RUSTFLAGS='-C link-arg=-s' cargo build \
    --release \
    --target wasm32-unknown-unknown \
    -p wmob-token \
    -p mob-bridge \
    -p defuse-mobilecoin
```

### Running a Solver

See the [simple-solver README](./examples/simple-solver/README.md) for a complete guide on building and running a solver.

## Documentation

- [Architecture Overview](./docs/architecture.md) - Detailed system design
- [Simple Solver Guide](./examples/simple-solver/README.md) - Step-by-step solver tutorial
- [API Documentation](https://jayzalowitz.github.io/mobilecoin-intents/) - Rustdoc API reference

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass (`cargo test`)
2. Code is formatted (`cargo fmt`)
3. Lints pass (`cargo clippy`)
4. New features include tests and documentation

## License

This project is dual-licensed under MIT OR Apache-2.0. See [LICENSE](./LICENSE) for details.

## Acknowledgments

- [MobileCoin](https://www.mobilecoin.com/) - Privacy-focused cryptocurrency
- [NEAR Protocol](https://near.org/) - Scalable blockchain platform
- [NEAR Intents](https://near.org/intents) - Cross-chain intent framework
- [CryptoNote](https://cryptonote.org/) - Stealth address protocol

---

Built with security and privacy in mind.
