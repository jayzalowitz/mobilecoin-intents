---
layout: default
title: Solver Guide
---

# Solver Guide

This guide explains how to build and run a solver (market maker) for MobileCoin Intents.

## What is a Solver?

A solver is an automated market maker that:
1. Listens for swap intents from users
2. Provides competitive price quotes
3. Executes winning swaps via the bridge

Solvers earn profit from the spread between their quotes and market prices.

## Quick Start

```bash
cd examples/simple-solver
cp .env.example .env
# Edit .env with your configuration
cargo run --release
```

## How Solvers Work

### Protocol Flow

```
1. IntentRequest    ──────►  Solver receives intent from bus
2. Calculate Quote  ──────►  Price feed + liquidity check
3. QuoteResponse    ──────►  Submit bid to solver bus
4. IntentAssigned   ──────►  Notification if you won
5. Execute          ──────►  Bridge deposit/withdrawal
6. SettleResult     ──────►  Report completion
```

### Message Types

#### IntentRequest

Received when a user submits an intent:

```json
{
  "type": "IntentRequest",
  "intent_id": "intent_abc123",
  "source_asset": "MOB",
  "source_amount": "1000000000000",
  "destination_asset": "wMOB",
  "deadline": 1700000000,
  "user_account": "user.near"
}
```

#### QuoteResponse

Your bid for the intent:

```json
{
  "type": "QuoteResponse",
  "intent_id": "intent_abc123",
  "solver_id": "my-solver-1",
  "destination_amount": "995000000000",
  "expiry": 1700000005,
  "signature": "..."
}
```

#### IntentAssigned

Notification when you win:

```json
{
  "type": "IntentAssigned",
  "intent_id": "intent_abc123",
  "solver_id": "my-solver-1"
}
```

## Configuration

### Required Settings

```bash
# Unique identifier for your solver
SOLVER_ID=my-solver-1

# Solver bus WebSocket endpoint
SOLVER_BUS_URL=wss://solver-bus.near-intents.org

# NEAR RPC for contract interactions
NEAR_RPC_URL=https://rpc.mainnet.near.org
```

### Optional Settings

```bash
# Minimum profit margin in basis points (0.5% = 50 bps)
MIN_PROFIT_BPS=50

# Maximum slippage tolerance (1% = 100 bps)
MAX_SLIPPAGE_BPS=100

# How long quotes are valid (milliseconds)
QUOTE_TIMEOUT_MS=5000

# MobileCoin node for production
MOB_NODE_URL=https://mob.node.example.com
```

## Quoting Strategy

### Basic Quote Calculation

```rust
fn calculate_quote(
    source_amount: u128,
    source_asset: &str,
    dest_asset: &str,
) -> Option<u128> {
    // Get current price
    let price = self.price_feed.get_price(source_asset, dest_asset)?;

    // Calculate base output
    let base_output = source_amount * price;

    // Apply profit margin (e.g., 0.5%)
    let profit_margin = base_output * self.min_profit_bps / 10000;
    let output = base_output - profit_margin;

    // Check liquidity
    if self.liquidity.available(dest_asset) < output {
        return None; // Insufficient liquidity
    }

    Some(output)
}
```

### Competitive Pricing

To win more intents:
- Monitor competitor quotes
- Use tighter spreads during high volume
- Adjust margins based on market volatility
- Consider gas costs in pricing

## Supported Trading Pairs

| Pair | Settlement Type |
|------|-----------------|
| MOB → wMOB | Bridge deposit |
| wMOB → MOB | Bridge withdrawal |
| MOB → USDC | Cross-chain swap |
| MOB → NEAR | Cross-chain swap |
| wMOB → USDC | NEAR-side swap |
| wMOB → NEAR | NEAR-side swap |

## Settlement Execution

### Deposit Flow (MOB → wMOB)

```rust
async fn settle_deposit(&self, intent: &Intent) -> Result<()> {
    // 1. Wait for user's MOB deposit to custody
    let deposit = self.wait_for_deposit(&intent.user_mob_address).await?;

    // 2. Get authority signatures
    let signatures = self.collect_authority_signatures(&deposit).await?;

    // 3. Submit proof to bridge
    self.bridge.submit_deposit_proof(DepositProof {
        tx_hash: deposit.tx_hash,
        amount: deposit.amount,
        recipient: intent.user_near_account.clone(),
        signatures,
    }).await?;

    Ok(())
}
```

### Withdrawal Flow (wMOB → MOB)

```rust
async fn settle_withdrawal(&self, intent: &Intent) -> Result<()> {
    // 1. Request withdrawal from bridge
    let withdrawal_id = self.bridge.request_withdrawal(
        intent.amount,
        intent.mob_destination_address.clone(),
    ).await?;

    // 2. Wait for authority processing
    self.wait_for_withdrawal_completion(withdrawal_id).await?;

    Ok(())
}
```

## Example Solver Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    SimpleSolver                          │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐ │
│  │ WebSocket   │  │ Price Feed  │  │ Liquidity       │ │
│  │ Client      │  │             │  │ Manager         │ │
│  └──────┬──────┘  └──────┬──────┘  └────────┬────────┘ │
│         │                │                   │          │
│         ▼                ▼                   ▼          │
│  ┌───────────────────────────────────────────────────┐ │
│  │               Quote Generator                      │ │
│  │   intent + price + liquidity → quote              │ │
│  └───────────────────────────────────────────────────┘ │
│                          │                              │
│                          ▼                              │
│  ┌───────────────────────────────────────────────────┐ │
│  │            Settlement Executor                     │ │
│  │   Bridge interactions, proof submission           │ │
│  └───────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

## Production Considerations

### High Availability

- Run multiple solver instances
- Use different `SOLVER_ID` for each
- Load balance across regions

### Risk Management

- Set position limits per asset
- Monitor exposure continuously
- Implement circuit breakers

### Security

- Store keys in HSM/KMS
- Use rate limiting
- Monitor for anomalies
- Regular key rotation

### Monitoring

Track these metrics:
- Quote win rate
- Settlement success rate
- Average profit margin
- Liquidity utilization
- Response latency

## Troubleshooting

### "Connection to solver bus failed"

```
- Check SOLVER_BUS_URL is correct
- Verify firewall allows WebSocket connections
- Check for TLS certificate issues
```

### "Quote expired before settlement"

```
- Increase QUOTE_TIMEOUT_MS
- Optimize settlement execution speed
- Check for network latency issues
```

### "Insufficient liquidity"

```
- Add more funds to liquidity pools
- Implement dynamic pricing based on availability
- Consider declining large orders
```

### "Signature verification failed"

```
- Verify you're using the correct signing key
- Check domain separation prefix
- Ensure message format matches expected
```

## Example: Custom Price Feed

```rust
use async_trait::async_trait;

#[async_trait]
pub trait PriceFeed: Send + Sync {
    async fn get_price(&self, base: &str, quote: &str) -> Option<f64>;
}

pub struct CoinGeckoPriceFeed {
    client: reqwest::Client,
}

#[async_trait]
impl PriceFeed for CoinGeckoPriceFeed {
    async fn get_price(&self, base: &str, quote: &str) -> Option<f64> {
        let url = format!(
            "https://api.coingecko.com/api/v3/simple/price?ids={}&vs_currencies={}",
            base, quote
        );

        let response = self.client.get(&url).send().await.ok()?;
        let data: serde_json::Value = response.json().await.ok()?;

        data[base][quote].as_f64()
    }
}
```

## Next Steps

- Review the [simple-solver source code](https://github.com/jayzalowitz/mobilecoin-intents/tree/main/examples/simple-solver)
- Study the [Architecture documentation](./architecture)
- Join the solver community for support
