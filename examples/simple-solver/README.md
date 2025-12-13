# Simple MobileCoin Solver for NEAR Intents

A minimal, well-documented example solver implementation for the MobileCoin NEAR Intents protocol.

## Overview

A **solver** (also called a market maker) provides liquidity for cross-chain swaps in the NEAR Intents protocol. When users want to swap MOB ↔ wMOB or exchange MOB for other tokens, solvers compete to fulfill these requests and earn a profit from the spread.

### How It Works

```
┌──────────┐     1. Intent      ┌─────────────┐     2. Broadcast     ┌──────────┐
│   User   │ ──────────────────►│   Verifier  │ ───────────────────► │  Solver  │
│          │                    │  Contract   │                      │   Bus    │
└──────────┘                    └─────────────┘                      └────┬─────┘
                                                                          │
                                                                          │ 3. Quote
                                                                          ▼
┌──────────┐     6. Assets      ┌─────────────┐     4. Assignment    ┌──────────┐
│   User   │ ◄──────────────────│   Bridge    │ ◄─────────────────── │  Solver  │
│          │                    │  Contract   │                      │  (You!)  │
└──────────┘                    └─────────────┘     5. Settlement    └──────────┘
```

1. **User creates intent**: "I want to swap 10 MOB for wMOB"
2. **Verifier broadcasts**: Intent is sent to the solver bus
3. **Solvers quote**: Competing solvers submit bids with their offered rates
4. **Best solver wins**: The solver offering the best rate gets assigned
5. **Settlement**: Winner executes the swap through the bridge
6. **User receives assets**: User gets their wMOB (or other destination token)

## Quick Start

### Prerequisites

- Rust 1.70+ installed
- Access to the NEAR Intents solver bus (testnet or mainnet)

### Running the Example

```bash
cd examples/simple-solver

# Run with default configuration (testnet)
cargo run

# Or customize via environment variables
SOLVER_ID="my-solver" \
MIN_PROFIT_BPS="100" \
cargo run
```

### Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `SOLVER_ID` | `simple-solver-1` | Unique identifier for your solver |
| `SOLVER_BUS_URL` | `wss://solver-bus.near-intents.org` | WebSocket URL of the solver bus |
| `MIN_PROFIT_BPS` | `50` | Minimum profit margin in basis points (50 = 0.5%) |
| `QUOTE_VALIDITY_MS` | `2500` | How long quotes remain valid (milliseconds) |

## Supported Trading Pairs

This example solver supports:

| Source | Destination | Description |
|--------|-------------|-------------|
| MOB | wMOB | Wrap MobileCoin on NEAR |
| wMOB | MOB | Unwrap to native MobileCoin |
| MOB | USDC | Sell MOB for USDC |
| USDC | MOB | Buy MOB with USDC |
| wMOB | USDC | Sell wMOB for USDC |
| USDC | wMOB | Buy wMOB with USDC |
| MOB | NEAR | Sell MOB for NEAR |
| NEAR | MOB | Buy MOB with NEAR |

## Code Structure

```
src/main.rs
├── Config              # Configuration from environment
├── SolverBusMessage    # WebSocket protocol messages
├── PriceFeed           # Exchange rate provider
├── LiquidityManager    # Balance tracking
├── SettlementType      # Settlement flow categorization
├── SimpleSolver        # Main solver implementation
│   ├── run()           # WebSocket connection loop
│   ├── handle_message()# Message dispatcher
│   ├── generate_quote()# Quote calculation
│   └── execute_settlement() # Settlement execution
└── main()              # Entry point
```

## Building Your Own Solver

This example is intentionally simple. For production, you'll need to implement:

### 1. Real Price Feeds

Replace `PriceFeed` with actual price sources:

```rust
// Example: Fetch from CoinGecko
async fn fetch_mob_price() -> Decimal {
    let resp = reqwest::get("https://api.coingecko.com/api/v3/simple/price?ids=mobilecoin&vs_currencies=usd")
        .await?
        .json::<Value>()
        .await?;
    // Parse and return price
}
```

### 2. Wallet Integration

Replace `LiquidityManager` with real wallet connections:

```rust
// Sync MOB balance from full node
async fn sync_mob_balance(&mut self) -> Result<u128, Error> {
    let balance = self.mob_client.get_balance(&self.mob_address).await?;
    self.balances.insert("MOB".to_string(), balance);
    Ok(balance)
}

// Sync wMOB balance from NEAR
async fn sync_wmob_balance(&mut self) -> Result<u128, Error> {
    let balance = self.near_client
        .view_call("wmob.near", "ft_balance_of", json!({"account_id": self.near_account}))
        .await?;
    self.balances.insert("wMOB".to_string(), balance);
    Ok(balance)
}
```

### 3. Settlement Execution

Implement actual blockchain transactions in `execute_settlement`:

```rust
// MOB → wMOB settlement
async fn execute_mob_to_wmob(&self, intent_id: &str, amount: u128, dest: &str) -> Result<String, Error> {
    // 1. Generate custody address for this intent
    let custody_addr = self.generate_custody_address(intent_id)?;

    // 2. Wait for MOB deposit (poll full node)
    let tx = self.wait_for_deposit(&custody_addr, amount).await?;

    // 3. Create deposit proof
    let proof = self.create_deposit_proof(&tx).await?;

    // 4. Submit proof to bridge contract
    let result = self.near_client
        .call("mob-bridge.near", "submit_deposit_proof", proof)
        .await?;

    Ok(result.tx_hash)
}
```

### 4. Risk Management

Add safeguards for production:

```rust
impl SimpleSolver {
    // Don't quote if liquidity is low
    fn check_liquidity_threshold(&self, asset: &str) -> bool {
        let available = self.liquidity.available(asset);
        let threshold = self.config.min_liquidity.get(asset).unwrap_or(&0);
        available >= *threshold
    }

    // Limit exposure per intent
    fn check_max_exposure(&self, amount: u128) -> bool {
        amount <= self.config.max_intent_size
    }

    // Monitor pending settlements
    async fn check_pending_limit(&self) -> bool {
        self.pending_quotes.read().await.len() < self.config.max_pending
    }
}
```

## Protocol Messages

### IntentRequest

Broadcast when a new intent is available:

```json
{
  "type": "IntentRequest",
  "intent_id": "intent_abc123",
  "source_asset": "MOB",
  "source_amount": 1000000000000,
  "dest_asset": "wMOB",
  "dest_address": "user.near",
  "deadline": 1699999999999
}
```

### QuoteResponse

Your solver's bid:

```json
{
  "type": "QuoteResponse",
  "intent_id": "intent_abc123",
  "solver_id": "my-solver-1",
  "dest_amount": 995000000000,
  "expiry": 1699999997500,
  "signature": "ed25519_signature_hex"
}
```

### IntentAssigned

You won the intent:

```json
{
  "type": "IntentAssigned",
  "intent_id": "intent_abc123",
  "solver_id": "my-solver-1"
}
```

### SettleResult

Settlement completion report:

```json
{
  "type": "SettleResult",
  "intent_id": "intent_abc123",
  "success": true,
  "tx_hash": "0xabc123...",
  "error": null
}
```

## Quoting Strategy

The profit margin is controlled by `MIN_PROFIT_BPS`:

```
output = input_amount × price × (1 - MIN_PROFIT_BPS / 10000)
```

Example with 50 bps (0.5%):
- Input: 100 MOB
- Price: 1.0 wMOB/MOB
- Output: 100 × 1.0 × 0.995 = **99.5 wMOB**

Higher spreads = more profit per trade but fewer wins.
Lower spreads = more wins but less profit per trade.

## Testing

### Local Development

1. Set up a local solver bus mock (or use testnet)
2. Run the solver with debug logging:

```bash
RUST_LOG=debug cargo run
```

### Testnet

Connect to the testnet solver bus:

```bash
SOLVER_BUS_URL="wss://solver-bus.testnet.near-intents.org" cargo run
```

## Troubleshooting

### "No price for X/Y"

The price feed doesn't have a rate for this pair. Add it to `PriceFeed::new()`:

```rust
prices.insert(("X".into(), "Y".into()), dec("1.5"));
prices.insert(("Y".into(), "X".into()), dec("0.667"));
```

### "Insufficient liquidity"

The solver doesn't have enough balance to fulfill the quote. Update `LiquidityManager::new()` or implement real wallet sync.

### Connection timeouts

Check your `SOLVER_BUS_URL` and ensure you have network access to the solver bus.

## Resources

- [MobileCoin Documentation](https://developers.mobilecoin.com/)
- [NEAR Intents Protocol](https://near.org/)
- [Architecture Overview](../../docs/architecture.md)

## License

Apache-2.0
