//! # Simple MobileCoin Solver for NEAR Intents
//!
//! This is an example solver implementation demonstrating how to participate in the
//! MobileCoin NEAR Intents protocol. A solver (also called a market maker) provides
//! liquidity and earns profit by fulfilling swap intents.
//!
//! ## How It Works
//!
//! 1. **Connect**: The solver connects to the NEAR Intents solver bus via WebSocket
//! 2. **Quote**: When an intent is broadcast, solvers compete by providing quotes
//! 3. **Win**: The best quote wins the intent assignment
//! 4. **Settle**: The winning solver executes the swap and reports completion
//!
//! ## Supported Trading Pairs
//!
//! This example supports:
//! - MOB ↔ wMOB (wrapped MobileCoin on NEAR)
//! - MOB ↔ USDC
//! - wMOB ↔ USDC
//!
//! ## Getting Started
//!
//! ```bash
//! # Set your configuration (or use defaults)
//! export SOLVER_ID="my-solver-1"
//! export SOLVER_BUS_URL="wss://solver-bus.near-intents.org"
//! export MIN_PROFIT_BPS="50"  # 0.5% minimum profit
//!
//! # Run the solver
//! cargo run
//! ```
//!
//! ## Customization Points
//!
//! To build your own solver, you'll want to customize:
//! - [`PriceFeed`]: Integrate real price sources (CoinGecko, DEX aggregators)
//! - [`LiquidityManager`]: Sync with your actual wallet balances
//! - [`SettlementExecutor`]: Implement actual blockchain transactions
//! - Quoting strategy: Adjust spread, timing, and pair selection

use std::collections::HashMap;
use std::env;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tokio_tungstenite::{connect_async, tungstenite::Message};

// =============================================================================
// Configuration
// =============================================================================

/// Solver configuration - customize these for your deployment.
///
/// All values can be set via environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    /// Unique identifier for this solver (used in quotes and assignments)
    pub solver_id: String,

    /// WebSocket URL of the NEAR Intents solver bus
    pub solver_bus_url: String,

    /// Minimum profit margin in basis points (100 bps = 1%)
    /// Quotes will include at least this much profit
    pub min_profit_bps: u32,

    /// How long quotes are valid (milliseconds)
    pub quote_validity_ms: u64,
}

impl Config {
    /// Load configuration from environment variables with sensible defaults.
    pub fn from_env() -> Self {
        Self {
            solver_id: env::var("SOLVER_ID").unwrap_or_else(|_| "simple-solver-1".to_string()),
            solver_bus_url: env::var("SOLVER_BUS_URL")
                .unwrap_or_else(|_| "wss://solver-bus.near-intents.org".to_string()),
            min_profit_bps: env::var("MIN_PROFIT_BPS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(50), // 0.5% default
            quote_validity_ms: env::var("QUOTE_VALIDITY_MS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(2500), // 2.5 seconds default
        }
    }
}

// =============================================================================
// Solver Bus Protocol Messages
// =============================================================================

/// Messages exchanged on the solver bus.
///
/// The solver bus uses JSON-encoded WebSocket messages with a "type" field
/// for message discrimination.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SolverBusMessage {
    /// A new intent is available for quoting.
    ///
    /// Solvers should respond with a QuoteResponse if they want to
    /// compete for this intent.
    IntentRequest {
        intent_id: String,
        source_asset: String,
        source_amount: u128,
        dest_asset: String,
        dest_address: String,
        deadline: u64,
    },

    /// A solver's quote in response to an IntentRequest.
    QuoteResponse {
        intent_id: String,
        solver_id: String,
        dest_amount: u128,
        expiry: u64,
        signature: String,
    },

    /// Notification that an intent has been assigned to a solver.
    ///
    /// The winning solver should begin settlement.
    IntentAssigned {
        intent_id: String,
        solver_id: String,
    },

    /// Request for a solver to settle an assigned intent.
    SettleRequest {
        intent_id: String,
    },

    /// Report of settlement completion or failure.
    SettleResult {
        intent_id: String,
        success: bool,
        tx_hash: Option<String>,
        error: Option<String>,
    },

    /// Keep-alive ping (server → solver)
    Ping,

    /// Keep-alive pong (solver → server)
    Pong,
}

// =============================================================================
// Price Feed
// =============================================================================

/// Simple price feed for getting exchange rates.
///
/// ## Production Implementation
///
/// In production, you should:
/// - Fetch prices from multiple sources (CoinGecko, CoinMarketCap, DEX aggregators)
/// - Cache prices with appropriate TTL
/// - Handle stale/unavailable prices gracefully
/// - Consider using TWAP or VWAP for more stable pricing
pub struct PriceFeed {
    prices: HashMap<(String, String), Decimal>,
}

impl PriceFeed {
    /// Create a new price feed with example prices.
    ///
    /// **Note**: These are hardcoded example prices. In production,
    /// fetch real-time prices from external APIs.
    pub fn new() -> Self {
        let mut prices = HashMap::new();

        // MOB ↔ wMOB is always 1:1 (wrapped/unwrapped)
        prices.insert(("MOB".into(), "wMOB".into()), Decimal::ONE);
        prices.insert(("wMOB".into(), "MOB".into()), Decimal::ONE);

        // Example prices - replace with real price feeds!
        // Assuming MOB ≈ $0.50 USD
        prices.insert(("MOB".into(), "USDC".into()), dec("0.50"));
        prices.insert(("USDC".into(), "MOB".into()), dec("2.0"));
        prices.insert(("wMOB".into(), "USDC".into()), dec("0.50"));
        prices.insert(("USDC".into(), "wMOB".into()), dec("2.0"));

        // MOB ↔ NEAR (assuming NEAR ≈ $5.00, MOB ≈ $0.50)
        prices.insert(("MOB".into(), "NEAR".into()), dec("0.1"));
        prices.insert(("NEAR".into(), "MOB".into()), dec("10.0"));

        Self { prices }
    }

    /// Get the exchange rate for a trading pair.
    ///
    /// Returns the amount of `quote` asset per unit of `base` asset.
    pub fn get_price(&self, base: &str, quote: &str) -> Option<Decimal> {
        self.prices.get(&(base.to_string(), quote.to_string())).copied()
    }
}

// Helper to create Decimal from string
fn dec(s: &str) -> Decimal {
    s.parse().expect("Invalid decimal")
}

// =============================================================================
// Liquidity Manager
// =============================================================================

/// Tracks available liquidity across assets.
///
/// ## Production Implementation
///
/// In production, you should:
/// - Sync balances from actual wallets (MOB wallet, NEAR account)
/// - Track pending settlements to avoid over-committing
/// - Set up alerts for low liquidity
/// - Implement automatic rebalancing
pub struct LiquidityManager {
    /// Current balances by asset (in smallest units)
    balances: HashMap<String, u128>,
    /// Reserved amounts for pending settlements
    reserved: HashMap<String, u128>,
}

impl LiquidityManager {
    /// Create a new liquidity manager with example balances.
    ///
    /// **Note**: These are hardcoded example balances. In production,
    /// sync with your actual wallet balances.
    pub fn new() -> Self {
        let mut balances = HashMap::new();

        // Example balances (in smallest units):
        // MOB has 12 decimal places (picoMOB)
        // 100 MOB = 100 * 10^12 picoMOB
        balances.insert("MOB".to_string(), 100_000_000_000_000);   // 100 MOB
        balances.insert("wMOB".to_string(), 100_000_000_000_000);  // 100 wMOB
        balances.insert("USDC".to_string(), 10_000_000_000);       // 10,000 USDC (6 decimals)
        balances.insert("NEAR".to_string(), 1_000_000_000_000_000_000_000_000); // 1000 NEAR (24 decimals)

        Self {
            balances,
            reserved: HashMap::new(),
        }
    }

    /// Get available (non-reserved) liquidity for an asset.
    pub fn available(&self, asset: &str) -> u128 {
        let balance = self.balances.get(asset).copied().unwrap_or(0);
        let reserved = self.reserved.get(asset).copied().unwrap_or(0);
        balance.saturating_sub(reserved)
    }

    /// Reserve liquidity for a pending settlement.
    pub fn reserve(&mut self, asset: &str, amount: u128) -> bool {
        if self.available(asset) >= amount {
            *self.reserved.entry(asset.to_string()).or_insert(0) += amount;
            true
        } else {
            false
        }
    }

    /// Release reserved liquidity (on settlement completion or cancellation).
    pub fn release(&mut self, asset: &str, amount: u128) {
        if let Some(reserved) = self.reserved.get_mut(asset) {
            *reserved = reserved.saturating_sub(amount);
        }
    }

    /// Update balance after settlement.
    pub fn update_balance(&mut self, asset: &str, delta: i128) {
        let balance = self.balances.entry(asset.to_string()).or_insert(0);
        if delta >= 0 {
            *balance = balance.saturating_add(delta as u128);
        } else {
            *balance = balance.saturating_sub((-delta) as u128);
        }
    }
}

// =============================================================================
// Settlement Types
// =============================================================================

/// The type of settlement required for an intent.
#[derive(Debug, Clone)]
pub enum SettlementType {
    /// MOB → wMOB: User deposits MOB, receives wMOB on NEAR
    MobToWmob,
    /// wMOB → MOB: User burns wMOB, receives MOB
    WmobToMob,
    /// wMOB → Other: Swap wMOB for another NEAR token
    WmobToOther { dest_asset: String },
    /// Other → wMOB: Swap a NEAR token for wMOB
    OtherToWmob { source_asset: String },
}

impl SettlementType {
    /// Determine the settlement type from the trading pair.
    pub fn from_pair(source: &str, dest: &str) -> Option<Self> {
        match (source, dest) {
            ("MOB", "wMOB") => Some(Self::MobToWmob),
            ("wMOB", "MOB") => Some(Self::WmobToMob),
            ("wMOB", dest) => Some(Self::WmobToOther { dest_asset: dest.to_string() }),
            (source, "wMOB") => Some(Self::OtherToWmob { source_asset: source.to_string() }),
            _ => None,
        }
    }
}

// =============================================================================
// The Solver
// =============================================================================

/// The main solver implementation.
///
/// This solver:
/// 1. Connects to the solver bus
/// 2. Listens for intent requests
/// 3. Generates competitive quotes
/// 4. Executes settlements when assigned
pub struct SimpleSolver {
    config: Config,
    liquidity: Arc<RwLock<LiquidityManager>>,
    price_feed: Arc<RwLock<PriceFeed>>,
    /// Pending quotes we've submitted (intent_id → our quote details)
    pending_quotes: Arc<RwLock<HashMap<String, PendingQuote>>>,
}

/// Details of a quote we've submitted.
#[derive(Debug, Clone)]
struct PendingQuote {
    source_asset: String,
    source_amount: u128,
    dest_asset: String,
    dest_amount: u128,
    dest_address: String,
}

impl SimpleSolver {
    /// Create a new solver instance.
    pub fn new(config: Config) -> Self {
        Self {
            config,
            liquidity: Arc::new(RwLock::new(LiquidityManager::new())),
            price_feed: Arc::new(RwLock::new(PriceFeed::new())),
            pending_quotes: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Run the solver - connects to solver bus and processes messages.
    pub async fn run(&self) -> Result<(), SolverError> {
        log::info!("Connecting to solver bus at {}", self.config.solver_bus_url);

        // Connect to WebSocket
        let (ws_stream, _) = connect_async(&self.config.solver_bus_url)
            .await
            .map_err(|e| SolverError::Connection(e.to_string()))?;

        log::info!("✓ Connected to solver bus");
        log::info!("Solver ID: {}", self.config.solver_id);
        log::info!("Min profit: {} bps", self.config.min_profit_bps);

        let (mut write, mut read) = ws_stream.split();

        // Main message loop
        while let Some(msg) = read.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    match serde_json::from_str::<SolverBusMessage>(&text) {
                        Ok(bus_msg) => {
                            if let Err(e) = self.handle_message(bus_msg, &mut write).await {
                                log::error!("Error handling message: {}", e);
                            }
                        }
                        Err(e) => {
                            log::warn!("Failed to parse message: {} (raw: {})", e, text);
                        }
                    }
                }
                Ok(Message::Ping(data)) => {
                    let _ = write.send(Message::Pong(data)).await;
                }
                Ok(Message::Close(_)) => {
                    log::info!("Connection closed by server");
                    break;
                }
                Err(e) => {
                    log::error!("WebSocket error: {}", e);
                    break;
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Handle an incoming solver bus message.
    async fn handle_message<W>(&self, msg: SolverBusMessage, write: &mut W) -> Result<(), SolverError>
    where
        W: SinkExt<Message> + Unpin,
        W::Error: std::fmt::Display,
    {
        match msg {
            // ─────────────────────────────────────────────────────────────────
            // New intent available - generate a quote if we can
            // ─────────────────────────────────────────────────────────────────
            SolverBusMessage::IntentRequest {
                intent_id,
                source_asset,
                source_amount,
                dest_asset,
                dest_address,
                deadline,
            } => {
                log::debug!(
                    "Intent {}: {} {} → {} (to: {})",
                    intent_id, source_amount, source_asset, dest_asset, dest_address
                );

                // Check if we support this pair
                if !self.supports_pair(&source_asset, &dest_asset) {
                    log::debug!("Skipping unsupported pair: {} → {}", source_asset, dest_asset);
                    return Ok(());
                }

                // Check deadline
                let now = current_timestamp_ms();
                if deadline <= now {
                    log::debug!("Skipping expired intent {}", intent_id);
                    return Ok(());
                }

                // Try to generate a quote
                match self.generate_quote(
                    &intent_id,
                    &source_asset,
                    source_amount,
                    &dest_asset,
                    &dest_address,
                ).await {
                    Ok((dest_amount, expiry, signature)) => {
                        // Store pending quote
                        self.pending_quotes.write().await.insert(
                            intent_id.clone(),
                            PendingQuote {
                                source_asset: source_asset.clone(),
                                source_amount,
                                dest_asset: dest_asset.clone(),
                                dest_amount,
                                dest_address: dest_address.clone(),
                            },
                        );

                        // Send quote
                        let response = SolverBusMessage::QuoteResponse {
                            intent_id: intent_id.clone(),
                            solver_id: self.config.solver_id.clone(),
                            dest_amount,
                            expiry,
                            signature,
                        };

                        let json = serde_json::to_string(&response)
                            .map_err(|e| SolverError::Serialization(e.to_string()))?;

                        write.send(Message::Text(json)).await
                            .map_err(|e| SolverError::WebSocket(e.to_string()))?;

                        log::info!(
                            "📤 Quoted intent {}: {} {} for {} {}",
                            intent_id, source_amount, source_asset, dest_amount, dest_asset
                        );
                    }
                    Err(e) => {
                        log::debug!("Cannot quote {}: {}", intent_id, e);
                    }
                }
            }

            // ─────────────────────────────────────────────────────────────────
            // We won an intent - execute settlement
            // ─────────────────────────────────────────────────────────────────
            SolverBusMessage::IntentAssigned { intent_id, solver_id } => {
                if solver_id != self.config.solver_id {
                    // Not for us
                    return Ok(());
                }

                log::info!("🎉 Won intent {}!", intent_id);

                // Get our pending quote
                let quote = self.pending_quotes.write().await.remove(&intent_id);

                match quote {
                    Some(q) => {
                        // Execute settlement
                        let result = self.execute_settlement(&intent_id, &q).await;

                        let response = match result {
                            Ok(tx_hash) => {
                                log::info!("✅ Settlement complete: {}", tx_hash);
                                SolverBusMessage::SettleResult {
                                    intent_id,
                                    success: true,
                                    tx_hash: Some(tx_hash),
                                    error: None,
                                }
                            }
                            Err(e) => {
                                log::error!("❌ Settlement failed: {}", e);
                                SolverBusMessage::SettleResult {
                                    intent_id,
                                    success: false,
                                    tx_hash: None,
                                    error: Some(e.to_string()),
                                }
                            }
                        };

                        let json = serde_json::to_string(&response)
                            .map_err(|e| SolverError::Serialization(e.to_string()))?;

                        write.send(Message::Text(json)).await
                            .map_err(|e| SolverError::WebSocket(e.to_string()))?;
                    }
                    None => {
                        log::error!("No pending quote for assigned intent {}", intent_id);
                    }
                }
            }

            // ─────────────────────────────────────────────────────────────────
            // Keep-alive
            // ─────────────────────────────────────────────────────────────────
            SolverBusMessage::Ping => {
                let pong = serde_json::to_string(&SolverBusMessage::Pong)
                    .map_err(|e| SolverError::Serialization(e.to_string()))?;

                write.send(Message::Text(pong)).await
                    .map_err(|e| SolverError::WebSocket(e.to_string()))?;
            }

            _ => {}
        }

        Ok(())
    }

    /// Check if we support a trading pair.
    fn supports_pair(&self, source: &str, dest: &str) -> bool {
        // Customize this based on what pairs you want to support
        matches!(
            (source, dest),
            // Direct MOB ↔ wMOB
            ("MOB", "wMOB") | ("wMOB", "MOB") |
            // MOB ↔ stables
            ("MOB", "USDC") | ("USDC", "MOB") |
            // wMOB ↔ stables
            ("wMOB", "USDC") | ("USDC", "wMOB") |
            // MOB ↔ NEAR
            ("MOB", "NEAR") | ("NEAR", "MOB")
        )
    }

    /// Generate a quote for an intent.
    ///
    /// Returns (dest_amount, expiry_timestamp, signature)
    async fn generate_quote(
        &self,
        intent_id: &str,
        source_asset: &str,
        source_amount: u128,
        dest_asset: &str,
        _dest_address: &str,
    ) -> Result<(u128, u64, String), SolverError> {
        // 1. Check liquidity
        let liquidity = self.liquidity.read().await;
        let price_feed = self.price_feed.read().await;

        // Get price
        let price = price_feed
            .get_price(source_asset, dest_asset)
            .ok_or_else(|| SolverError::NoPrice(source_asset.to_string(), dest_asset.to_string()))?;

        // Calculate gross output
        let source_dec = Decimal::from(source_amount);
        let gross_output = source_dec * price;
        let gross_output_u128: u128 = gross_output.to_string().parse().unwrap_or(0);

        // Check we have enough liquidity
        let available = liquidity.available(dest_asset);
        if available < gross_output_u128 {
            return Err(SolverError::InsufficientLiquidity {
                asset: dest_asset.to_string(),
                needed: gross_output_u128,
                available,
            });
        }

        // 2. Apply profit margin
        let spread = Decimal::from(self.config.min_profit_bps) / Decimal::from(10000);
        let net_output = gross_output * (Decimal::ONE - spread);
        let dest_amount: u128 = net_output.to_string().parse().unwrap_or(0);

        // 3. Calculate expiry
        let now = current_timestamp_ms();
        let expiry = now + self.config.quote_validity_ms;

        // 4. Sign the quote
        // In production, use proper Ed25519 signing with your solver key
        let signature = format!("sig_{}_{}", intent_id, self.config.solver_id);

        Ok((dest_amount, expiry, signature))
    }

    /// Execute settlement for a won intent.
    ///
    /// ## Production Implementation
    ///
    /// This is where the real work happens. You need to:
    ///
    /// ### For MOB → wMOB (deposit):
    /// 1. Wait for user's MOB deposit to custody address
    /// 2. Create deposit proof (signatures from bridge authorities)
    /// 3. Submit proof to bridge contract
    /// 4. Bridge mints wMOB to user's NEAR account
    ///
    /// ### For wMOB → MOB (withdrawal):
    /// 1. User has already locked wMOB
    /// 2. Bridge burns wMOB
    /// 3. Generate one-time MOB address using intent_id
    /// 4. Send MOB to user's stealth address
    /// 5. Submit completion proof
    ///
    /// ### For wMOB ↔ Other:
    /// 1. Execute swap on NEAR DEX (Ref Finance, etc.)
    /// 2. Transfer result to user
    async fn execute_settlement(
        &self,
        intent_id: &str,
        quote: &PendingQuote,
    ) -> Result<String, SolverError> {
        log::info!(
            "Executing settlement for {}: {} {} → {} {}",
            intent_id,
            quote.source_amount, quote.source_asset,
            quote.dest_amount, quote.dest_asset
        );

        let settlement_type = SettlementType::from_pair(&quote.source_asset, &quote.dest_asset)
            .ok_or_else(|| SolverError::UnsupportedPair {
                source_asset: quote.source_asset.clone(),
                dest_asset: quote.dest_asset.clone(),
            })?;

        // Update liquidity tracking
        {
            let mut liquidity = self.liquidity.write().await;
            // We're giving out dest_asset
            liquidity.update_balance(&quote.dest_asset, -(quote.dest_amount as i128));
            // We're receiving source_asset
            liquidity.update_balance(&quote.source_asset, quote.source_amount as i128);
        }

        // In production, execute the actual settlement here
        match settlement_type {
            SettlementType::MobToWmob => {
                log::info!("MOB→wMOB: Would wait for MOB deposit and mint wMOB");
                // TODO: Implement actual MOB deposit monitoring and wMOB minting
            }
            SettlementType::WmobToMob => {
                log::info!("wMOB→MOB: Would burn wMOB and send MOB to {}", quote.dest_address);
                // TODO: Implement actual wMOB burning and MOB withdrawal
            }
            SettlementType::WmobToOther { ref dest_asset } => {
                log::info!("wMOB→{}: Would swap on DEX", dest_asset);
                // TODO: Implement DEX swap
            }
            SettlementType::OtherToWmob { ref source_asset } => {
                log::info!("{}→wMOB: Would swap on DEX", source_asset);
                // TODO: Implement DEX swap
            }
        }

        // Return transaction hash (placeholder)
        Ok(format!("tx_{}_{}", intent_id, current_timestamp_ms()))
    }
}

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur in the solver.
#[derive(Debug, thiserror::Error)]
pub enum SolverError {
    #[error("Connection failed: {0}")]
    Connection(String),

    #[error("WebSocket error: {0}")]
    WebSocket(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("No price for {0}/{1}")]
    NoPrice(String, String),

    #[error("Insufficient {asset} liquidity: need {needed}, have {available}")]
    InsufficientLiquidity {
        asset: String,
        needed: u128,
        available: u128,
    },

    #[error("Unsupported pair: {source_asset} -> {dest_asset}")]
    UnsupportedPair { source_asset: String, dest_asset: String },

    #[error("Settlement failed: {0}")]
    Settlement(String),
}

// =============================================================================
// Utilities
// =============================================================================

/// Get current timestamp in milliseconds.
fn current_timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

// =============================================================================
// Main Entry Point
// =============================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    ).init();

    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║       Simple MobileCoin Solver for NEAR Intents               ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");
    println!();

    // Load configuration
    let config = Config::from_env();

    log::info!("Configuration:");
    log::info!("  Solver ID:     {}", config.solver_id);
    log::info!("  Solver Bus:    {}", config.solver_bus_url);
    log::info!("  Min Profit:    {} bps ({}%)", config.min_profit_bps, config.min_profit_bps as f64 / 100.0);
    log::info!("  Quote Validity: {}ms", config.quote_validity_ms);
    println!();

    // Create and run solver
    let solver = SimpleSolver::new(config);

    log::info!("Starting solver...");
    solver.run().await?;

    Ok(())
}
