//! Solver configuration.

use std::env;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Missing environment variable: {0}")]
    MissingEnv(String),
    #[error("Invalid configuration: {0}")]
    Invalid(String),
}

/// Solver configuration loaded from environment.
#[derive(Debug, Clone)]
pub struct SolverConfig {
    /// Unique solver identifier.
    pub solver_id: String,
    /// Solver bus WebSocket URL.
    pub solver_bus_url: String,
    /// NEAR RPC URL.
    pub near_rpc_url: String,
    /// MobileCoin node URL.
    pub mob_node_url: String,
    /// Minimum profit margin (basis points).
    pub min_profit_bps: u32,
    /// Maximum slippage tolerance (basis points).
    pub max_slippage_bps: u32,
    /// Quote timeout (milliseconds).
    pub quote_timeout_ms: u64,
}

impl SolverConfig {
    /// Load configuration from environment variables.
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            solver_id: env::var("SOLVER_ID")
                .unwrap_or_else(|_| "mob-solver-1".to_string()),
            solver_bus_url: env::var("SOLVER_BUS_URL")
                .unwrap_or_else(|_| "wss://solver-bus.near-intents.org".to_string()),
            near_rpc_url: env::var("NEAR_RPC_URL")
                .unwrap_or_else(|_| "https://rpc.mainnet.near.org".to_string()),
            mob_node_url: env::var("MOB_NODE_URL")
                .unwrap_or_else(|_| "https://node.mobilecoin.com".to_string()),
            min_profit_bps: env::var("MIN_PROFIT_BPS")
                .unwrap_or_else(|_| "50".to_string())
                .parse()
                .map_err(|_| ConfigError::Invalid("MIN_PROFIT_BPS".to_string()))?,
            max_slippage_bps: env::var("MAX_SLIPPAGE_BPS")
                .unwrap_or_else(|_| "100".to_string())
                .parse()
                .map_err(|_| ConfigError::Invalid("MAX_SLIPPAGE_BPS".to_string()))?,
            quote_timeout_ms: env::var("QUOTE_TIMEOUT_MS")
                .unwrap_or_else(|_| "2500".to_string())
                .parse()
                .map_err(|_| ConfigError::Invalid("QUOTE_TIMEOUT_MS".to_string()))?,
        })
    }
}
