//! Error types for the solver.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SolverError {
    #[error("WebSocket error: {0}")]
    WebSocket(String),

    #[error("Connection failed: {0}")]
    Connection(String),

    #[error("Unsupported pair: {source_asset} -> {dest_asset}")]
    UnsupportedPair {
        source_asset: String,
        dest_asset: String,
    },

    #[error("Insufficient liquidity for {asset}: need {needed}, have {available}")]
    InsufficientLiquidity {
        asset: String,
        needed: u128,
        available: u128,
    },

    #[error("Price feed error: {0}")]
    PriceFeed(String),

    #[error("Settlement failed: {0}")]
    Settlement(String),

    #[error("Quote timeout")]
    QuoteTimeout,

    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    #[error("Configuration error: {0}")]
    Config(String),
}
