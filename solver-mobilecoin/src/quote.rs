//! Quote generation for MOB intents.

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

use crate::config::SolverConfig;
use crate::error::SolverError;
use crate::liquidity::LiquidityManager;
use crate::price_feed::PriceFeed;

/// Quote request from the solver bus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteRequest {
    pub intent_id: String,
    pub source_asset: String,
    pub source_amount: u128,
    pub dest_asset: String,
    pub dest_address: String,
    pub deadline: u64,
}

/// Quote response to send back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteResponse {
    pub intent_id: String,
    pub solver_id: String,
    pub dest_amount: u128,
    pub expiry: u64,
    pub signature: String,
}

/// Generate a quote for an intent.
pub async fn generate_quote(
    request: &QuoteRequest,
    config: &SolverConfig,
    liquidity: &LiquidityManager,
    price_feed: &PriceFeed,
) -> Result<QuoteResponse, SolverError> {
    // Check liquidity
    let available = liquidity.available_liquidity(&request.dest_asset);
    let needed = estimate_output(request, price_feed)?;

    if available < needed {
        return Err(SolverError::InsufficientLiquidity {
            asset: request.dest_asset.clone(),
            needed,
            available,
        });
    }

    // Get price and calculate output
    let dest_amount = calculate_output(request, config, price_feed)?;

    // Create quote
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let expiry = now + config.quote_timeout_ms;

    // Sign the quote (simplified - in production use proper signing)
    let signature = format!("sig_{}_{}", request.intent_id, config.solver_id);

    Ok(QuoteResponse {
        intent_id: request.intent_id.clone(),
        solver_id: config.solver_id.clone(),
        dest_amount,
        expiry,
        signature,
    })
}

/// Estimate the output amount (for liquidity check).
fn estimate_output(request: &QuoteRequest, price_feed: &PriceFeed) -> Result<u128, SolverError> {
    // Get price
    let price = price_feed.get_price(&request.source_asset, &request.dest_asset)?;

    // Calculate gross output
    let source_decimal = Decimal::from(request.source_amount);
    let output_decimal = source_decimal * price;

    Ok(output_decimal.to_string().parse().unwrap_or(0))
}

/// Calculate the actual output amount with spread.
fn calculate_output(
    request: &QuoteRequest,
    config: &SolverConfig,
    price_feed: &PriceFeed,
) -> Result<u128, SolverError> {
    // Get price
    let price = price_feed.get_price(&request.source_asset, &request.dest_asset)?;

    // Calculate gross output
    let source_decimal = Decimal::from(request.source_amount);
    let gross_output = source_decimal * price;

    // Apply spread (profit margin)
    let spread = Decimal::from(config.min_profit_bps) / Decimal::from(10000);
    let net_output = gross_output * (Decimal::ONE - spread);

    Ok(net_output.to_string().parse().unwrap_or(0))
}
