//! Price feed for MOB quotes.

use rust_decimal::Decimal;
use std::collections::HashMap;
use std::str::FromStr;

use crate::error::SolverError;

/// Price feed for getting asset prices.
pub struct PriceFeed {
    /// Cached prices (base -> quote -> price).
    cache: HashMap<String, HashMap<String, Decimal>>,
}

impl PriceFeed {
    /// Create a new price feed.
    pub async fn new() -> Result<Self, SolverError> {
        let mut feed = Self {
            cache: HashMap::new(),
        };

        // Initialize with some default prices (in production, fetch from APIs)
        feed.set_price("MOB", "wMOB", Decimal::ONE); // 1:1 for wrapped
        feed.set_price("wMOB", "MOB", Decimal::ONE);
        feed.set_price("MOB", "USDC", Decimal::from_str("0.50").unwrap()); // Example: $0.50/MOB
        feed.set_price("USDC", "MOB", Decimal::from_str("2.0").unwrap());
        feed.set_price("MOB", "NEAR", Decimal::from_str("0.1").unwrap()); // Example: 0.1 NEAR/MOB
        feed.set_price("NEAR", "MOB", Decimal::from_str("10.0").unwrap());
        feed.set_price("wMOB", "USDC", Decimal::from_str("0.50").unwrap());
        feed.set_price("USDC", "wMOB", Decimal::from_str("2.0").unwrap());

        Ok(feed)
    }

    /// Get the price for a trading pair.
    pub fn get_price(&self, base: &str, quote: &str) -> Result<Decimal, SolverError> {
        self.cache
            .get(base)
            .and_then(|quotes| quotes.get(quote))
            .copied()
            .ok_or_else(|| SolverError::PriceFeed(format!("No price for {}/{}", base, quote)))
    }

    /// Set a price in the cache.
    fn set_price(&mut self, base: &str, quote: &str, price: Decimal) {
        self.cache
            .entry(base.to_string())
            .or_default()
            .insert(quote.to_string(), price);
    }

    /// Update prices from external sources.
    pub async fn update(&mut self) -> Result<(), SolverError> {
        // In production, fetch prices from:
        // - CoinGecko
        // - CoinMarketCap
        // - DEX aggregators
        // - etc.

        log::debug!("Updating prices from external sources...");

        Ok(())
    }
}
