//! Liquidity management for the solver.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// Manages solver liquidity across assets.
pub struct LiquidityManager {
    /// Available balances by asset.
    balances: HashMap<String, u128>,
    /// Reserved amounts (pending settlements).
    reserved: HashMap<String, u128>,
}

impl LiquidityManager {
    /// Create a new liquidity manager.
    pub fn new() -> Self {
        let mut balances = HashMap::new();

        // Initialize with some default liquidity (in production, sync from wallets)
        balances.insert("MOB".to_string(), 100_000_000_000_000); // 100 MOB
        balances.insert("wMOB".to_string(), 100_000_000_000_000); // 100 wMOB
        balances.insert("USDC".to_string(), 10_000_000_000); // 10,000 USDC (6 decimals)
        balances.insert("NEAR".to_string(), 1_000_000_000_000_000_000_000_000); // 1000 NEAR

        Self {
            balances,
            reserved: HashMap::new(),
        }
    }

    /// Get available liquidity for an asset.
    pub fn available_liquidity(&self, asset: &str) -> u128 {
        let balance = self.balances.get(asset).copied().unwrap_or(0);
        let reserved = self.reserved.get(asset).copied().unwrap_or(0);
        balance.saturating_sub(reserved)
    }

    /// Reserve liquidity for a pending settlement.
    pub fn reserve(&mut self, asset: &str, amount: u128) -> Result<ReservationId, LiquidityError> {
        let available = self.available_liquidity(asset);
        if available < amount {
            return Err(LiquidityError::InsufficientLiquidity {
                asset: asset.to_string(),
                needed: amount,
                available,
            });
        }

        let reserved = self.reserved.entry(asset.to_string()).or_insert(0);
        *reserved += amount;

        Ok(ReservationId::new())
    }

    /// Release reserved liquidity.
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

    /// Sync balances from on-chain state.
    pub async fn sync(&mut self) -> Result<(), LiquidityError> {
        // In production:
        // 1. Query MOB wallet balance
        // 2. Query wMOB balance on NEAR
        // 3. Query other token balances
        // 4. Update self.balances

        log::debug!("Syncing liquidity from chain...");
        Ok(())
    }
}

/// Unique identifier for a liquidity reservation.
#[derive(Debug, Clone, Copy)]
pub struct ReservationId(u64);

impl ReservationId {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        Self(COUNTER.fetch_add(1, Ordering::SeqCst))
    }
}

/// Liquidity errors.
#[derive(Debug)]
pub enum LiquidityError {
    InsufficientLiquidity {
        asset: String,
        needed: u128,
        available: u128,
    },
    SyncError(String),
}

impl std::fmt::Display for LiquidityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LiquidityError::InsufficientLiquidity {
                asset,
                needed,
                available,
            } => {
                write!(
                    f,
                    "Insufficient {} liquidity: need {}, have {}",
                    asset, needed, available
                )
            }
            LiquidityError::SyncError(msg) => write!(f, "Sync error: {}", msg),
        }
    }
}

impl std::error::Error for LiquidityError {}
