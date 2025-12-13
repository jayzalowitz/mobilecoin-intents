//! MobileCoin Solver for NEAR Intents
//!
//! This is the main entry point for the MOB solver service.
//! It connects to the NEAR Intents solver bus and provides
//! liquidity for MOB swaps.

use std::sync::Arc;
use tokio::sync::RwLock;

mod config;
mod error;
mod liquidity;
mod price_feed;
mod quote;
mod settlement;
mod solver;

use config::SolverConfig;
use solver::MobSolver;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();
    log::info!("Starting MobileCoin Solver...");

    // Load configuration
    let config = SolverConfig::from_env()?;
    log::info!("Loaded configuration: solver_id={}", config.solver_id);

    // Create solver
    let solver = MobSolver::new(config).await?;
    log::info!("Solver initialized");

    // Run the solver
    log::info!("Connecting to solver bus...");
    solver.run().await?;

    Ok(())
}
