//! Main solver implementation.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use futures::{SinkExt, StreamExt};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use serde::{Deserialize, Serialize};

use crate::config::SolverConfig;
use crate::error::SolverError;
use crate::quote::{QuoteRequest, QuoteResponse, generate_quote};
use crate::liquidity::LiquidityManager;
use crate::price_feed::PriceFeed;

/// Messages on the solver bus.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SolverBusMessage {
    /// New intent available for quoting.
    IntentRequest(QuoteRequest),
    /// Quote response from solver.
    QuoteResponse(QuoteResponse),
    /// Intent assigned to solver.
    IntentAssigned { intent_id: String, solver_id: String },
    /// Settlement request.
    SettleRequest { intent_id: String },
    /// Settlement result.
    SettleResult { intent_id: String, success: bool, tx_hash: Option<String> },
    /// Ping for keepalive.
    Ping,
    /// Pong response.
    Pong,
}

/// The MobileCoin solver.
pub struct MobSolver {
    config: SolverConfig,
    liquidity: Arc<RwLock<LiquidityManager>>,
    price_feed: Arc<RwLock<PriceFeed>>,
    pending_quotes: Arc<RwLock<HashMap<String, QuoteResponse>>>,
}

impl MobSolver {
    /// Create a new solver instance.
    pub async fn new(config: SolverConfig) -> Result<Self, SolverError> {
        let liquidity = LiquidityManager::new();
        let price_feed = PriceFeed::new().await?;

        Ok(Self {
            config,
            liquidity: Arc::new(RwLock::new(liquidity)),
            price_feed: Arc::new(RwLock::new(price_feed)),
            pending_quotes: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Run the solver, connecting to the solver bus.
    pub async fn run(&self) -> Result<(), SolverError> {
        log::info!("Connecting to solver bus at {}", self.config.solver_bus_url);

        let (ws_stream, _) = connect_async(&self.config.solver_bus_url)
            .await
            .map_err(|e| SolverError::Connection(e.to_string()))?;

        let (mut write, mut read) = ws_stream.split();

        log::info!("Connected to solver bus");

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
                            log::warn!("Failed to parse message: {}", e);
                        }
                    }
                }
                Ok(Message::Ping(data)) => {
                    if let Err(e) = write.send(Message::Pong(data)).await {
                        log::error!("Failed to send pong: {}", e);
                    }
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

    /// Handle an incoming message.
    async fn handle_message<S>(
        &self,
        msg: SolverBusMessage,
        write: &mut S,
    ) -> Result<(), SolverError>
    where
        S: SinkExt<Message> + Unpin,
        S::Error: std::fmt::Display,
    {
        match msg {
            SolverBusMessage::IntentRequest(request) => {
                log::debug!("Received intent request: {}", request.intent_id);

                // Check if we support this pair
                if self.supports_pair(&request.source_asset, &request.dest_asset) {
                    // Generate quote
                    let liquidity = self.liquidity.read().await;
                    let price_feed = self.price_feed.read().await;

                    match generate_quote(
                        &request,
                        &self.config,
                        &liquidity,
                        &price_feed,
                    ).await {
                        Ok(quote) => {
                            // Store pending quote
                            self.pending_quotes
                                .write()
                                .await
                                .insert(request.intent_id.clone(), quote.clone());

                            // Send quote
                            let msg = serde_json::to_string(&SolverBusMessage::QuoteResponse(quote))
                                .map_err(|e| SolverError::InvalidMessage(e.to_string()))?;

                            write
                                .send(Message::Text(msg))
                                .await
                                .map_err(|e| SolverError::WebSocket(e.to_string()))?;
                        }
                        Err(e) => {
                            log::debug!("Cannot quote intent {}: {}", request.intent_id, e);
                        }
                    }
                }
            }

            SolverBusMessage::IntentAssigned { intent_id, solver_id } => {
                if solver_id == self.config.solver_id {
                    log::info!("Intent {} assigned to us!", intent_id);

                    // Get the pending quote
                    let quote = self.pending_quotes
                        .write()
                        .await
                        .remove(&intent_id);

                    if let Some(quote) = quote {
                        // Execute settlement
                        match self.execute_settlement(&intent_id, &quote).await {
                            Ok(tx_hash) => {
                                let result = SolverBusMessage::SettleResult {
                                    intent_id: intent_id.clone(),
                                    success: true,
                                    tx_hash: Some(tx_hash),
                                };

                                let msg = serde_json::to_string(&result)
                                    .map_err(|e| SolverError::InvalidMessage(e.to_string()))?;

                                write
                                    .send(Message::Text(msg))
                                    .await
                                    .map_err(|e| SolverError::WebSocket(e.to_string()))?;
                            }
                            Err(e) => {
                                log::error!("Settlement failed: {}", e);
                                let result = SolverBusMessage::SettleResult {
                                    intent_id,
                                    success: false,
                                    tx_hash: None,
                                };

                                let msg = serde_json::to_string(&result)
                                    .map_err(|e| SolverError::InvalidMessage(e.to_string()))?;

                                write
                                    .send(Message::Text(msg))
                                    .await
                                    .map_err(|e| SolverError::WebSocket(e.to_string()))?;
                            }
                        }
                    }
                }
            }

            SolverBusMessage::Ping => {
                let pong = serde_json::to_string(&SolverBusMessage::Pong)
                    .map_err(|e| SolverError::InvalidMessage(e.to_string()))?;

                write
                    .send(Message::Text(pong))
                    .await
                    .map_err(|e| SolverError::WebSocket(e.to_string()))?;
            }

            _ => {}
        }

        Ok(())
    }

    /// Check if we support a trading pair.
    fn supports_pair(&self, source: &str, dest: &str) -> bool {
        matches!(
            (source, dest),
            ("MOB", "wMOB")
                | ("wMOB", "MOB")
                | ("MOB", "USDC")
                | ("USDC", "MOB")
                | ("MOB", "NEAR")
                | ("NEAR", "MOB")
                | ("wMOB", _)
                | (_, "wMOB")
        )
    }

    /// Execute a settlement for a won intent.
    async fn execute_settlement(
        &self,
        intent_id: &str,
        quote: &QuoteResponse,
    ) -> Result<String, SolverError> {
        log::info!("Executing settlement for intent {}", intent_id);

        // In a real implementation, this would:
        // 1. Check settlement type
        // 2. Execute appropriate transactions
        // 3. Return transaction hash

        // For now, return a placeholder
        Ok(format!("tx_{}", intent_id))
    }
}
