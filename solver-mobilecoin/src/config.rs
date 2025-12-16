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
    /// Allow insecure (non-TLS) URLs (dev/test only).
    pub allow_insecure_urls: bool,
}

impl SolverConfig {
    /// Load configuration from environment variables.
    pub fn from_env() -> Result<Self, ConfigError> {
        let allow_insecure_urls = env::var("ALLOW_INSECURE_URLS")
            .unwrap_or_else(|_| "0".to_string())
            .to_lowercase();
        let allow_insecure_urls = matches!(allow_insecure_urls.as_str(), "1" | "true" | "yes");

        let solver_bus_url = env::var("SOLVER_BUS_URL")
            .unwrap_or_else(|_| "wss://solver-bus.near-intents.org".to_string());
        let near_rpc_url =
            env::var("NEAR_RPC_URL").unwrap_or_else(|_| "https://rpc.mainnet.near.org".to_string());
        let mob_node_url =
            env::var("MOB_NODE_URL").unwrap_or_else(|_| "https://node.mobilecoin.com".to_string());

        if !allow_insecure_urls {
            if !solver_bus_url.starts_with("wss://") {
                return Err(ConfigError::Invalid(
                    "SOLVER_BUS_URL must use wss:// (set ALLOW_INSECURE_URLS=1 to override)"
                        .to_string(),
                ));
            }
            if !near_rpc_url.starts_with("https://") {
                return Err(ConfigError::Invalid(
                    "NEAR_RPC_URL must use https:// (set ALLOW_INSECURE_URLS=1 to override)"
                        .to_string(),
                ));
            }
            if !mob_node_url.starts_with("https://") {
                return Err(ConfigError::Invalid(
                    "MOB_NODE_URL must use https:// (set ALLOW_INSECURE_URLS=1 to override)"
                        .to_string(),
                ));
            }
        }

        Ok(Self {
            solver_id: env::var("SOLVER_ID").unwrap_or_else(|_| "mob-solver-1".to_string()),
            solver_bus_url,
            near_rpc_url,
            mob_node_url,
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
            allow_insecure_urls,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_env_var(k: &str, v: &str) -> EnvGuard {
        let prev = std::env::var(k).ok();
        std::env::set_var(k, v);
        EnvGuard {
            key: k.to_string(),
            prev,
        }
    }

    struct EnvGuard {
        key: String,
        prev: Option<String>,
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(prev) = self.prev.take() {
                std::env::set_var(&self.key, prev);
            } else {
                std::env::remove_var(&self.key);
            }
        }
    }

    #[test]
    fn rejects_insecure_urls_by_default() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _g1 = with_env_var("ALLOW_INSECURE_URLS", "0");
        let _g2 = with_env_var("SOLVER_BUS_URL", "ws://localhost:1234");
        let err = SolverConfig::from_env().unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn allows_insecure_urls_with_flag() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _g1 = with_env_var("ALLOW_INSECURE_URLS", "1");
        let _g2 = with_env_var("SOLVER_BUS_URL", "ws://localhost:1234");
        let cfg = SolverConfig::from_env().unwrap();
        assert!(cfg.allow_insecure_urls);
        assert_eq!(cfg.solver_bus_url, "ws://localhost:1234");
    }
}
