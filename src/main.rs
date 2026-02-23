use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

use proxy_rotator::{config, env, proxy, rotator};

#[tokio::main]
async fn main() -> Result<()> {
    // Determine config file path.
    let config_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config.toml"));

    let cfg = config::Config::load(&config_path)
        .with_context(|| format!("loading config from {}", config_path.display()))?;

    // Initialize logging.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cfg.log_level)),
        )
        .init();

    // Resolve config directory for relative proxies_file paths.
    let config_dir = config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));

    // Load all proxy sets.
    let proxy_sets = config::load_proxy_sets(&cfg, config_dir)?;
    let rotator = Arc::new(rotator::Rotator::new(proxy_sets));

    // Start affinity cleanup task.
    rotator::spawn_affinity_cleanup(Arc::clone(&rotator));

    // Run the proxy server.
    proxy::run_proxy(&cfg.bind_addr, rotator, env::api_key()).await
}
