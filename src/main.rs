//! Testnet KeyPackage Registry service.
//!
//! Throwaway service for issue #110 — replaced by λLEZ in v0.3. No libchat-core
//! dependency; the embedded logos-delivery node comes from the sibling libchat
//! checkout's transport crate.
//!
//! Submissions arrive on either write path — both feed the same verification +
//! storage pipeline (`submit`):
//!   - HTTP POST (below), synchronous and acknowledged;
//!   - logos-delivery subscription (`ingest`, disable with `--no-delivery`):
//!     clients publish the same JSON on the store content topics.
//!
//! HTTP wire:
//!   POST /v0/keypackage             — submit a signed keypackage bundle
//!   GET  /v0/keypackage/{device_id} — fetch the latest stored keypackage bundle
//!   POST /v0/account                — upsert a signed account device-list bundle
//!   GET  /v0/account/{account_pub}  — fetch the account device-list bundle

mod handlers;
mod ingest;
mod store;
mod submit;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use tracing_subscriber::EnvFilter;

use store::Store;

#[derive(Parser, Debug)]
#[command(name = "chat-store", about = "Testnet Chat Store (KeyPackage + account directory)")]
struct Cli {
    /// Address to bind the HTTP server.
    #[arg(long, default_value = "0.0.0.0:8080")]
    bind: SocketAddr,

    /// SQLite database path.
    #[arg(long, default_value = "chat-store.db")]
    db: PathBuf,

    /// Maximum number of keypackage bundles retained per device_id.
    #[arg(long, default_value_t = 100)]
    max_per_identity: usize,

    /// Retention window in days; older bundles are pruned.
    #[arg(long, default_value_t = 30)]
    retention_days: u64,

    /// How often the prune task runs.
    #[arg(long, default_value_t = 3600)]
    prune_interval_secs: u64,

    /// Disable the logos-delivery subscriber; submissions then arrive over
    /// HTTP POST only.
    #[arg(long)]
    no_delivery: bool,

    /// logos-delivery network preset the subscriber joins.
    #[arg(long, default_value = "logos.dev")]
    preset: String,

    /// TCP + discv5 UDP port for the embedded logos-delivery node
    /// (0 = OS-assigned).
    #[arg(long, default_value_t = 0)]
    p2p_port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let store = Arc::new(
        Store::open(&cli.db)
            .await
            .context("failed to open store")?,
    );

    let prune_store = store.clone();
    let max_per_id = cli.max_per_identity;
    let retention = Duration::from_secs(cli.retention_days * 24 * 3600);
    let interval = Duration::from_secs(cli.prune_interval_secs);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            if let Err(e) = prune_store.prune_key_packages(max_per_id, retention).await {
                tracing::warn!("prune (keypackages) failed: {e}");
            }
            if let Err(e) = prune_store.prune_accounts(retention).await {
                tracing::warn!("prune (accounts) failed: {e}");
            }
        }
    });

    if !cli.no_delivery {
        // Blocks for a few seconds while the node starts and finds peers;
        // deliberately before serving HTTP so a subscriber failure is a
        // startup error, not a silent half-running store.
        ingest::start(
            store.clone(),
            ingest::P2pConfig {
                preset: cli.preset.clone(),
                port: cli.p2p_port,
                log_level: "ERROR".into(),
            },
            tokio::runtime::Handle::current(),
        )
        .context("failed to start logos-delivery ingestion")?;
        tracing::info!("logos-delivery ingestion running (preset={})", cli.preset);
    }

    let app = handlers::router(store);
    let listener = tokio::net::TcpListener::bind(cli.bind)
        .await
        .with_context(|| format!("failed to bind {}", cli.bind))?;
    tracing::info!("chat-store listening on {}", cli.bind);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
}
