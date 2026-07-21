//! SSH sync server binary.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use base64::Engine;
use clap::Parser;
use server::{auth::JwtConfig, build_app, db::Db, AppState};
use tokio::net::TcpListener;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "ssh-sync-server", about = "SSH config + vault sync server")]
struct Args {
    /// Bind address.
    #[arg(long, default_value = "127.0.0.1:8787")]
    addr: SocketAddr,
    /// Path to the SQLite database file.
    #[arg(long, default_value = "sync.db")]
    db: PathBuf,
    /// JWT signing secret. If omitted a random one is generated per start
    /// (existing tokens become invalid on restart).
    #[arg(long, env = "SSH_SYNC_SECRET")]
    secret: Option<String>,
    /// Token lifetime in seconds.
    #[arg(long, default_value_t = 7 * 24 * 3600)]
    token_ttl: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "server=info,tower_http=info".into()),
        )
        .init();

    let args = Args::parse();
    let db = Db::open(&args.db)?;
    db.init_schema()?;
    let secret = args.secret.unwrap_or_else(|| {
        use rand::RngCore;
        let mut b = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut b);
        base64::engine::general_purpose::STANDARD.encode(b)
    });
    let jwt = JwtConfig::new(secret, args.token_ttl);
    let state = AppState {
        db: Arc::new(tokio::sync::Mutex::new(db)),
        jwt,
    };

    let app = build_app(state);
    info!("ssh-sync-server listening on http://{}", args.addr);
    let listener = TcpListener::bind(args.addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
