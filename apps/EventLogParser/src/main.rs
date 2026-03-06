mod api;
mod db;
mod error;
mod ingest;
mod parser;
mod models;
mod state;
mod utils;
mod stats_query;

use crate::state::AppState;
use crate::utils::{load_config, sqlite_busy_timeout};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;
use tower_http::cors::{Any, CorsLayer};

#[tokio::main]
async fn main() -> Result<(), error::AppError> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let cfg = load_config();

    let pool = db::init_pool(&cfg.db_path, sqlite_busy_timeout(&cfg))?;
    db::init_schema(&pool)?;

    let state = AppState::new(pool, cfg.clone());
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = api::router(state).layer(cors);

    let addr: SocketAddr = cfg
        .bind_addr
        .parse()
        .map_err(|e| error::AppError::BadRequest(format!("invalid bind address: {e}")))?;

    let listener = TcpListener::bind(addr)
        .await
        .map_err(error::AppError::Io)?;

    tracing::info!("listening on {}", addr);
    axum::serve(listener, app)
        .await
        .map_err(error::AppError::Io)?;

    Ok(())
}
