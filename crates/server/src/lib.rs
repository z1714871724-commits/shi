//! SSH sync server library.
//!
//! The binary (`src/main.rs`) is a thin wrapper around [`build_app`] so that
//! tests (and other embedders) can spin the server up in-process.

use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

pub mod auth;
pub mod db;
pub mod error;
pub mod routes;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<tokio::sync::Mutex<db::Db>>,
    pub jwt: auth::JwtConfig,
}

/// Build the configured axum `Router` ready to be served.
pub fn build_app(state: AppState) -> Router {
    let api = Router::new()
        .route("/health", get(routes::health))
        .route("/register", post(routes::register))
        .route("/login", post(routes::login))
        .route(
            "/vault/salt",
            get(routes::get_vault_salt).post(routes::set_vault_salt),
        )
        .route("/hosts", get(routes::list_hosts).put(routes::upsert_host))
        .route("/hosts/:id", axum::routing::delete(routes::delete_host))
        .route(
            "/vault",
            get(routes::list_vault).put(routes::upsert_vault_entry),
        )
        .route(
            "/vault/:id",
            axum::routing::delete(routes::delete_vault_entry),
        );

    Router::new()
        .nest("/api/v1", api)
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state)
}
