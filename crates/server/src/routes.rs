//! HTTP handlers. All vault payloads are opaque ciphertext to the server.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use protocol::api::*;
use protocol::{hash_login_password, verify_login_password};
use tracing::warn;

use crate::auth::AuthUser;
use crate::error::AppError;
use crate::AppState;

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
    })
}

pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<AuthResponse>), AppError> {
    if req.username.trim().len() < 3 {
        return Err(AppError::bad_request("username must be >= 3 chars"));
    }
    if req.password.len() < 6 {
        return Err(AppError::bad_request("password must be >= 6 chars"));
    }
    if req.vault_salt.is_empty() {
        return Err(AppError::bad_request("vault_salt required"));
    }
    let hash = hash_login_password(&req.password)
        .map_err(|e| AppError::internal(format!("hash failed: {e}")))?;
    let now = Utc::now().timestamp();
    let db = state.db.lock().await;
    let user_id = match db.create_user(&req.username, &hash, &req.vault_salt, now) {
        Ok(id) => id,
        Err(e) => {
            // most likely a UNIQUE constraint violation -> username taken
            if e.to_string().contains("UNIQUE") {
                return Err(AppError::conflict("username already taken"));
            }
            return Err(AppError::from(e));
        }
    };
    drop(db);
    let token = state
        .jwt
        .issue(user_id, &req.username)
        .map_err(|e| AppError::internal(format!("jwt failed: {e}")))?;
    Ok((
        StatusCode::CREATED,
        Json(AuthResponse {
            token,
            username: req.username,
            vault_salt: req.vault_salt,
        }),
    ))
}

pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let db = state.db.lock().await;
    let user = db
        .find_user_by_name(&req.username)?
        .ok_or_else(|| AppError::unauthorized("invalid credentials"))?;
    drop(db);
    let ok = verify_login_password(&req.password, &user.password_hash)
        .map_err(|e| AppError::internal(format!("verify failed: {e}")))?;
    if !ok {
        warn!(username = %req.username, "failed login attempt");
        return Err(AppError::unauthorized("invalid credentials"));
    }
    let token = state
        .jwt
        .issue(user.id, &user.username)
        .map_err(|e| AppError::internal(format!("jwt failed: {e}")))?;
    Ok(Json(AuthResponse {
        token,
        username: user.username,
        vault_salt: user.vault_salt,
    }))
}

pub async fn get_vault_salt(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<SetVaultSaltRequest>, AppError> {
    let db = state.db.lock().await;
    let user_row = db
        .find_user_by_name(&user.username)?
        .ok_or_else(|| AppError::not_found("user"))?;
    Ok(Json(SetVaultSaltRequest {
        vault_salt: user_row.vault_salt,
    }))
}

pub async fn set_vault_salt(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<SetVaultSaltRequest>,
) -> Result<Json<OkResponse>, AppError> {
    if req.vault_salt.is_empty() {
        return Err(AppError::bad_request("vault_salt required"));
    }
    let db = state.db.lock().await;
    db.set_vault_salt(user.user_id, &req.vault_salt)?;
    Ok(Json(OkResponse { ok: true }))
}

pub async fn list_hosts(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<HostListResponse>, AppError> {
    let db = state.db.lock().await;
    let hosts = db.list_hosts(user.user_id)?;
    let latest = hosts.iter().map(|h| h.updated_at).max().unwrap_or(0);
    Ok(Json(HostListResponse {
        hosts,
        latest_updated_at: latest,
    }))
}

pub async fn upsert_host(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<UpsertHostRequest>,
) -> Result<Json<OkResponse>, AppError> {
    if req.host.id.is_empty() {
        return Err(AppError::bad_request("host.id required"));
    }
    let db = state.db.lock().await;
    let accepted = db.upsert_host(user.user_id, &req.host)?;
    Ok(Json(OkResponse { ok: accepted }))
}

pub async fn delete_host(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<OkResponse>, AppError> {
    let db = state.db.lock().await;
    let deleted = db.delete_host(user.user_id, &id)?;
    Ok(Json(OkResponse { ok: deleted }))
}

pub async fn list_vault(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<VaultListResponse>, AppError> {
    let db = state.db.lock().await;
    let entries = db.list_vault(user.user_id)?;
    Ok(Json(VaultListResponse { entries }))
}

pub async fn upsert_vault_entry(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<UpsertVaultEntryRequest>,
) -> Result<Json<OkResponse>, AppError> {
    if req.entry.id.is_empty() {
        return Err(AppError::bad_request("entry.id required"));
    }
    let db = state.db.lock().await;
    let accepted = db.upsert_vault_entry(user.user_id, &req.entry)?;
    Ok(Json(OkResponse { ok: accepted }))
}

pub async fn delete_vault_entry(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<OkResponse>, AppError> {
    let db = state.db.lock().await;
    let deleted = db.delete_vault_entry(user.user_id, &id)?;
    Ok(Json(OkResponse { ok: deleted }))
}
