//! JWT issuance + an axum extractor that authenticates requests.

use std::sync::Arc;

use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::AppState;

#[derive(Clone)]
pub struct JwtConfig {
    encoding: Arc<EncodingKey>,
    decoding: Arc<DecodingKey>,
    pub ttl_seconds: i64,
}

impl JwtConfig {
    pub fn new(secret: String, ttl_seconds: u64) -> Self {
        Self {
            encoding: Arc::new(EncodingKey::from_secret(secret.as_bytes())),
            decoding: Arc::new(DecodingKey::from_secret(secret.as_bytes())),
            ttl_seconds: ttl_seconds as i64,
        }
    }

    pub fn issue(&self, user_id: i64, username: &str) -> anyhow::Result<String> {
        let now = Utc::now();
        let claims = Claims {
            sub: username.to_string(),
            uid: user_id,
            exp: (now + Duration::seconds(self.ttl_seconds)).timestamp(),
            iat: now.timestamp(),
        };
        Ok(encode(&Header::default(), &claims, &self.encoding)?)
    }

    pub fn verify(&self, token: &str) -> anyhow::Result<Claims> {
        let data = decode::<Claims>(token, &self.decoding, &Validation::default())?;
        Ok(data.claims)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub uid: i64,
    pub exp: i64,
    pub iat: i64,
}

/// Extractor that pulls the Bearer token from `Authorization` and resolves to
/// the authenticated user id. Returns 401 on any failure.
pub struct AuthUser {
    pub user_id: i64,
    pub username: String,
}

#[axum::async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app = AppState::from_ref(state);
        let header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AppError::unauthorized("missing authorization header"))?;
        let token = header
            .strip_prefix("Bearer ")
            .ok_or_else(|| AppError::unauthorized("expected bearer token"))?;
        let claims = app
            .jwt
            .verify(token)
            .map_err(|_| AppError::unauthorized("invalid token"))?;
        Ok(AuthUser {
            user_id: claims.uid,
            username: claims.sub,
        })
    }
}
