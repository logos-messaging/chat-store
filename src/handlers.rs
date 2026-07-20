use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::Serialize;

use crate::store::Store;
use crate::submit::{self, SubmitAccountRequest, SubmitError, SubmitRequest};

#[derive(Debug, Serialize)]
pub struct FetchResponse {
    /// base64 of the stored payload; consumers verify `signature` over it.
    pub payload: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

pub fn router(store: Arc<Store>) -> Router {
    Router::new()
        .route("/v0/keypackage", post(submit))
        .route("/v0/keypackage/:device_id", get(fetch))
        .route("/v0/account", post(submit_account))
        .route("/v0/account/:account_pub", get(fetch_account))
        .with_state(store)
}

/// `POST /v0/keypackage` — same submission the logos-delivery subscriber
/// accepts; verification and storage live in [`submit::apply_keypackage`].
async fn submit(
    State(store): State<Arc<Store>>,
    Json(req): Json<SubmitRequest>,
) -> Result<StatusCode, ApiError> {
    submit::apply_keypackage(&store, &req).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn fetch(
    State(store): State<Arc<Store>>,
    Path(device_id): Path<String>,
) -> Result<Json<FetchResponse>, ApiError> {
    let Some(bundle) = store
        .latest(&device_id)
        .await
        .map_err(ApiError::internal)?
    else {
        return Err(ApiError::not_found("no keypackage for device"));
    };
    Ok(Json(FetchResponse {
        payload: BASE64.encode(&bundle.payload),
        signature: BASE64.encode(&bundle.signature),
    }))
}

#[derive(Debug, Serialize)]
pub struct FetchAccountResponse {
    /// base64 of the stored payload.
    pub payload: String,
    /// base64 of the 64-byte Ed25519 signature.
    pub signature: String,
    /// Unix timestamp (ms) of the last successful upsert.
    pub updated_at: i64,
}

/// `POST /v0/account` — upsert a signed device-list bundle for an account.
///
/// The server verifies the Ed25519 signature and then stores exactly one blob
/// per `account_pub`, replacing any previous value. Clients should re-publish
/// whenever they add or rotate LocalIdentities. Same submission the
/// logos-delivery subscriber accepts; the shared rules live in
/// [`submit::apply_account`].
async fn submit_account(
    State(store): State<Arc<Store>>,
    Json(req): Json<SubmitAccountRequest>,
) -> Result<StatusCode, ApiError> {
    submit::apply_account(&store, &req).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v0/account/:account_pub` — fetch the device-list bundle for an account.
///
/// Returns the latest published bundle so consumers can verify the
/// account signature and decode the list of LocalIdentity keys themselves.
async fn fetch_account(
    State(store): State<Arc<Store>>,
    Path(account_pub): Path<String>,
) -> Result<Json<FetchAccountResponse>, ApiError> {
    let Some(bundle) = store
        .get_account(&account_pub)
        .await
        .map_err(ApiError::internal)?
    else {
        return Err(ApiError::not_found("no account bundle for account_pub"));
    };
    Ok(Json(FetchAccountResponse {
        payload: BASE64.encode(&bundle.payload),
        signature: BASE64.encode(&bundle.signature),
        updated_at: bundle.updated_at,
    }))
}

struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn not_found(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: msg.into(),
        }
    }
    fn internal<E: std::fmt::Display>(err: E) -> Self {
        tracing::error!("internal: {err}");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "internal error".into(),
        }
    }
}

impl From<SubmitError> for ApiError {
    fn from(err: SubmitError) -> Self {
        match err {
            SubmitError::Invalid(msg) => Self {
                status: StatusCode::BAD_REQUEST,
                message: msg.into(),
            },
            SubmitError::Stale => Self {
                status: StatusCode::CONFLICT,
                message: err.to_string(),
            },
            SubmitError::Internal(inner) => Self::internal(inner),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}
