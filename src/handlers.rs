//! HTTP endpoints, one module per resource. Resources are versioned
//! independently — a client may use `/v1/account` alongside `/v0/keypackage` —
//! so each module owns every version of its own routes and [`router`] merges
//! them. What the resources share lives here: the JSON bundle encoding and
//! [`ApiError`].

pub mod account;
pub mod keypackage;

use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::Serialize;

use crate::bundle::{Bundle, BundleError};
use crate::store::Store;

pub fn router(store: Arc<Store>) -> Router {
    Router::new()
        .merge(keypackage::routes())
        .merge(account::routes())
        .with_state(store)
}

/// This wire spells a bundle out in text: the key as hex, payload and signature
/// as base64. Undo that here — the delivery wire hands over raw bytes already —
/// and let [`Bundle::from_bytes`] enforce the lengths.
fn decode_bundle(
    key_hex: &str,
    payload_b64: &str,
    signature_b64: &str,
) -> Result<Bundle, BundleError> {
    let key = hex::decode(key_hex).map_err(|_| BundleError::Invalid("key: must be hex"))?;
    let payload = BASE64
        .decode(payload_b64)
        .map_err(|_| BundleError::Invalid("payload: not valid base64"))?;
    let signature = BASE64
        .decode(signature_b64)
        .map_err(|_| BundleError::Invalid("signature: not valid base64"))?;
    Bundle::from_bytes(&key, &payload, &signature)
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
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

impl From<BundleError> for ApiError {
    fn from(err: BundleError) -> Self {
        match err {
            BundleError::Invalid(msg) => Self {
                status: StatusCode::BAD_REQUEST,
                message: msg.into(),
            },
            BundleError::MalformedLog(_) => Self {
                status: StatusCode::BAD_REQUEST,
                message: err.to_string(),
            },
            BundleError::Stale | BundleError::Forked => Self {
                status: StatusCode::CONFLICT,
                message: err.to_string(),
            },
            BundleError::Internal(inner) => Self::internal(inner),
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
