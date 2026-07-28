use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

use crate::bundle::{self, Bundle, BundleError};
use crate::store::Store;

/// A signed keypackage bundle.
#[derive(Debug, Deserialize)]
pub struct SubmitKeyPackageRequest {
    /// Hex of the 32-byte Ed25519 device verifying key. Used to verify the
    /// signature and as the storage/lookup key. `payload` stays opaque.
    pub device_id: String,
    /// base64 of the signed payload. Opaque to the server — it never decodes it.
    pub payload: String,
    /// base64 of the 64-byte Ed25519 signature over `payload`. Verifying it
    /// under `device_id`'s key is proof-of-possession: only the holder of that
    /// key can publish under this `device_id`.
    pub signature: String,
}

impl SubmitKeyPackageRequest {
    /// Decode the JSON body's hex + base64 fields into a [`Bundle`].
    pub fn decode(&self) -> Result<Bundle, BundleError> {
        decode_bundle(&self.device_id, &self.payload, &self.signature)
    }
}

/// A signed account device-list bundle.
///
/// The `payload` is intentionally opaque to the server. Clients are expected
/// to encode a lamport-timestamped list of device (LocalIdentity) Ed25519
/// public keys inside it so that consumers can detect stale bundles. The server
/// only verifies that `signature` is a valid Ed25519 signature over `payload`
/// made by the key identified by `account_pub`.
#[derive(Debug, Deserialize)]
pub struct SubmitAccountRequest {
    /// Hex of the 32-byte Ed25519 account (AccountAddress) verifying key.
    /// Acts as both the storage key and the verification key.
    pub account_pub: String,
    /// base64 of the opaque signed payload (lamport-ts + device pubkeys, etc.).
    pub payload: String,
    /// base64 of the 64-byte Ed25519 signature over `payload` made by the
    /// account key. Proof-of-possession: only the account holder can publish.
    pub signature: String,
}

impl SubmitAccountRequest {
    /// Decode the JSON body's hex + base64 fields into a [`Bundle`].
    pub fn decode(&self) -> Result<Bundle, BundleError> {
        decode_bundle(&self.account_pub, &self.payload, &self.signature)
    }
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
pub struct FetchKeyPackageResponse {
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
        .route("/v0/keypackage", post(submit_key_package))
        .route("/v0/keypackage/:device_id", get(fetch_key_package))
        .route("/v0/account", post(submit_account))
        .route("/v0/account/:account_pub", get(fetch_account))
        .with_state(store)
}

/// `POST /v0/keypackage` — the same bundle the logos-delivery subscriber
/// accepts, in JSON rather than protobuf; verification and storage live in
/// [`bundle::apply_keypackage`].
async fn submit_key_package(
    State(store): State<Arc<Store>>,
    Json(req): Json<SubmitKeyPackageRequest>,
) -> Result<StatusCode, ApiError> {
    bundle::apply_keypackage(&store, &req.decode()?).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn fetch_key_package(
    State(store): State<Arc<Store>>,
    Path(device_id): Path<String>,
) -> Result<Json<FetchKeyPackageResponse>, ApiError> {
    let Some(bundle) = store.latest(&device_id).await.map_err(ApiError::internal)? else {
        return Err(ApiError::not_found("no keypackage for device"));
    };
    Ok(Json(FetchKeyPackageResponse {
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
/// whenever they add or rotate LocalIdentities. The same submission the
/// logos-delivery subscriber accepts, in JSON rather than protobuf; the shared
/// rules live in [`bundle::apply_account`].
async fn submit_account(
    State(store): State<Arc<Store>>,
    Json(req): Json<SubmitAccountRequest>,
) -> Result<StatusCode, ApiError> {
    bundle::apply_account(&store, &req.decode()?).await?;
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

impl From<BundleError> for ApiError {
    fn from(err: BundleError) -> Self {
        match err {
            BundleError::Invalid(msg) => Self {
                status: StatusCode::BAD_REQUEST,
                message: msg.into(),
            },
            BundleError::Stale => Self {
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
