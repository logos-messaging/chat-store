//! Account device-list endpoints, every version.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

use super::{ApiError, decode_bundle};
use crate::bundle::{self, Bundle, BundleError};
use crate::store::Store;

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

#[derive(Debug, Serialize)]
pub struct FetchAccountResponse {
    /// base64 of the stored payload.
    pub payload: String,
    /// base64 of the 64-byte Ed25519 signature.
    pub signature: String,
    /// Unix timestamp (ms) of the last successful upsert.
    pub updated_at: i64,
}

pub(super) fn routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v0/account", post(submit_account))
        .route("/v0/account/:account_pub", get(fetch_account))
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
