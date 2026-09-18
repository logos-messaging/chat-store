//! Keypackage endpoints, every version.

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

#[derive(Debug, Serialize)]
pub struct FetchKeyPackageResponse {
    /// base64 of the stored payload; consumers verify `signature` over it.
    pub payload: String,
    pub signature: String,
}

pub(super) fn routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v0/keypackage", post(submit_key_package))
        .route("/v0/keypackage/:device_id", get(fetch_key_package))
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
