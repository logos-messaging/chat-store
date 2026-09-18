//! `/v1/account` — an account's append-only log, as defined by the account-log
//! crate. Replaces [`super::v0`].

use std::sync::Arc;

use account_log::{AccountAddr, SignedAccountLog};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::post;

use crate::bundle::{self, BundleError};
use crate::handlers::ApiError;
use crate::store::Store;

pub(super) fn routes() -> Router<Arc<Store>> {
    Router::new().route("/v1/account/:account_addr", post(submit_account))
}

/// `POST /v1/account/:account_addr` — publish an account's log. The body is the
/// signed log exactly as the account-log crate transmits it
/// ([`SignedAccountLog::to_bytes`]: `signature || payload`), as raw bytes. The
/// log does not name its account, so the path does: `account_addr` is the
/// account's [`AccountAddr`] (64 lowercase hex characters), the key the log
/// must be signed by.
///
/// Stored only when it strictly extends the log on file; resubmitting that log
/// is a no-op. The rules live in [`bundle::apply_account_log`].
async fn submit_account(
    State(store): State<Arc<Store>>,
    Path(account_addr): Path<String>,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let addr = account_addr
        .parse::<AccountAddr>()
        .map_err(|_| BundleError::Invalid("account_addr: not a valid account address"))?;
    let signed = SignedAccountLog::from_bytes(&body).map_err(BundleError::MalformedLog)?;
    bundle::apply_account_log(&store, addr, signed).await?;
    Ok(StatusCode::NO_CONTENT)
}
