//! `/v1/account` — an account's append-only log, as defined by the account-log
//! crate. Replaces [`super::v0`].
//!
//! A log travels as raw bytes, exactly as the crate transmits it
//! ([`SignedAccountLog::to_bytes`]: `signature || payload`), in both
//! directions. The log does not name its account, so the path does:
//! `account_addr` is the account's [`AccountAddr`] (64 lowercase hex
//! characters), the key the log is signed by.

use std::sync::Arc;

use account_log::{AccountAddr, SignedAccountLog};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::post;

use crate::bundle::{self, BundleError};
use crate::handlers::ApiError;
use crate::store::Store;

pub(super) fn routes() -> Router<Arc<Store>> {
    Router::new().route(
        "/v1/account/:account_addr",
        post(submit_account).get(fetch_account),
    )
}

/// `POST /v1/account/:account_addr` — publish an account's log. Stored only
/// when it strictly extends the log on file; resubmitting that log is a no-op.
/// The rules live in [`bundle::apply_account_log`].
async fn submit_account(
    State(store): State<Arc<Store>>,
    Path(account_addr): Path<String>,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let addr = parse_addr(&account_addr)?;
    let signed = SignedAccountLog::from_bytes(&body).map_err(BundleError::MalformedLog)?;
    bundle::apply_account_log(&store, addr, signed).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/account/:account_addr` — the stored log, or `404` if the account
/// has not published one. The server is not trusted: consumers verify the log
/// under `account_addr`, and that it extends any log they already hold, before
/// using it — `AccountRecord` does both.
async fn fetch_account(
    State(store): State<Arc<Store>>,
    Path(account_addr): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let addr = parse_addr(&account_addr)?;
    let Some(signed_log) = store
        .get_account_log(&addr)
        .await
        .map_err(ApiError::internal)?
    else {
        return Err(ApiError::not_found("no account log for account_addr"));
    };
    Ok((
        [(header::CONTENT_TYPE, "application/octet-stream")],
        signed_log,
    ))
}

fn parse_addr(account_addr: &str) -> Result<AccountAddr, BundleError> {
    account_addr
        .parse()
        .map_err(|_| BundleError::Invalid("account_addr: not a valid account address"))
}
