//! logos-delivery ingestion.
//!
//! Runs an embedded logos-delivery node, subscribes to the store submission
//! content topics, and feeds every received submission through the same
//! verification + storage pipeline as the HTTP POST endpoints (`submit`).
//! Publishing is fire-and-forget on the client side, so rejected submissions
//! are only logged here — consumers verify every bundle on retrieval anyway.

use std::sync::Arc;

use anyhow::{Context, Result};
use logos_delivery::ThreadedDeliveryWrapper;
pub use logos_delivery::P2pConfig;
use tracing::{debug, warn};

use crate::store::Store;
use crate::submit::{self, SubmitAccountRequest, SubmitRequest};

/// Content topic carrying keypackage submissions. Must match what libchat's
/// `DeliveryRegistry` publishes: delivery address `store-keypackage-v0` mapped
/// through the `/logos-chat/1/{address}/proto` content-topic scheme.
pub const KEYPACKAGE_SUBMIT_TOPIC: &str = "/logos-chat/1/store-keypackage-v0/proto";

/// Content topic carrying account device-list bundle submissions.
pub const ACCOUNT_SUBMIT_TOPIC: &str = "/logos-chat/1/store-account-v0/proto";

/// A raw submission taken off the wire; the JSON body is parsed (and its
/// signature verified) on the ingest thread, not the node callback.
#[derive(Clone)]
enum Submission {
    KeyPackage(Vec<u8>),
    Account(Vec<u8>),
}

/// Start the embedded node, subscribe to the submission topics, and spawn the
/// ingest thread. The node lives as long as the returned thread does — i.e.
/// the whole process; there is no shutdown handshake for this testnet service.
///
/// `runtime` is the server's tokio handle: the store is async, but the
/// delivery wrapper hands messages to a plain thread, so each submission is
/// bridged back with `block_on`.
pub fn start(store: Arc<Store>, cfg: P2pConfig, runtime: tokio::runtime::Handle) -> Result<()> {
    let mut node = ThreadedDeliveryWrapper::start(cfg, |event| {
        let msg = event.into_received()?;
        let wrap = match msg.content_topic() {
            KEYPACKAGE_SUBMIT_TOPIC => Submission::KeyPackage as fn(Vec<u8>) -> Submission,
            ACCOUNT_SUBMIT_TOPIC => Submission::Account,
            _ => return None,
        };
        msg.into_payload().map(wrap)
    })
    .context("start embedded logos-delivery node")?;

    node.subscribe(KEYPACKAGE_SUBMIT_TOPIC)
        .context("subscribe keypackage submissions")?;
    node.subscribe(ACCOUNT_SUBMIT_TOPIC)
        .context("subscribe account submissions")?;

    let inbound = node.inbound_queue();
    std::thread::Builder::new()
        .name("delivery-ingest".into())
        .spawn(move || {
            // Keep the node alive: dropping the last wrapper clone stops it.
            let _node = node;
            while let Ok(submission) = inbound.recv() {
                match submission {
                    Submission::KeyPackage(bytes) => ingest_keypackage(&store, &runtime, &bytes),
                    Submission::Account(bytes) => ingest_account(&store, &runtime, &bytes),
                }
            }
        })
        .context("spawn delivery-ingest thread")?;
    Ok(())
}

fn ingest_keypackage(store: &Store, runtime: &tokio::runtime::Handle, bytes: &[u8]) {
    let req: SubmitRequest = match serde_json::from_slice(bytes) {
        Ok(req) => req,
        Err(e) => {
            warn!("keypackage submission: invalid JSON: {e}");
            return;
        }
    };
    match runtime.block_on(submit::apply_keypackage(store, &req)) {
        Ok(()) => debug!(device_id = %req.device_id, "stored keypackage from delivery"),
        Err(e) => warn!(device_id = %req.device_id, "keypackage submission rejected: {e}"),
    }
}

fn ingest_account(store: &Store, runtime: &tokio::runtime::Handle, bytes: &[u8]) {
    let req: SubmitAccountRequest = match serde_json::from_slice(bytes) {
        Ok(req) => req,
        Err(e) => {
            warn!("account submission: invalid JSON: {e}");
            return;
        }
    };
    match runtime.block_on(submit::apply_account(store, &req)) {
        Ok(()) => debug!(account_pub = %req.account_pub, "stored account bundle from delivery"),
        Err(e) => warn!(account_pub = %req.account_pub, "account submission rejected: {e}"),
    }
}
