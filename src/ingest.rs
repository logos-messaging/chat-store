//! logos-delivery ingestion.
//!
//! Runs an embedded logos-delivery node, subscribes to the store submission
//! content topics, and feeds every received submission through the same
//! verification + storage pipeline as the HTTP POST endpoints (`submit`).
//! Submissions arrive as protobuf on this wire — matching the `/proto` content
//! topics they are published on — and carry the same fields the JSON POST
//! bodies do. Publishing is fire-and-forget on the client side, so rejected
//! submissions are only logged here; consumers verify every bundle on
//! retrieval anyway.

use std::sync::Arc;

use anyhow::{Context, Result};
use chat_proto::logoschat::store::{AccountSubmissionV1, KeyPackageSubmissionV1};
pub use logos_delivery::P2pConfig;
use logos_delivery::ThreadedDeliveryWrapper;
use prost::Message;
use tracing::{debug, warn};

use crate::store::Store;
use crate::submit::{self, Submission};

/// Content topic carrying keypackage submissions. Must match what libchat's
/// `DeliveryRegistry` publishes: delivery address `store-keypackage-v0` mapped
/// through the `/logos-chat/1/{address}/proto` content-topic scheme.
pub const KEYPACKAGE_SUBMIT_TOPIC: &str = "/logos-chat/1/store-keypackage-v0/proto";

/// Content topic carrying account device-list bundle submissions.
pub const ACCOUNT_SUBMIT_TOPIC: &str = "/logos-chat/1/store-account-v0/proto";

/// A raw submission taken off the wire; the protobuf body is decoded (and its
/// signature verified) on the ingest thread, not the node callback.
#[derive(Clone)]
enum Received {
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
            KEYPACKAGE_SUBMIT_TOPIC => Received::KeyPackage as fn(Vec<u8>) -> Received,
            ACCOUNT_SUBMIT_TOPIC => Received::Account,
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
            while let Ok(received) = inbound.recv() {
                match received {
                    Received::KeyPackage(bytes) => ingest_keypackage(&store, &runtime, &bytes),
                    Received::Account(bytes) => ingest_account(&store, &runtime, &bytes),
                }
            }
        })
        .context("spawn delivery-ingest thread")?;
    Ok(())
}

fn ingest_keypackage(store: &Store, runtime: &tokio::runtime::Handle, bytes: &[u8]) {
    let wire = match KeyPackageSubmissionV1::decode(bytes) {
        Ok(wire) => wire,
        Err(e) => {
            warn!("keypackage submission: invalid protobuf: {e}");
            return;
        }
    };
    let submission = match Submission::keypackage(&wire.device_id, &wire.payload, &wire.signature) {
        Ok(submission) => submission,
        Err(e) => {
            warn!("keypackage submission rejected: {e}");
            return;
        }
    };
    let device_id = submission.key_hex();
    match runtime.block_on(submit::apply_keypackage(store, &submission)) {
        Ok(()) => debug!(%device_id, "stored keypackage from delivery"),
        Err(e) => warn!(%device_id, "keypackage submission rejected: {e}"),
    }
}

fn ingest_account(store: &Store, runtime: &tokio::runtime::Handle, bytes: &[u8]) {
    let wire = match AccountSubmissionV1::decode(bytes) {
        Ok(wire) => wire,
        Err(e) => {
            warn!("account submission: invalid protobuf: {e}");
            return;
        }
    };
    let submission = match Submission::account(&wire.account_pub, &wire.payload, &wire.signature) {
        Ok(submission) => submission,
        Err(e) => {
            warn!("account submission rejected: {e}");
            return;
        }
    };
    let account_pub = submission.key_hex();
    match runtime.block_on(submit::apply_account(store, &submission)) {
        Ok(()) => debug!(%account_pub, "stored account bundle from delivery"),
        Err(e) => warn!(%account_pub, "account submission rejected: {e}"),
    }
}
