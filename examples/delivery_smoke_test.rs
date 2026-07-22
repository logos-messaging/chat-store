//! End-to-end smoke test for the logos-delivery write path.
//!
//! Publishes a signed keypackage bundle and an account device-list bundle over
//! the delivery network — the protobuf submissions the store subscribes for,
//! carrying the same fields the HTTP POST endpoints take as JSON — then polls
//! the HTTP query API until both appear. Requires a chat-store running with
//! delivery ingestion enabled (the default) on the same network preset.
//!
//! ```text
//! cargo run -- --bind 127.0.0.1:8080 --db tmp/chat-store.db   # terminal 1
//! cargo run --example delivery_smoke_test                     # terminal 2
//! cargo run --example delivery_smoke_test -- http://host:port # custom target
//! ```

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use chat_proto::logoschat::store::{AccountSubmissionV1, KeyPackageSubmissionV1};
use ed25519_dalek::{Signer, SigningKey};
use logos_delivery::{P2pConfig, ThreadedDeliveryWrapper};
use prost::Message;
use prost::bytes::Bytes;
use reqwest::blocking::Client;

/// Must match `ingest::KEYPACKAGE_SUBMIT_TOPIC` / `ingest::ACCOUNT_SUBMIT_TOPIC`
/// (examples cannot import from the binary crate).
const KEYPACKAGE_SUBMIT_TOPIC: &str = "/logos-chat/1/store-keypackage-v0/proto";
const ACCOUNT_SUBMIT_TOPIC: &str = "/logos-chat/1/store-account-v0/proto";

/// Domain-separation prefix the server expects on every account bundle payload.
const ACCOUNT_BUNDLE_DOMAIN: &[u8] = b"libchat:account-device-bundle\0";

/// How long to keep polling the query API for the published bundles. Covers
/// node startup, peer discovery, and gossip propagation.
const POLL_BUDGET: Duration = Duration::from_secs(90);

fn main() -> Result<()> {
    let base = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://127.0.0.1:8080".to_string());
    let base = base.trim_end_matches('/').to_string();
    let client = Client::new();

    println!("Starting logos-delivery publisher node (this takes a few seconds)...");
    let node = ThreadedDeliveryWrapper::<Vec<u8>>::start(P2pConfig::default(), |_| None)
        .map_err(|e| anyhow::anyhow!("start logos-delivery node: {e}"))?;

    // Unique keys per run so re-runs don't hit the account lamport replay guard.
    let seed_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let device_key = derived_key(seed_ms, 1);
    let account_key = derived_key(seed_ms, 2);
    let device_id = hex::encode(device_key.verifying_key().as_bytes());
    let account_pub = hex::encode(account_key.verifying_key().as_bytes());

    // Keypackage payload: opaque to the server; real clients use
    // `timestamp_ms_le[8] || key_package`.
    let mut kp_payload = seed_ms.to_le_bytes().to_vec();
    kp_payload.extend_from_slice(b"delivery-smoke-keypackage");
    publish(
        &node,
        KEYPACKAGE_SUBMIT_TOPIC,
        &KeyPackageSubmissionV1 {
            device_id: Bytes::copy_from_slice(device_key.verifying_key().as_bytes()),
            payload: Bytes::copy_from_slice(&kp_payload),
            signature: Bytes::copy_from_slice(&device_key.sign(&kp_payload).to_bytes()),
        },
    )?;
    println!("published keypackage submission on {KEYPACKAGE_SUBMIT_TOPIC}");

    // Account bundle payload: domain || version || lamport || opaque rest.
    let mut acct_payload = ACCOUNT_BUNDLE_DOMAIN.to_vec();
    acct_payload.push(1u8);
    acct_payload.extend_from_slice(&1u64.to_le_bytes());
    acct_payload.extend_from_slice(b"delivery-smoke-devices");
    publish(
        &node,
        ACCOUNT_SUBMIT_TOPIC,
        &AccountSubmissionV1 {
            account_pub: Bytes::copy_from_slice(account_key.verifying_key().as_bytes()),
            payload: Bytes::copy_from_slice(&acct_payload),
            signature: Bytes::copy_from_slice(&account_key.sign(&acct_payload).to_bytes()),
        },
    )?;
    println!("published account submission on {ACCOUNT_SUBMIT_TOPIC}");

    poll_until_stored(
        &client,
        &format!("{base}/v0/keypackage/{device_id}"),
        "keypackage",
    )?;
    poll_until_stored(&client, &format!("{base}/v0/account/{account_pub}"), "account")?;

    println!("delivery smoke test passed");
    Ok(())
}

fn derived_key(seed_ms: u64, salt: u8) -> SigningKey {
    let mut bytes = [salt; 32];
    bytes[..8].copy_from_slice(&seed_ms.to_le_bytes());
    SigningKey::from_bytes(&bytes)
}

fn publish<M: Message>(
    node: &ThreadedDeliveryWrapper<Vec<u8>>,
    topic: &str,
    submission: &M,
) -> Result<()> {
    node.publish(topic, &submission.encode_to_vec())
        .map_err(|e| anyhow::anyhow!("publish on {topic}: {e}"))
}

/// Poll `url` until it returns 200 (the subscriber stored the bundle) or the
/// budget runs out.
fn poll_until_stored(client: &Client, url: &str, what: &str) -> Result<()> {
    let started = Instant::now();
    loop {
        let status = client
            .get(url)
            .send()
            .with_context(|| format!("GET {url}"))?
            .status();
        if status.is_success() {
            println!("GET {url} -> {status} ({what} stored, {:?})", started.elapsed());
            return Ok(());
        }
        if started.elapsed() > POLL_BUDGET {
            bail!("{what} did not appear within {POLL_BUDGET:?} (last status {status})");
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}
