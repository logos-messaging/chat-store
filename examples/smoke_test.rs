//! End-to-end smoke test for the chat-store HTTP API.
//!
//! Generates throwaway Ed25519 keys, signs a keypackage bundle and an account
//! device-list bundle, POSTs both, then GETs them back. The server verifies the
//! signature over the exact payload bytes, so the bundles must be properly
//! signed — this example does that for you.
//!
//! Run it against a live server:
//!
//! ```text
//! cargo run -- --bind 127.0.0.1:8080 --db tmp/chat-store.db   # terminal 1
//! cargo run --example smoke_test                              # terminal 2
//! cargo run --example smoke_test -- http://host:port          # custom target
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signer, SigningKey};
use reqwest::blocking::Client;
use serde_json::json;

/// Domain-separation prefix the server expects on every account bundle payload.
/// Must match `BUNDLE_DOMAIN` in `src/store.rs` (and libchat's account_directory).
const ACCOUNT_BUNDLE_DOMAIN: &[u8] = b"libchat:account-device-bundle\0";

fn main() -> Result<()> {
    let base = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://127.0.0.1:8080".to_string());
    let base = base.trim_end_matches('/');
    let client = Client::new();

    println!("Testing chat-store at {base}");
    test_keypackage(&client, base)?;
    test_account(&client, base)?;
    Ok(())
}

fn test_keypackage(client: &Client, base: &str) -> Result<()> {
    let key = signing_key(1);
    let device_id = pub_hex(&key);

    // The keypackage payload is opaque to the server: any bytes work as long as
    // the signature matches. Real clients put `timestamp_ms_le[8] || key_package`.
    let mut payload = 0u64.to_le_bytes().to_vec();
    payload.extend_from_slice(b"hello-keypackage");

    let resp = client
        .post(format!("{base}/v0/keypackage"))
        .json(&json!({
            "device_id": device_id,
            "payload": BASE64.encode(&payload),
            "signature": BASE64.encode(key.sign(&payload).to_bytes()),
        }))
        .send()?;
    println!("POST /v0/keypackage        -> {} (expect 204)", resp.status());

    let resp = client
        .get(format!("{base}/v0/keypackage/{device_id}"))
        .send()?;
    println!(
        "GET  /v0/keypackage/<id>   -> {} (expect 200) {}",
        resp.status(),
        resp.text()?
    );
    Ok(())
}

fn test_account(client: &Client, base: &str) -> Result<()> {
    let key = signing_key(2);
    let account_pub = pub_hex(&key);

    // The account payload is NOT arbitrary: it must start with the domain prefix,
    // a version byte, and an 8-byte little-endian lamport so the server can run
    // its replay check. Device pubkeys would follow, but stay opaque to the server.
    let lamport: u64 = 1;
    let mut payload = ACCOUNT_BUNDLE_DOMAIN.to_vec();
    payload.push(1); // version
    payload.extend_from_slice(&lamport.to_le_bytes());

    let body = json!({
        "account_pub": account_pub,
        "payload": BASE64.encode(&payload),
        "signature": BASE64.encode(key.sign(&payload).to_bytes()),
    });

    let resp = client
        .post(format!("{base}/v0/account"))
        .json(&body)
        .send()?;
    println!("POST /v0/account           -> {} (expect 204)", resp.status());

    let resp = client.get(format!("{base}/v0/account/{account_pub}")).send()?;
    println!(
        "GET  /v0/account/<id>      -> {} (expect 200) {}",
        resp.status(),
        resp.text()?
    );

    // Re-posting the same lamport must be rejected as a stale replay.
    let resp = client
        .post(format!("{base}/v0/account"))
        .json(&body)
        .send()?;
    println!("POST /v0/account (replay)  -> {} (expect 409)", resp.status());
    Ok(())
}

/// A throwaway Ed25519 signing key seeded from the current time (plus a salt so
/// the keypackage and account keys differ), so repeated runs use fresh ids.
fn signing_key(salt: u8) -> SigningKey {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .to_le_bytes();
    let mut seed = [0u8; 32];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = nanos[i % nanos.len()] ^ salt ^ (i as u8);
    }
    SigningKey::from_bytes(&seed)
}

fn pub_hex(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_bytes())
}
