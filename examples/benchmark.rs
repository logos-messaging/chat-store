//! Isolated end-to-end benchmark for chat-store.
//!
//! This example deliberately has no URL argument. It starts a local server on
//! loopback with a unique temporary SQLite database, then removes that database
//! when it exits. It therefore cannot write benchmark data to a deployed server.
//!
//! Build the release server first, then run:
//!
//! ```text
//! cargo build --release
//! cargo run --release --example benchmark -- --operations 1000 --concurrency 16
//! ```

use std::env;
use std::fs;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signer, SigningKey};
use reqwest::StatusCode;
use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json::json;

const ACCOUNT_BUNDLE_DOMAIN: &[u8] = b"libchat:account-device-bundle\0";

#[derive(Debug)]
struct Config {
    operations: usize,
    concurrency: usize,
    payload_bytes: usize,
    server_bin: PathBuf,
    keep_db: bool,
}

#[derive(Debug, Deserialize)]
struct BundleResponse {
    payload: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
struct AccountResponse {
    payload: String,
    signature: String,
    updated_at: i64,
}

struct LocalServer {
    child: Child,
    db_path: PathBuf,
    base_url: String,
    keep_db: bool,
}

impl Drop for LocalServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if !self.keep_db {
            let _ = fs::remove_file(&self.db_path);
            let _ = fs::remove_file(self.db_path.with_extension("db-shm"));
            let _ = fs::remove_file(self.db_path.with_extension("db-wal"));
        }
    }
}

fn main() -> Result<()> {
    let config = parse_args()?;
    let server = start_local_server(&config)?;
    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .context("build HTTP client")?;

    wait_until_ready(&client, &server.base_url)?;
    check_error_paths(&client, &server.base_url)?;

    let started = Instant::now();
    let workers = config.concurrency.min(config.operations);
    let operations_per_worker = split_work(config.operations, workers);
    let base_url = Arc::new(server.base_url.clone());
    let client = Arc::new(client);
    let payload_bytes = config.payload_bytes;
    let mut threads = Vec::with_capacity(workers);

    for (worker, operations) in operations_per_worker.into_iter().enumerate() {
        let base_url = base_url.clone();
        let client = client.clone();
        threads.push(thread::spawn(move || -> Result<usize> {
            for operation in 0..operations {
                let sequence = (worker as u64) << 32 | operation as u64;
                exercise_business_flow(&client, &base_url, sequence, payload_bytes)?;
            }
            Ok(operations)
        }));
    }

    let completed = threads
        .into_iter()
        .map(|thread| {
            thread
                .join()
                .map_err(|_| anyhow!("benchmark worker panicked"))?
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .sum::<usize>();
    let elapsed = started.elapsed();
    let requests = completed * 7;

    println!("Local benchmark completed without contacting an external server.");
    println!("operations: {completed}");
    println!("HTTP requests: {requests}");
    println!("concurrency: {workers}");
    println!("elapsed: {:.3}s", elapsed.as_secs_f64());
    println!(
        "business flows/s: {:.1}",
        completed as f64 / elapsed.as_secs_f64()
    );
    println!(
        "HTTP requests/s: {:.1}",
        requests as f64 / elapsed.as_secs_f64()
    );
    if config.keep_db {
        println!("database retained at {}", server.db_path.display());
    }
    Ok(())
}

fn exercise_business_flow(
    client: &Client,
    base_url: &str,
    sequence: u64,
    payload_bytes: usize,
) -> Result<()> {
    let device_key = signing_key(sequence * 2);
    let device_id = pub_hex(&device_key);
    let mut keypackage_payload = sequence.to_le_bytes().to_vec();
    keypackage_payload.resize(8 + payload_bytes, b'k');
    let keypackage_signature = device_key.sign(&keypackage_payload);

    expect_status(
        client
            .post(format!("{base_url}/v0/keypackage"))
            .json(&json!({
                "device_id": device_id,
                "payload": BASE64.encode(&keypackage_payload),
                "signature": BASE64.encode(keypackage_signature.to_bytes()),
            }))
            .send()?,
        StatusCode::NO_CONTENT,
        "publish keypackage",
    )?;
    let keypackage: BundleResponse = expect_status(
        client
            .get(format!("{base_url}/v0/keypackage/{device_id}"))
            .send()?,
        StatusCode::OK,
        "fetch keypackage",
    )?
    .json()?;
    verify_response(&device_key, &keypackage, &keypackage_payload)?;

    let account_key = signing_key(sequence * 2 + 1);
    let account_pub = pub_hex(&account_key);
    let first_payload = account_payload(1, payload_bytes);
    publish_account(
        client,
        base_url,
        &account_key,
        &account_pub,
        &first_payload,
        StatusCode::NO_CONTENT,
    )?;
    let account: AccountResponse = expect_status(
        client
            .get(format!("{base_url}/v0/account/{account_pub}"))
            .send()?,
        StatusCode::OK,
        "fetch account",
    )?
    .json()?;
    if account.updated_at <= 0 {
        bail!("fetch account: server returned a non-positive updated_at");
    }
    verify_response(
        &account_key,
        &BundleResponse {
            payload: account.payload,
            signature: account.signature,
        },
        &first_payload,
    )?;

    publish_account(
        client,
        base_url,
        &account_key,
        &account_pub,
        &first_payload,
        StatusCode::CONFLICT,
    )?;
    let second_payload = account_payload(2, payload_bytes);
    publish_account(
        client,
        base_url,
        &account_key,
        &account_pub,
        &second_payload,
        StatusCode::NO_CONTENT,
    )?;
    let updated_account: AccountResponse = expect_status(
        client
            .get(format!("{base_url}/v0/account/{account_pub}"))
            .send()?,
        StatusCode::OK,
        "fetch updated account",
    )?
    .json()?;
    verify_response(
        &account_key,
        &BundleResponse {
            payload: updated_account.payload,
            signature: updated_account.signature,
        },
        &second_payload,
    )?;
    Ok(())
}

fn publish_account(
    client: &Client,
    base_url: &str,
    account_key: &SigningKey,
    account_pub: &str,
    payload: &[u8],
    expected: StatusCode,
) -> Result<()> {
    expect_status(
        client
            .post(format!("{base_url}/v0/account"))
            .json(&json!({
                "account_pub": account_pub,
                "payload": BASE64.encode(payload),
                "signature": BASE64.encode(account_key.sign(payload).to_bytes()),
            }))
            .send()?,
        expected,
        "publish account",
    )?;
    Ok(())
}

fn check_error_paths(client: &Client, base_url: &str) -> Result<()> {
    expect_status(
        client
            .get(format!("{base_url}/v0/keypackage/{}", "0".repeat(64)))
            .send()?,
        StatusCode::NOT_FOUND,
        "fetch unknown keypackage",
    )?;
    expect_status(
        client
            .get(format!("{base_url}/v0/account/{}", "0".repeat(64)))
            .send()?,
        StatusCode::NOT_FOUND,
        "fetch unknown account",
    )?;
    expect_status(
        client
            .post(format!("{base_url}/v0/keypackage"))
            .json(&json!({"device_id": "not-a-key", "payload": "bad", "signature": "bad"}))
            .send()?,
        StatusCode::BAD_REQUEST,
        "reject malformed keypackage",
    )?;
    Ok(())
}

fn verify_response(
    key: &SigningKey,
    response: &BundleResponse,
    expected_payload: &[u8],
) -> Result<()> {
    let payload = BASE64
        .decode(&response.payload)
        .context("response payload was not base64")?;
    let signature: [u8; 64] = BASE64
        .decode(&response.signature)
        .context("response signature was not base64")?
        .try_into()
        .map_err(|_| anyhow!("response signature did not contain 64 bytes"))?;
    if payload != expected_payload {
        bail!("response payload did not match the published payload");
    }
    key.verifying_key()
        .verify_strict(&payload, &ed25519_dalek::Signature::from_bytes(&signature))
        .context("response signature verification failed")?;
    Ok(())
}

fn account_payload(lamport: u64, payload_bytes: usize) -> Vec<u8> {
    let mut payload = ACCOUNT_BUNDLE_DOMAIN.to_vec();
    payload.push(1);
    payload.extend_from_slice(&lamport.to_le_bytes());
    payload.resize(payload.len() + payload_bytes, b'a');
    payload
}

fn expect_status(
    response: reqwest::blocking::Response,
    expected: StatusCode,
    operation: &str,
) -> Result<reqwest::blocking::Response> {
    let actual = response.status();
    if actual != expected {
        let body = response.text().unwrap_or_default();
        bail!("{operation}: expected {expected}, got {actual}: {body}");
    }
    Ok(response)
}

fn signing_key(sequence: u64) -> SigningKey {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&sequence.to_le_bytes());
    for (index, byte) in seed[8..].iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(37).wrapping_add(11);
    }
    SigningKey::from_bytes(&seed)
}

fn pub_hex(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_bytes())
}

fn start_local_server(config: &Config) -> Result<LocalServer> {
    if !config.server_bin.is_file() {
        bail!(
            "server binary not found at {}; run `cargo build --release` or pass --server-bin <path>",
            config.server_bin.display()
        );
    }
    let listener = TcpListener::bind("127.0.0.1:0").context("reserve loopback port")?;
    let address = listener
        .local_addr()
        .context("read reserved loopback port")?;
    drop(listener);

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let db_path = env::temp_dir().join(format!("chat-store-benchmark-{unique}.db"));
    let child = Command::new(&config.server_bin)
        .args(["--bind", &address.to_string(), "--db"])
        .arg(&db_path)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("start local server {}", config.server_bin.display()))?;

    Ok(LocalServer {
        child,
        db_path,
        base_url: format!("http://{address}"),
        keep_db: config.keep_db,
    })
}

fn wait_until_ready(client: &Client, base_url: &str) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(response) = client
            .get(format!("{base_url}/v0/keypackage/unknown"))
            .send()
            && response.status() == StatusCode::NOT_FOUND
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("local server did not become ready within 5 seconds");
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn split_work(operations: usize, workers: usize) -> Vec<usize> {
    (0..workers)
        .map(|worker| operations / workers + usize::from(worker < operations % workers))
        .collect()
}

fn parse_args() -> Result<Config> {
    let mut config = Config {
        operations: 1_000,
        concurrency: 16,
        payload_bytes: 512,
        server_bin: PathBuf::from("target/release/chat-store"),
        keep_db: false,
    };
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--operations" => config.operations = parse_value(&mut args, "--operations")?,
            "--concurrency" => config.concurrency = parse_value(&mut args, "--concurrency")?,
            "--payload-bytes" => config.payload_bytes = parse_value(&mut args, "--payload-bytes")?,
            "--server-bin" => {
                config.server_bin = PathBuf::from(next_value(&mut args, "--server-bin")?)
            }
            "--keep-db" => config.keep_db = true,
            "--help" | "-h" => {
                println!("Usage: cargo run --release --example benchmark -- [options]");
                println!(
                    "  --operations <n>     Complete business flows to execute (default: 1000)"
                );
                println!("  --concurrency <n>    Worker threads (default: 16)");
                println!(
                    "  --payload-bytes <n>  Opaque payload bytes after headers (default: 512)"
                );
                println!(
                    "  --server-bin <path>  Local chat-store binary (default: target/release/chat-store)"
                );
                println!("  --keep-db            Retain the temporary database for inspection");
                return Err(anyhow!("help requested"));
            }
            _ => bail!("unknown option: {arg}"),
        }
    }
    if config.operations == 0 || config.concurrency == 0 {
        bail!("--operations and --concurrency must both be greater than zero");
    }
    Ok(config)
}

fn parse_value<T: std::str::FromStr>(
    args: &mut impl Iterator<Item = String>,
    option: &str,
) -> Result<T>
where
    T::Err: std::fmt::Display,
{
    next_value(args, option)?
        .parse()
        .map_err(|error| anyhow!("invalid value for {option}: {error}"))
}

fn next_value(args: &mut impl Iterator<Item = String>, option: &str) -> Result<String> {
    args.next()
        .ok_or_else(|| anyhow!("{option} requires a value"))
}
