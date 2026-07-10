use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use tokio::sync::Mutex;

pub struct Store {
    pool: SqlitePool,
    write_lock: Mutex<()>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct StoredKeyPackageBundle {
    /// The canonical signed payload, stored verbatim and returned as-is so
    /// consumers verify over the exact bytes that were signed.
    pub payload: Vec<u8>,
    /// 64-byte Ed25519 signature over `payload`. Opaque to the server.
    pub signature: Vec<u8>,
}

/// A signed bundle associating an account with its set of device (LocalIdentity)
/// public keys. The server stores exactly one blob per `account_pub`; a newer
/// bundle replaces the old one only when its lamport is strictly higher (see
/// [`Store::upsert_account`]). `payload` is otherwise opaque to the server: it
/// encodes a lamport-timestamped list of device pubkeys signed by the account
/// key so that consumers can verify the full device set.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct StoredAccountBundle {
    /// The canonical signed payload, returned verbatim so consumers can verify
    /// the account signature over the exact bytes.
    pub payload: Vec<u8>,
    /// 64-byte Ed25519 signature over `payload` made by the account key.
    pub signature: Vec<u8>,
    /// Unix timestamp (ms) of the last upsert, stored for pruning.
    pub updated_at: i64,
}

impl Store {
    pub async fn open(path: &Path) -> Result<Self> {
        let is_memory = path == Path::new(":memory:");

        let mut options = SqliteConnectOptions::new()
            .create_if_missing(true)
            .busy_timeout(Duration::from_secs(5));

        if is_memory {
            options = options.filename(":memory:");
        } else {
            // Create the db's parent directory if the caller pointed at a nested
            // path (e.g. `tmp/registry.db`); SQLite won't create it and errors
            // with "unable to open database file" otherwise.
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create db directory {}", parent.display()))?;
            }
            options = options.filename(path).journal_mode(SqliteJournalMode::Wal);
        }

        // A shared in-memory database only lives as long as a connection is open,
        // so pin the `:memory:` pool to a single reused connection; file-backed
        // pools can fan out across requests and the prune task.
        let pool = SqlitePoolOptions::new()
            .max_connections(if is_memory { 1 } else { 5 })
            .connect_with(options)
            .await
            .context("open sqlite")?;

        sqlx::migrate!()
            .run(&pool)
            .await
            .context("run migrations")?;

        Ok(Self {
            pool,
            write_lock: Mutex::new(()),
        })
    }

    pub async fn insert(&self, device_id: &str, bundle: &StoredKeyPackageBundle) -> Result<()> {
        let _write_guard = self.write_lock.lock().await;
        let received_at = now_ms() as i64;
        sqlx::query(
            "INSERT INTO keypackages (device_id, received_at, payload, signature)
             VALUES (?, ?, ?, ?)",
        )
        .bind(device_id)
        .bind(received_at)
        .bind(&bundle.payload)
        .bind(&bundle.signature)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Returns the most recently received bundle for `device_id`. Scope A: the
    /// chat layer consumes one bundle per device. When multi-keypackage fanout
    /// lands, switch this to return a `Vec<StoredKeyPackageBundle>`.
    pub async fn latest(&self, device_id: &str) -> Result<Option<StoredKeyPackageBundle>> {
        let row = sqlx::query_as::<_, StoredKeyPackageBundle>(
            "SELECT payload, signature FROM keypackages
             WHERE device_id = ?
             ORDER BY received_at DESC
             LIMIT 1",
        )
        .bind(device_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Upsert the signed device-list bundle for `account_pub`. The server stores
    /// exactly one blob per account.
    ///
    /// Anti-replay: `lamport` is the monotonic version read from `bundle.payload`
    /// (already signature-verified by the handler, so a forged value can't slip
    /// past — the signature wouldn't match). The stored bundle is replaced only
    /// when `lamport` is strictly greater than the one currently on file. A
    /// replayed older-but-still-valid bundle therefore can't downgrade the device
    /// list, and `updated_at` (the retention clock) is only bumped on a real
    /// update so a replay can't keep a stale bundle alive past retention.
    ///
    /// Returns `true` when the bundle was stored, `false` when it was rejected as
    /// stale. The compare-and-swap runs inside a transaction so a concurrent
    /// publish can't interleave the read with the write. The `updated_at` field of
    /// `bundle` is ignored; the store stamps the row with the current time.
    pub async fn upsert_account(
        &self,
        account_pub: &str,
        lamport: u64,
        bundle: &StoredAccountBundle,
    ) -> Result<bool> {
        // SQLite allows only one writer. This transaction reads first to enforce
        // Lamport ordering, so concurrent mutations can otherwise race to
        // upgrade their shared read locks and fail with SQLITE_BUSY.
        let _write_guard = self.write_lock.lock().await;
        let updated_at = now_ms() as i64;

        let mut tx = self.pool.begin().await?;
        let existing_lamport = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT payload FROM account_bundles WHERE account_pub = ?",
        )
        .bind(account_pub)
        .fetch_optional(&mut *tx)
        .await?
        .and_then(|payload| payload_lamport(&payload));
        if let Some(stored) = existing_lamport
            && lamport <= stored
        {
            // Dropping `tx` rolls the (read-only) transaction back.
            return Ok(false);
        }
        sqlx::query(
            "INSERT INTO account_bundles (account_pub, updated_at, payload, signature)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(account_pub) DO UPDATE SET
               updated_at = excluded.updated_at,
               payload    = excluded.payload,
               signature  = excluded.signature",
        )
        .bind(account_pub)
        .bind(updated_at)
        .bind(&bundle.payload)
        .bind(&bundle.signature)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Returns the stored bundle for `account_pub`, or `None` if unknown.
    pub async fn get_account(&self, account_pub: &str) -> Result<Option<StoredAccountBundle>> {
        let row = sqlx::query_as::<_, StoredAccountBundle>(
            "SELECT payload, signature, updated_at FROM account_bundles
             WHERE account_pub = ?",
        )
        .bind(account_pub)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Drops account bundles that have not been refreshed within `retention`.
    pub async fn prune_accounts(&self, retention: Duration) -> Result<()> {
        let _write_guard = self.write_lock.lock().await;
        let cutoff_ms = now_ms().saturating_sub(retention.as_millis() as u64) as i64;
        sqlx::query("DELETE FROM account_bundles WHERE updated_at < ?")
            .bind(cutoff_ms)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Drops bundles older than `retention` and keeps at most
    /// `max_per_identity` per `device_id` — each device's history is bounded
    /// independently.
    pub async fn prune_key_packages(
        &self,
        max_per_identity: usize,
        retention: Duration,
    ) -> Result<()> {
        let _write_guard = self.write_lock.lock().await;
        let cutoff_ms = now_ms().saturating_sub(retention.as_millis() as u64) as i64;
        sqlx::query("DELETE FROM keypackages WHERE received_at < ?")
            .bind(cutoff_ms)
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "DELETE FROM keypackages
             WHERE rowid IN (
               SELECT rowid FROM (
                 SELECT rowid,
                        ROW_NUMBER() OVER (
                          PARTITION BY device_id
                          ORDER BY received_at DESC
                        ) AS rn
                 FROM keypackages
               )
               WHERE rn > ?
             )",
        )
        .bind(max_per_identity as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

/// Domain-separation prefix on every account-device-bundle payload. Must stay in
/// sync with `account_directory::BUNDLE_DOMAIN` in the conversations crate; this
/// throwaway service deliberately has no libchat-core dependency, so the constant
/// is duplicated here rather than imported.
const BUNDLE_DOMAIN: &[u8] = b"libchat:account-device-bundle\0";

/// Extract the lamport version from a bundle payload without otherwise
/// interpreting it. The canonical layout (owned by the conversations crate's
/// `encode_bundle_payload`) is `domain | version:u8 | lamport:u64 LE | …`, so the
/// lamport sits in the 8 bytes right after the domain prefix and version byte.
/// Returns `None` when the domain prefix is absent or the payload is too short to
/// contain a header — the handler treats either as a malformed request.
pub fn payload_lamport(payload: &[u8]) -> Option<u64> {
    payload
        .strip_prefix(BUNDLE_DOMAIN)?
        .get(1..9)
        .map(|b| u64::from_le_bytes(b.try_into().expect("1..9 is 8 bytes")))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal stand-in for a real bundle payload: the domain prefix plus the
    /// header fields the server reads (`version:u8 | lamport:u64 LE`), no device
    /// keys needed.
    fn payload_with_lamport(lamport: u64) -> Vec<u8> {
        let mut p = BUNDLE_DOMAIN.to_vec();
        p.push(1u8); // version
        p.extend_from_slice(&lamport.to_le_bytes());
        p
    }

    fn bundle(lamport: u64) -> StoredAccountBundle {
        StoredAccountBundle {
            payload: payload_with_lamport(lamport),
            signature: vec![0u8; 64],
            updated_at: 0,
        }
    }

    async fn upsert(store: &Store, account: &str, lamport: u64) -> bool {
        store
            .upsert_account(account, lamport, &bundle(lamport))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn rejects_replayed_or_stale_lamport() {
        let store = Store::open(Path::new(":memory:")).await.unwrap();

        // First publish is always accepted.
        assert!(upsert(&store, "acct", 5).await);
        // A strictly higher lamport replaces it.
        assert!(upsert(&store, "acct", 6).await);
        // Re-publishing the same lamport (a replay) is rejected.
        assert!(!upsert(&store, "acct", 6).await);
        // An older lamport (a downgrade) is rejected.
        assert!(!upsert(&store, "acct", 4).await);

        // The stored bundle is still the newest one accepted.
        let stored = store.get_account("acct").await.unwrap().unwrap();
        assert_eq!(payload_lamport(&stored.payload), Some(6));
    }

    #[tokio::test]
    async fn stale_publish_does_not_refresh_retention_clock() {
        let store = Store::open(Path::new(":memory:")).await.unwrap();
        assert!(upsert(&store, "acct", 9).await);
        let after_first = store.get_account("acct").await.unwrap().unwrap().updated_at;

        // A rejected (stale) publish must not bump updated_at, so a replay can't
        // keep a stale bundle alive past the retention window.
        assert!(!upsert(&store, "acct", 9).await);
        let after_replay = store.get_account("acct").await.unwrap().unwrap().updated_at;
        assert_eq!(after_first, after_replay);
    }

    #[tokio::test]
    async fn concurrent_account_publishes_succeed() {
        let store = std::sync::Arc::new(Store::open(Path::new(":memory:")).await.unwrap());
        let mut tasks = tokio::task::JoinSet::new();
        for index in 0..16 {
            let store = store.clone();
            tasks.spawn(async move { upsert(&store, &format!("acct-{index}"), 1).await });
        }
        while let Some(result) = tasks.join_next().await {
            assert!(result.unwrap());
        }
    }

    #[test]
    fn payload_lamport_requires_domain_and_full_header() {
        assert_eq!(payload_lamport(&payload_with_lamport(42)), Some(42));
        // Missing the domain prefix → unparseable.
        assert_eq!(payload_lamport(&[1u8, 0, 0, 0, 0, 0, 0, 0, 0]), None);
        // Has the domain but is too short for version + u64 → unparseable.
        let mut short = BUNDLE_DOMAIN.to_vec();
        short.push(1u8);
        assert_eq!(payload_lamport(&short), None);
    }
}
