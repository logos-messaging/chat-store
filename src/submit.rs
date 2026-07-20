//! Shared submission pipeline.
//!
//! Both write paths — the HTTP POST endpoints and the logos-delivery
//! subscriber (`ingest`) — carry the same JSON submissions and feed them
//! through these functions, so signature verification and storage rules are
//! identical no matter which wire delivered the request.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;

use crate::store::{Store, StoredAccountBundle, StoredKeyPackageBundle};

/// A signed keypackage bundle submission.
#[derive(Debug, Deserialize)]
pub struct SubmitRequest {
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

/// A signed account device-list bundle submission.
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

#[derive(Debug)]
pub enum SubmitError {
    /// Malformed submission or failed signature verification.
    Invalid(&'static str),
    /// Valid account bundle whose lamport is not newer than the stored one.
    Stale,
    /// Storage failure.
    Internal(anyhow::Error),
}

impl std::fmt::Display for SubmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubmitError::Invalid(msg) => write!(f, "{msg}"),
            SubmitError::Stale => {
                write!(f, "stale bundle: lamport is not newer than the stored one")
            }
            SubmitError::Internal(err) => write!(f, "internal: {err}"),
        }
    }
}

/// Decoded and signature-verified fields common to both submission kinds.
struct Verified {
    payload: Vec<u8>,
    signature: [u8; 64],
}

/// Verify proof-of-possession before persisting. `payload` is opaque — the
/// server only checks that `signature` over the received payload bytes is
/// valid under `key_hex`'s key. A valid signature means the submitter holds
/// that key. This rejects junk early (DoS mitigation); consumers still verify
/// on retrieve, the server is not a trusted authority.
fn verify(
    key_hex: &str,
    payload_b64: &str,
    signature_b64: &str,
    key_field: KeyField,
) -> Result<Verified, SubmitError> {
    let pubkey: [u8; 32] = hex::decode(key_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(SubmitError::Invalid(key_field.not_hex))?;
    let payload = BASE64
        .decode(payload_b64)
        .map_err(|_| SubmitError::Invalid("payload: not valid base64"))?;
    let signature: [u8; 64] = BASE64
        .decode(signature_b64)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(SubmitError::Invalid("signature: must be base64 of 64 bytes"))?;

    let verifying_key =
        VerifyingKey::from_bytes(&pubkey).map_err(|_| SubmitError::Invalid(key_field.not_key))?;
    verifying_key
        .verify_strict(&payload, &Signature::from_bytes(&signature))
        .map_err(|_| SubmitError::Invalid("signature: verification failed"))?;
    Ok(Verified { payload, signature })
}

/// Error messages named after the submission's key field, so HTTP responses
/// and ingest logs point at the right field.
struct KeyField {
    not_hex: &'static str,
    not_key: &'static str,
}

const DEVICE_ID: KeyField = KeyField {
    not_hex: "device_id: must be hex of a 32-byte key",
    not_key: "device_id: not a valid ed25519 key",
};

const ACCOUNT_PUB: KeyField = KeyField {
    not_hex: "account_pub: must be hex of a 32-byte key",
    not_key: "account_pub: not a valid ed25519 key",
};

/// Verify and store a keypackage bundle submission.
pub async fn apply_keypackage(store: &Store, req: &SubmitRequest) -> Result<(), SubmitError> {
    let verified = verify(&req.device_id, &req.payload, &req.signature, DEVICE_ID)?;
    store
        .insert(
            &req.device_id,
            &StoredKeyPackageBundle {
                payload: verified.payload,
                signature: verified.signature.to_vec(),
            },
        )
        .await
        .map_err(SubmitError::Internal)
}

/// Verify and upsert an account device-list bundle submission.
pub async fn apply_account(store: &Store, req: &SubmitAccountRequest) -> Result<(), SubmitError> {
    let verified = verify(&req.account_pub, &req.payload, &req.signature, ACCOUNT_PUB)?;

    // Read the bundle's lamport so the store can reject replays. Safe to trust:
    // the signature over `payload` was just verified, so the lamport can't be
    // forged without the account key.
    let lamport = crate::store::payload_lamport(&verified.payload).ok_or(SubmitError::Invalid(
        "payload: too short to contain a lamport header",
    ))?;

    let applied = store
        .upsert_account(
            &req.account_pub,
            lamport,
            &StoredAccountBundle {
                payload: verified.payload,
                signature: verified.signature.to_vec(),
                updated_at: 0, // filled in by store
            },
        )
        .await
        .map_err(SubmitError::Internal)?;
    if !applied {
        return Err(SubmitError::Stale);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    use super::*;

    /// Must match `BUNDLE_DOMAIN` in `store.rs` (kept private there).
    const ACCOUNT_BUNDLE_DOMAIN: &[u8] = b"libchat:account-device-bundle\0";

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// A submission exactly as it arrives off the delivery wire: the JSON body
    /// libchat's `DeliveryRegistry` publishes (same shape as the POST body).
    fn keypackage_submission_json(key: &SigningKey, payload: &[u8]) -> Vec<u8> {
        json!({
            "device_id": hex::encode(key.verifying_key().as_bytes()),
            "payload": BASE64.encode(payload),
            "signature": BASE64.encode(key.sign(payload).to_bytes()),
        })
        .to_string()
        .into_bytes()
    }

    fn account_payload(lamport: u64) -> Vec<u8> {
        let mut p = ACCOUNT_BUNDLE_DOMAIN.to_vec();
        p.push(1u8); // version
        p.extend_from_slice(&lamport.to_le_bytes());
        p
    }

    fn account_submission(key: &SigningKey, payload: &[u8]) -> SubmitAccountRequest {
        SubmitAccountRequest {
            account_pub: hex::encode(key.verifying_key().as_bytes()),
            payload: BASE64.encode(payload),
            signature: BASE64.encode(key.sign(payload).to_bytes()),
        }
    }

    #[tokio::test]
    async fn wire_json_keypackage_is_parsed_verified_and_stored() {
        let store = Store::open(Path::new(":memory:")).await.unwrap();
        let key = signing_key(1);
        let payload = b"ts-and-keypackage-bytes".to_vec();

        let wire = keypackage_submission_json(&key, &payload);
        let req: SubmitRequest = serde_json::from_slice(&wire).unwrap();
        apply_keypackage(&store, &req).await.unwrap();

        let stored = store.latest(&req.device_id).await.unwrap().unwrap();
        assert_eq!(stored.payload, payload);
    }

    #[tokio::test]
    async fn tampered_keypackage_submission_is_rejected() {
        let store = Store::open(Path::new(":memory:")).await.unwrap();
        let key = signing_key(2);

        let mut req: SubmitRequest =
            serde_json::from_slice(&keypackage_submission_json(&key, b"original")).unwrap();
        req.payload = BASE64.encode(b"tampered");

        let err = apply_keypackage(&store, &req).await.unwrap_err();
        assert!(matches!(err, SubmitError::Invalid("signature: verification failed")));
        assert!(store.latest(&req.device_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn account_submission_upserts_and_rejects_stale_replay() {
        let store = Store::open(Path::new(":memory:")).await.unwrap();
        let key = signing_key(3);

        apply_account(&store, &account_submission(&key, &account_payload(1)))
            .await
            .unwrap();
        apply_account(&store, &account_submission(&key, &account_payload(2)))
            .await
            .unwrap();

        // Replaying the lamport-2 bundle (as a delivery duplicate would) is stale.
        let err = apply_account(&store, &account_submission(&key, &account_payload(2)))
            .await
            .unwrap_err();
        assert!(matches!(err, SubmitError::Stale));
    }
}
