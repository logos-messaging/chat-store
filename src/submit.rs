//! Shared submission pipeline.
//!
//! The two write paths carry the same fields in the encoding native to each
//! wire: the HTTP POST endpoints take a JSON body with hex and base64 strings,
//! while the logos-delivery subscriber (`ingest`) takes a protobuf message
//! with raw bytes. Both decode into a [`Submission`] and feed it through these
//! functions, so signature verification and storage rules are identical no
//! matter which wire delivered the request.

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

impl SubmitRequest {
    /// Decode the JSON body's hex + base64 fields into a [`Submission`].
    pub fn decode(&self) -> Result<Submission, SubmitError> {
        Submission::from_encoded(&self.device_id, &self.payload, &self.signature, DEVICE_ID)
    }
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

impl SubmitAccountRequest {
    /// Decode the JSON body's hex + base64 fields into a [`Submission`].
    pub fn decode(&self) -> Result<Submission, SubmitError> {
        Submission::from_encoded(
            &self.account_pub,
            &self.payload,
            &self.signature,
            ACCOUNT_PUB,
        )
    }
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

/// A submission decoded off either wire, before verification: the raw key,
/// payload and signature bytes that both encodings ultimately carry.
#[derive(Debug)]
pub struct Submission {
    key: [u8; 32],
    payload: Vec<u8>,
    signature: [u8; 64],
}

impl Submission {
    /// A keypackage submission from raw bytes, as the protobuf wire carries them.
    pub fn keypackage(
        device_id: &[u8],
        payload: &[u8],
        signature: &[u8],
    ) -> Result<Self, SubmitError> {
        Self::from_bytes(device_id, payload, signature, DEVICE_ID)
    }

    /// An account device-list submission from raw bytes.
    pub fn account(
        account_pub: &[u8],
        payload: &[u8],
        signature: &[u8],
    ) -> Result<Self, SubmitError> {
        Self::from_bytes(account_pub, payload, signature, ACCOUNT_PUB)
    }

    fn from_bytes(
        key: &[u8],
        payload: &[u8],
        signature: &[u8],
        key_field: KeyField,
    ) -> Result<Self, SubmitError> {
        Ok(Self {
            key: key
                .try_into()
                .map_err(|_| SubmitError::Invalid(key_field.not_32_bytes))?,
            payload: payload.to_vec(),
            signature: signature
                .try_into()
                .map_err(|_| SubmitError::Invalid("signature: must be 64 bytes"))?,
        })
    }

    /// From the HTTP body's hex key and base64 payload/signature.
    fn from_encoded(
        key_hex: &str,
        payload_b64: &str,
        signature_b64: &str,
        key_field: KeyField,
    ) -> Result<Self, SubmitError> {
        let key: [u8; 32] = hex::decode(key_hex)
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
            .ok_or(SubmitError::Invalid(
                "signature: must be base64 of 64 bytes",
            ))?;
        Ok(Self {
            key,
            payload,
            signature,
        })
    }

    /// Hex of the submission's key — the store's lookup key. Canonical
    /// lowercase, so the same key always lands in the same row whichever wire
    /// and whichever casing it arrived in.
    pub fn key_hex(&self) -> String {
        hex::encode(self.key)
    }
}

/// Verify proof-of-possession before persisting. `payload` is opaque — the
/// server only checks that `signature` over the received payload bytes is
/// valid under the submission's key. A valid signature means the submitter
/// holds that key. This rejects junk early (DoS mitigation); consumers still
/// verify on retrieve, the server is not a trusted authority.
fn verify(submission: &Submission, key_field: KeyField) -> Result<(), SubmitError> {
    let verifying_key = VerifyingKey::from_bytes(&submission.key)
        .map_err(|_| SubmitError::Invalid(key_field.not_key))?;
    verifying_key
        .verify_strict(
            &submission.payload,
            &Signature::from_bytes(&submission.signature),
        )
        .map_err(|_| SubmitError::Invalid("signature: verification failed"))?;
    Ok(())
}

/// Error messages named after the submission's key field, so HTTP responses
/// and ingest logs point at the right field.
#[derive(Clone, Copy)]
struct KeyField {
    not_hex: &'static str,
    not_32_bytes: &'static str,
    not_key: &'static str,
}

const DEVICE_ID: KeyField = KeyField {
    not_hex: "device_id: must be hex of a 32-byte key",
    not_32_bytes: "device_id: must be 32 bytes",
    not_key: "device_id: not a valid ed25519 key",
};

const ACCOUNT_PUB: KeyField = KeyField {
    not_hex: "account_pub: must be hex of a 32-byte key",
    not_32_bytes: "account_pub: must be 32 bytes",
    not_key: "account_pub: not a valid ed25519 key",
};

/// Verify and store a keypackage bundle submission.
pub async fn apply_keypackage(store: &Store, submission: &Submission) -> Result<(), SubmitError> {
    verify(submission, DEVICE_ID)?;
    store
        .insert(
            &submission.key_hex(),
            &StoredKeyPackageBundle {
                payload: submission.payload.clone(),
                signature: submission.signature.to_vec(),
            },
        )
        .await
        .map_err(SubmitError::Internal)
}

/// Verify and upsert an account device-list bundle submission.
pub async fn apply_account(store: &Store, submission: &Submission) -> Result<(), SubmitError> {
    verify(submission, ACCOUNT_PUB)?;

    // Read the bundle's lamport so the store can reject replays. Safe to trust:
    // the signature over `payload` was just verified, so the lamport can't be
    // forged without the account key.
    let lamport = crate::store::payload_lamport(&submission.payload).ok_or(SubmitError::Invalid(
        "payload: too short to contain a lamport header",
    ))?;

    let applied = store
        .upsert_account(
            &submission.key_hex(),
            lamport,
            &StoredAccountBundle {
                payload: submission.payload.clone(),
                signature: submission.signature.to_vec(),
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

    use chat_proto::logoschat::store::{AccountSubmissionV1, KeyPackageSubmissionV1};
    use ed25519_dalek::{Signer, SigningKey};
    use prost::Message;
    use prost::bytes::Bytes;
    use serde_json::json;

    use super::*;

    /// Must match `BUNDLE_DOMAIN` in `store.rs` (kept private there).
    const ACCOUNT_BUNDLE_DOMAIN: &[u8] = b"libchat:account-device-bundle\0";

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// A keypackage submission exactly as it arrives off the delivery wire:
    /// the protobuf message libchat's `DeliveryRegistry` publishes.
    fn keypackage_submission_proto(key: &SigningKey, payload: &[u8]) -> Vec<u8> {
        KeyPackageSubmissionV1 {
            device_id: Bytes::copy_from_slice(key.verifying_key().as_bytes()),
            payload: Bytes::copy_from_slice(payload),
            signature: Bytes::copy_from_slice(&key.sign(payload).to_bytes()),
        }
        .encode_to_vec()
    }

    /// The same submission as the HTTP POST body.
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

    fn account_submission(key: &SigningKey, payload: &[u8]) -> Submission {
        Submission::account(
            key.verifying_key().as_bytes(),
            payload,
            &key.sign(payload).to_bytes(),
        )
        .unwrap()
    }

    /// The protobuf wire and the JSON body must decode to the same submission,
    /// so the store applies identical rules whichever path delivered it.
    #[tokio::test]
    async fn proto_and_json_keypackage_wires_agree() {
        let key = signing_key(1);
        let payload = b"ts-and-keypackage-bytes".to_vec();

        let wire = KeyPackageSubmissionV1::decode(&keypackage_submission_proto(&key, &payload)[..])
            .unwrap();
        let from_proto =
            Submission::keypackage(&wire.device_id, &wire.payload, &wire.signature).unwrap();

        let body: SubmitRequest =
            serde_json::from_slice(&keypackage_submission_json(&key, &payload)).unwrap();
        let from_json = body.decode().unwrap();

        assert_eq!(from_proto.key_hex(), from_json.key_hex());
        assert_eq!(from_proto.payload, from_json.payload);
        assert_eq!(from_proto.signature, from_json.signature);
    }

    #[tokio::test]
    async fn wire_proto_keypackage_is_parsed_verified_and_stored() {
        let store = Store::open(Path::new(":memory:")).await.unwrap();
        let key = signing_key(1);
        let payload = b"ts-and-keypackage-bytes".to_vec();

        let wire = KeyPackageSubmissionV1::decode(&keypackage_submission_proto(&key, &payload)[..])
            .unwrap();
        let submission =
            Submission::keypackage(&wire.device_id, &wire.payload, &wire.signature).unwrap();
        apply_keypackage(&store, &submission).await.unwrap();

        let stored = store.latest(&submission.key_hex()).await.unwrap().unwrap();
        assert_eq!(stored.payload, payload);
    }

    #[tokio::test]
    async fn tampered_keypackage_submission_is_rejected() {
        let store = Store::open(Path::new(":memory:")).await.unwrap();
        let key = signing_key(2);

        let mut wire =
            KeyPackageSubmissionV1::decode(&keypackage_submission_proto(&key, b"original")[..])
                .unwrap();
        wire.payload = Bytes::from_static(b"tampered");
        let submission =
            Submission::keypackage(&wire.device_id, &wire.payload, &wire.signature).unwrap();

        let err = apply_keypackage(&store, &submission).await.unwrap_err();
        assert!(matches!(
            err,
            SubmitError::Invalid("signature: verification failed")
        ));
        assert!(store.latest(&submission.key_hex()).await.unwrap().is_none());
    }

    /// A truncated or foreign payload on the submission topics must be dropped,
    /// not panic the ingest thread.
    #[test]
    fn non_protobuf_bytes_are_rejected() {
        assert!(KeyPackageSubmissionV1::decode(&b"{\"device_id\":\"xx\"}"[..]).is_err());
        assert!(AccountSubmissionV1::decode(&[0xff, 0xff, 0xff][..]).is_err());
    }

    /// A key that is not 32 bytes is rejected at decode, before verification.
    #[test]
    fn short_key_is_rejected() {
        let err = Submission::keypackage(&[1u8; 31], b"payload", &[0u8; 64]).unwrap_err();
        assert!(matches!(
            err,
            SubmitError::Invalid("device_id: must be 32 bytes")
        ));
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
