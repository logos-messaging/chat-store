//! Bundles: an opaque payload plus its signature, published under the key that
//! signed it. This is what the store holds and what both write paths carry.
//!
//! Each wire encodes a bundle in its own way — the HTTP POST endpoints take a
//! JSON body with hex and base64 strings, the logos-delivery subscriber
//! (`delivery`) takes a protobuf message with raw bytes — and both decode into
//! a [`Bundle`]. Verification and storage rules below are therefore identical
//! no matter which wire carried it.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::store::{Store, StoredAccountBundle, StoredKeyPackageBundle};

#[derive(Debug)]
pub enum BundleError {
    /// Malformed bundle or failed signature verification.
    Invalid(&'static str),
    /// Valid account bundle whose lamport is not newer than the stored one.
    Stale,
    /// Storage failure.
    Internal(anyhow::Error),
}

impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BundleError::Invalid(msg) => write!(f, "{msg}"),
            BundleError::Stale => {
                write!(f, "stale bundle: lamport is not newer than the stored one")
            }
            BundleError::Internal(err) => write!(f, "internal: {err}"),
        }
    }
}

/// A bundle decoded off either wire, before verification: the raw key,
/// payload and signature bytes that both encodings ultimately carry.
#[derive(Debug)]
pub struct Bundle {
    key: [u8; 32],
    payload: Vec<u8>,
    signature: [u8; 64],
}

impl Bundle {
    /// From raw bytes, as the protobuf wire carries them. Keypackage and
    /// account bundles are the same shape here — which kind it is comes from
    /// the topic it arrived on and the `apply_*` it is passed to.
    pub fn from_bytes(key: &[u8], payload: &[u8], signature: &[u8]) -> Result<Self, BundleError> {
        Ok(Self {
            key: key
                .try_into()
                .map_err(|_| BundleError::Invalid("key: must be 32 bytes"))?,
            payload: payload.to_vec(),
            signature: signature
                .try_into()
                .map_err(|_| BundleError::Invalid("signature: must be 64 bytes"))?,
        })
    }

    /// Hex of the bundle's key — the store's lookup key. Canonical
    /// lowercase, so the same key always lands in the same row whichever wire
    /// and whichever casing it arrived in.
    pub fn key_hex(&self) -> String {
        hex::encode(self.key)
    }
}

/// Verify proof-of-possession before persisting. `payload` is opaque — the
/// server only checks that `signature` over the received payload bytes is
/// valid under the bundle's key. A valid signature means the submitter
/// holds that key. This rejects junk early (DoS mitigation); consumers still
/// verify on retrieve, the server is not a trusted authority.
fn verify(bundle: &Bundle) -> Result<(), BundleError> {
    let verifying_key = VerifyingKey::from_bytes(&bundle.key)
        .map_err(|_| BundleError::Invalid("key: not a valid ed25519 key"))?;
    verifying_key
        .verify_strict(&bundle.payload, &Signature::from_bytes(&bundle.signature))
        .map_err(|_| BundleError::Invalid("signature: verification failed"))?;
    Ok(())
}

/// Verify and store a keypackage bundle.
pub async fn apply_keypackage(store: &Store, bundle: &Bundle) -> Result<(), BundleError> {
    verify(bundle)?;
    store
        .insert(
            &bundle.key_hex(),
            &StoredKeyPackageBundle {
                payload: bundle.payload.clone(),
                signature: bundle.signature.to_vec(),
            },
        )
        .await
        .map_err(BundleError::Internal)
}

/// Verify and upsert an account device-list bundle.
pub async fn apply_account(store: &Store, bundle: &Bundle) -> Result<(), BundleError> {
    verify(bundle)?;

    // Read the bundle's lamport so the store can reject replays. Safe to trust:
    // the signature over `payload` was just verified, so the lamport can't be
    // forged without the account key.
    let lamport = crate::store::payload_lamport(&bundle.payload).ok_or(BundleError::Invalid(
        "payload: too short to contain a lamport header",
    ))?;

    let applied = store
        .upsert_account(
            &bundle.key_hex(),
            lamport,
            &StoredAccountBundle {
                payload: bundle.payload.clone(),
                signature: bundle.signature.to_vec(),
                updated_at: 0, // filled in by store
            },
        )
        .await
        .map_err(BundleError::Internal)?;
    if !applied {
        return Err(BundleError::Stale);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use chat_proto::logoschat::store::{AccountSubmissionV1, KeyPackageSubmissionV1};
    use ed25519_dalek::{Signer, SigningKey};
    use prost::Message;
    use prost::bytes::Bytes;
    use serde_json::json;

    use super::*;
    // The JSON body lives with the HTTP wire that owns it; this test asserts
    // that wire and the protobuf one decode to the same bundle.
    use crate::handlers::SubmitKeyPackageRequest;

    /// Must match `BUNDLE_DOMAIN` in `store.rs` (kept private there).
    const ACCOUNT_BUNDLE_DOMAIN: &[u8] = b"libchat:account-device-bundle\0";

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// A keypackage bundle exactly as it arrives off the delivery wire:
    /// the protobuf message libchat's `DeliveryRegistry` publishes.
    fn keypackage_submission_proto(key: &SigningKey, payload: &[u8]) -> Vec<u8> {
        KeyPackageSubmissionV1 {
            device_id: Bytes::copy_from_slice(key.verifying_key().as_bytes()),
            payload: Bytes::copy_from_slice(payload),
            signature: Bytes::copy_from_slice(&key.sign(payload).to_bytes()),
        }
        .encode_to_vec()
    }

    /// The same bundle as the HTTP POST body.
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

    fn account_submission(key: &SigningKey, payload: &[u8]) -> Bundle {
        Bundle::from_bytes(
            key.verifying_key().as_bytes(),
            payload,
            &key.sign(payload).to_bytes(),
        )
        .unwrap()
    }

    /// The protobuf wire and the JSON body must decode to the same bundle,
    /// so the store applies identical rules whichever path delivered it.
    #[tokio::test]
    async fn proto_and_json_keypackage_wires_agree() {
        let key = signing_key(1);
        let payload = b"ts-and-keypackage-bytes".to_vec();

        let wire = KeyPackageSubmissionV1::decode(&keypackage_submission_proto(&key, &payload)[..])
            .unwrap();
        let from_proto =
            Bundle::from_bytes(&wire.device_id, &wire.payload, &wire.signature).unwrap();

        let body: SubmitKeyPackageRequest =
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
        let bundle = Bundle::from_bytes(&wire.device_id, &wire.payload, &wire.signature).unwrap();
        apply_keypackage(&store, &bundle).await.unwrap();

        let stored = store.latest(&bundle.key_hex()).await.unwrap().unwrap();
        assert_eq!(stored.payload, payload);
    }

    #[tokio::test]
    async fn tampered_keypackage_bundle_is_rejected() {
        let store = Store::open(Path::new(":memory:")).await.unwrap();
        let key = signing_key(2);

        let mut wire =
            KeyPackageSubmissionV1::decode(&keypackage_submission_proto(&key, b"original")[..])
                .unwrap();
        wire.payload = Bytes::from_static(b"tampered");
        let bundle = Bundle::from_bytes(&wire.device_id, &wire.payload, &wire.signature).unwrap();

        let err = apply_keypackage(&store, &bundle).await.unwrap_err();
        assert!(matches!(
            err,
            BundleError::Invalid("signature: verification failed")
        ));
        assert!(store.latest(&bundle.key_hex()).await.unwrap().is_none());
    }

    /// A truncated or foreign payload on the bundle topics must be dropped,
    /// not panic the ingest thread.
    #[test]
    fn non_protobuf_bytes_are_rejected() {
        assert!(KeyPackageSubmissionV1::decode(&b"{\"device_id\":\"xx\"}"[..]).is_err());
        assert!(AccountSubmissionV1::decode(&[0xff, 0xff, 0xff][..]).is_err());
    }

    /// A key that is not 32 bytes is rejected at decode, before verification.
    #[test]
    fn short_key_is_rejected() {
        let err = Bundle::from_bytes(&[1u8; 31], b"payload", &[0u8; 64]).unwrap_err();
        assert!(matches!(err, BundleError::Invalid("key: must be 32 bytes")));
    }

    #[tokio::test]
    async fn account_bundle_upserts_and_rejects_stale_replay() {
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
        assert!(matches!(err, BundleError::Stale));
    }
}
