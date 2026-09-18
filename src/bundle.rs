//! Bundles: an opaque payload plus its signature, published under the key that
//! signed it. This is what the store holds and what both write paths carry.
//!
//! Each wire encodes a bundle in its own way — the HTTP POST endpoints take a
//! JSON body with hex and base64 strings, the logos-delivery subscriber
//! (`delivery`) takes a protobuf message with raw bytes — and both decode into
//! a [`Bundle`]. Verification and storage rules below are therefore identical
//! no matter which wire carried it.

use account_log::{
    AccountAddr, AccountLogError, AccountRecord, LogFreshness, Outcome, SignedAccountLog,
};
use ed25519_dalek::{Signature, VerifyingKey};

use crate::store::{Store, StoredAccountBundle, StoredKeyPackageBundle};

#[derive(Debug)]
pub enum BundleError {
    /// Malformed bundle or failed signature verification.
    Invalid(&'static str),
    /// Authentic account log that does not decode, or breaks the log's rules.
    MalformedLog(AccountLogError),
    /// Valid account bundle or log that is not newer than the stored one.
    Stale,
    /// Valid account log that rewrites the stored one instead of extending it.
    Forked,
    /// Storage failure.
    Internal(anyhow::Error),
}

impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BundleError::Invalid(msg) => write!(f, "{msg}"),
            BundleError::MalformedLog(err) => write!(f, "{err}"),
            BundleError::Stale => write!(f, "stale bundle: not newer than the stored one"),
            BundleError::Forked => write!(f, "forked log: does not extend the stored one"),
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

/// Verify and store an account log. An account log is not a [`Bundle`]: the
/// account-log crate defines how it travels, so a wire decodes it straight
/// into the crate's types. What is valid and what is newer are the crate's
/// rules too, the ones consumers apply: the log replaces the stored one only
/// when it strictly extends it, and resubmitting the stored log is accepted and
/// changes nothing, so a retried publish is not reported as stale.
pub async fn apply_account_log(
    store: &Store,
    addr: AccountAddr,
    signed: SignedAccountLog,
) -> Result<(), BundleError> {
    // Verify and decode before the store takes its write lock, so junk is
    // rejected early, as `verify` does for the other bundles.
    let candidate = AccountRecord::new(addr, signed).map_err(|err| match err {
        AccountLogError::SignatureInvalid => BundleError::Invalid("signature: verification failed"),
        err => BundleError::MalformedLog(err),
    })?;

    match store
        .put_account_log(candidate)
        .await
        .map_err(BundleError::Internal)?
    {
        Outcome::Updated | Outcome::Unchanged(LogFreshness::Identical) => Ok(()),
        Outcome::Unchanged(LogFreshness::Behind) => Err(BundleError::Stale),
        Outcome::Unchanged(LogFreshness::Diverged) => Err(BundleError::Forked),
        // The candidate was verified above, and a newer log is `Updated`.
        other => Err(BundleError::Internal(anyhow::anyhow!(
            "unexpected account log outcome: {other:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use account_log::{AccountLogDraft, EntryData, SIGNER_CONTEXT};
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
    use crate::handlers::keypackage::SubmitKeyPackageRequest;

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

    /// An account log endorsing one device key per seed, in order, encoded by
    /// the account-log crate as a client would publish it.
    fn account_log(device_seeds: &[u8]) -> Vec<u8> {
        let mut draft = AccountLogDraft::new();
        for &seed in device_seeds {
            let device = signing_key(seed).verifying_key().to_bytes();
            draft
                .add(SIGNER_CONTEXT.clone(), EntryData::Ed25519Key(device))
                .unwrap();
        }
        draft.log().encode().unwrap().as_bytes().to_vec()
    }

    /// `payload` signed by `key`, read from the artifact the account-log crate
    /// transmits: `signature || payload`.
    fn signed_log(key: &SigningKey, payload: &[u8]) -> SignedAccountLog {
        let mut artifact = key.sign(payload).to_bytes().to_vec();
        artifact.extend_from_slice(payload);
        SignedAccountLog::from_bytes(&artifact).unwrap()
    }

    fn addr_of(key: &SigningKey) -> AccountAddr {
        AccountAddr::try_from(key.verifying_key().as_bytes().as_slice()).unwrap()
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

    #[tokio::test]
    async fn account_log_must_extend_the_stored_one() {
        let store = Store::open(Path::new(":memory:")).await.unwrap();
        let key = signing_key(4);
        let addr = addr_of(&key);
        let log = |devices: &[u8]| signed_log(&key, &account_log(devices));

        // The empty log is valid: an account that has endorsed nothing yet.
        apply_account_log(&store, addr.clone(), log(&[]))
            .await
            .unwrap();
        apply_account_log(&store, addr.clone(), log(&[1]))
            .await
            .unwrap();
        // Resubmitting the stored log (a retried publish) is accepted.
        apply_account_log(&store, addr.clone(), log(&[1]))
            .await
            .unwrap();
        apply_account_log(&store, addr.clone(), log(&[1, 2]))
            .await
            .unwrap();

        let err = apply_account_log(&store, addr.clone(), log(&[1]))
            .await
            .unwrap_err();
        assert!(matches!(err, BundleError::Stale));
        let err = apply_account_log(&store, addr.clone(), log(&[3, 2, 1]))
            .await
            .unwrap_err();
        assert!(matches!(err, BundleError::Forked));

        // Neither refusal touched the stored log: it is the last one accepted,
        // served back as the artifact it was published as.
        let stored = store.get_account_log(&addr).await.unwrap().unwrap();
        assert_eq!(stored, log(&[1, 2]).to_bytes());
        let never_published = addr_of(&signing_key(7));
        assert!(
            store
                .get_account_log(&never_published)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn account_log_must_be_authentic_and_well_formed() {
        let store = Store::open(Path::new(":memory:")).await.unwrap();
        let key = signing_key(5);

        // Signed by another key: refused on the signature.
        let forged = signed_log(&signing_key(6), &account_log(&[1]));
        let err = apply_account_log(&store, addr_of(&key), forged)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            BundleError::Invalid("signature: verification failed")
        ));

        // Authentic, but a v0 device-list bundle rather than an account log.
        let v0_bundle = signed_log(&key, &account_payload(1));
        let err = apply_account_log(&store, addr_of(&key), v0_bundle)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            BundleError::MalformedLog(AccountLogError::Malformed(_))
        ));
    }
}
