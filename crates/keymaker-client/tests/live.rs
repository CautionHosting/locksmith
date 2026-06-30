//! Live integration tests against a deployed keymaker.
//!
//! These hit a real, running keymaker over the network. They are skipped (pass as no-ops, with a
//! note on stderr) unless `KEYMAKER_URL` is set, so an ordinary `cargo test` stays green offline.
//!
//! Run against a deployment:
//!
//! ```sh
//! KEYMAKER_URL=https://keymaker.caution.co \
//!   cargo test -p keymaker-client --test live -- --nocapture
//! ```
//!
//! Each test mints throwaway quorum material with a fresh in-memory keyring, so it's safe to run
//! repeatedly against the hosted (always-on, stateless) keymaker.

use keymaker_client::{KeymakerClient, models::generate_quorum::GenerateQuorumRequest};
use sequoia_openpgp::cert::CertBuilder;
use sequoia_openpgp::serialize::SerializeInto;
use sha2::{Digest, Sha256};

/// Returns the base URL under test, or `None` if `KEYMAKER_URL` is unset (→ skip).
fn base_url() -> Option<String> {
    match std::env::var("KEYMAKER_URL") {
        Ok(u) if !u.trim().is_empty() => Some(u.trim_end_matches('/').to_string()),
        _ => {
            eprintln!("skipping: set KEYMAKER_URL to run live keymaker tests");
            None
        }
    }
}

fn client() -> KeymakerClient {
    let url = base_url().unwrap();
    KeymakerClient::new(reqwest::Client::new(), url.parse().expect("KEYMAKER_URL must be a valid URL"))
}

/// `count` throwaway member TSKs armored into a single keyring string.
fn test_keyring(count: usize) -> String {
    (0..count)
        .map(|_| {
            let (cert, _) = CertBuilder::new()
                .add_userid("member")
                .add_authentication_subkey()
                .add_storage_encryption_subkey()
                .generate()
                .unwrap();
            String::from_utf8(cert.armored().to_vec().unwrap()).unwrap()
        })
        .collect()
}

fn request(keyring: String, threshold: u8, max: u8) -> GenerateQuorumRequest {
    GenerateQuorumRequest {
        label: Default::default(),
        threshold,
        max,
        keyring,
    }
}

/// `/health` answers and self-identifies as the hosted service.
#[tokio::test]
async fn health_is_ok() {
    let Some(base) = base_url() else { return };
    let body: serde_json::Value = reqwest::get(format!("{base}/health"))
        .await
        .expect("health request")
        .json()
        .await
        .expect("health body is json");
    assert_eq!(body["status"], "ok", "unexpected health body: {body}");
}

/// Statelessness / fresh entropy. The shardfile is non-deterministic even for fixed entropy
/// (ephemeral per-recipient session keys), so it proves nothing. The *public key* is derived
/// deterministically from the entropy — distinct public keys across calls means distinct entropy.
#[tokio::test]
async fn mints_are_independent() {
    let Some(_) = base_url() else { return };
    let client = client();
    let keyring = test_keyring(3);

    let mut public_keys = vec![];
    for _ in 0..4 {
        let resp = client
            .generate_quorum(request(keyring.clone(), 2, 3))
            .await
            .expect("generate_quorum");
        public_keys.push(resp.public_key);
    }

    public_keys.sort();
    public_keys.dedup();
    assert_eq!(
        public_keys.len(),
        4,
        "expected 4 distinct public keys (fresh entropy per call); got duplicates → state leak"
    );
}

/// The bundle echoes the keyring we sent and `keyring_hash` is its SHA-256.
#[tokio::test]
async fn keyring_hash_matches() {
    let Some(_) = base_url() else { return };
    let client = client();
    let keyring = test_keyring(3);

    let resp = client
        .generate_quorum(request(keyring.clone(), 2, 3))
        .await
        .expect("generate_quorum");

    assert_eq!(resp.keyring, keyring, "server should echo the submitted keyring");
    let expected = Sha256::digest(resp.keyring.as_bytes()).to_vec();
    assert_eq!(resp.keyring_hash, expected, "keyring_hash is not SHA-256 of keyring");
}

/// A real t-of-m bundle is well-formed: armored PGP public key + armored PGP shardfile.
#[tokio::test]
async fn quorum_2_of_3_is_well_formed() {
    let Some(_) = base_url() else { return };
    let client = client();
    let keyring = test_keyring(3);

    let resp = client
        .generate_quorum(request(keyring, 2, 3))
        .await
        .expect("generate_quorum");

    assert!(
        resp.public_key.contains("BEGIN PGP PUBLIC KEY BLOCK"),
        "public_key is not an armored PGP public key"
    );
    assert!(
        resp.shardfile.contains("BEGIN PGP MESSAGE"),
        "shardfile is not an armored PGP message"
    );
}

/// A garbage keyring is rejected with HTTP 400 and a non-empty `errors` array.
#[tokio::test]
async fn invalid_keyring_returns_400() {
    let Some(base) = base_url() else { return };
    let resp = reqwest::Client::new()
        .post(format!("{base}/generate_quorum"))
        .json(&serde_json::json!({
            "label": {},
            "threshold": 2u8,
            "max": 3u8,
            "keyring": "not a valid armored keyring",
        }))
        .send()
        .await
        .expect("generate_quorum request");

    assert_eq!(resp.status(), 400, "expected 400 for garbage keyring");
    let body: serde_json::Value = resp.json().await.expect("400 body is json");
    assert!(
        body["errors"].as_array().is_some_and(|e| !e.is_empty()),
        "expected non-empty errors array, got: {body}"
    );
}
