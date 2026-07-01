//! Integration tests for the selfnuke keymaker.
//!
//! These verify the observable contract of the selfnuke behaviour without
//! actually rebooting: the `reboot_permit` semaphore is consumed after the
//! first `/generate_quorum` call, proving the reboot task was spawned.
//!
//! Run:
//!
//! ```sh
//! SHOOT_SELF_IN_FOOT=1 cargo test -p keymaker --test selfnuke -- --nocapture
//! ```
//!
//! The `SHOOT_SELF_IN_FOOT` bypass is required so that `ensure_safe()` passes
//! on a networked dev/CI host (it normally aborts outside a Nitro enclave).
//! The tests are skipped when the var is unset so `cargo test` stays green.

use keymaker::AppState;
use sequoia_openpgp::cert::CertBuilder;
use sequoia_openpgp::serialize::SerializeInto;
use std::collections::HashMap;
use std::sync::Arc;

fn bypass_active() -> bool {
    std::env::var("SHOOT_SELF_IN_FOOT").is_ok_and(|v| !v.is_empty())
}

async fn spawn() -> (String, Arc<AppState>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (router, state) = keymaker::app();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (format!("http://{addr}"), state)
}

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

fn quorum_request(keyring: String) -> serde_json::Value {
    serde_json::json!({
        "label": HashMap::<String, String>::new(),
        "threshold": 2u8,
        "max": 3u8,
        "keyring": keyring,
    })
}

/// Before any call, the semaphore has exactly one permit (one reboot may be scheduled).
#[tokio::test]
async fn reboot_permit_starts_at_one() {
    let (_base, state) = spawn().await;
    assert_eq!(state.reboot_permit.available_permits(), 1);
}

/// After `/generate_quorum` succeeds, the semaphore has zero permits — the reboot task
/// consumed and forgot the permit, so no second reboot can ever be scheduled.
#[cfg(all(feature = "selfnuke", target_os = "linux"))]
#[tokio::test]
async fn generate_quorum_consumes_reboot_permit() {
    if !bypass_active() {
        eprintln!("skipping: set SHOOT_SELF_IN_FOOT=1 to run selfnuke tests");
        return;
    }
    unsafe { std::env::set_var("SHOOT_SELF_IN_FOOT", "1") };

    let (base, state) = spawn().await;
    assert_eq!(state.reboot_permit.available_permits(), 1, "precondition");

    let resp = reqwest::Client::new()
        .post(format!("{base}/generate_quorum"))
        .json(&quorum_request(test_keyring(3)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Yield so the spawned reboot task gets a chance to acquire the permit.
    tokio::task::yield_now().await;
    assert_eq!(
        state.reboot_permit.available_permits(),
        0,
        "reboot task should have consumed the permit"
    );
}

/// A second call after the first still returns a valid response — the route itself
/// doesn't block on the permit. The spawned reboot task for the second call will
/// block forever on `acquire()` (no permit left), so only one reboot ever fires.
#[cfg(all(feature = "selfnuke", target_os = "linux"))]
#[tokio::test]
async fn second_call_returns_valid_response() {
    if !bypass_active() {
        eprintln!("skipping: set SHOOT_SELF_IN_FOOT=1 to run selfnuke tests");
        return;
    }
    unsafe { std::env::set_var("SHOOT_SELF_IN_FOOT", "1") };

    let (base, state) = spawn().await;
    let client = reqwest::Client::new();
    let keyring = test_keyring(3);

    for i in 0..2 {
        let resp = client
            .post(format!("{base}/generate_quorum"))
            .json(&quorum_request(keyring.clone()))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "call {i} should succeed");
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            body["public_key"]
                .as_str()
                .is_some_and(|k| k.contains("BEGIN PGP PUBLIC KEY BLOCK")),
            "call {i}: expected valid public key, got: {body}"
        );
        tokio::task::yield_now().await;
    }

    // Permit was consumed by the first call's reboot task; second call's task is blocked.
    assert_eq!(state.reboot_permit.available_permits(), 0);
}

/// The response bundle is well-formed even with selfnuke enabled.
#[cfg(all(feature = "selfnuke", target_os = "linux"))]
#[tokio::test]
async fn response_is_well_formed() {
    if !bypass_active() {
        eprintln!("skipping: set SHOOT_SELF_IN_FOOT=1 to run selfnuke tests");
        return;
    }
    unsafe { std::env::set_var("SHOOT_SELF_IN_FOOT", "1") };

    let (base, _state) = spawn().await;
    let resp = reqwest::Client::new()
        .post(format!("{base}/generate_quorum"))
        .json(&quorum_request(test_keyring(3)))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["public_key"]
            .as_str()
            .is_some_and(|k| k.contains("BEGIN PGP PUBLIC KEY BLOCK")),
        "public_key not a PGP public key: {body}"
    );
    assert!(
        body["shardfile"]
            .as_str()
            .is_some_and(|s| s.contains("BEGIN PGP MESSAGE")),
        "shardfile not a PGP message: {body}"
    );
}
