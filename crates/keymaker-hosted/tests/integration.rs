use keymaker_hosted::app;
use std::collections::HashMap;

async fn spawn() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app()).await.unwrap();
    });
    format!("http://{addr}")
}

/// Three test members (TSKs) armored into a single keyring string.
fn test_keyring() -> String {
    use sequoia_openpgp::cert::CertBuilder;
    use sequoia_openpgp::serialize::SerializeInto;
    (0..3)
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

#[tokio::test]
async fn health_is_ok() {
    let base = spawn().await;
    let body: serde_json::Value = reqwest::get(format!("{base}/health"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["service"], "keymaker-hosted");
}

#[tokio::test]
async fn concurrent_requests_return_independent_material() {
    // `/generate_quorum` calls `keyfork_entropy::ensure_safe()`, an airgap guard that aborts unless
    // every non-`lo` interface is down (true only inside a real Nitro enclave) or a documented
    // bypass var is set. Set the bypass so this test runs on an ordinary networked CI/dev host.
    unsafe { std::env::set_var("SHOOT_SELF_IN_FOOT", "1") };

    let base = spawn().await;
    let keyring = test_keyring();

    let mut handles = vec![];
    for _ in 0..4 {
        let base = base.clone();
        let keyring = keyring.clone();
        handles.push(tokio::spawn(async move {
            let req = serde_json::json!({
                "label": HashMap::<String, String>::new(),
                "threshold": 2u8,
                "max": 3u8,
                "keyring": keyring,
            });
            let resp: serde_json::Value = reqwest::Client::new()
                .post(format!("{base}/generate_quorum"))
                .json(&req)
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            resp["public_key"].as_str().unwrap().to_string()
        }));
    }

    let mut keys = vec![];
    for h in handles {
        keys.push(h.await.unwrap());
    }
    // Statelessness: each request generated its own fresh entropy → distinct derived public key.
    keys.sort();
    keys.dedup();
    assert_eq!(keys.len(), 4);
}

#[tokio::test]
async fn invalid_keyring_returns_400_with_errors_field() {
    // ensure_safe() fires before parse_certs; set the bypass so this test reaches cert parsing.
    unsafe { std::env::set_var("SHOOT_SELF_IN_FOOT", "1") };
    let base = spawn().await;
    let req = serde_json::json!({
        "label": HashMap::<String, String>::new(),
        "threshold": 2u8,
        "max": 3u8,
        "keyring": "not a valid armored keyring",
    });
    let resp = reqwest::Client::new()
        .post(format!("{base}/generate_quorum"))
        .json(&req)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["errors"].is_array() && !body["errors"].as_array().unwrap().is_empty(),
        "expected non-empty errors array, got: {body}"
    );
}
