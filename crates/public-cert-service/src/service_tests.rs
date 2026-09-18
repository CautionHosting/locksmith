use super::*;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use std::time::{Duration, Instant};
use tower::ServiceExt;

async fn issuance_status(state: Arc<AppState>) -> StatusCode {
    router(state)
        .oneshot(
            Request::post("/v1/public-certificates")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "version": "V1", "organization_id": vec![1; 16], "certificate_count": 1
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn timed_out_or_cancelled_generation_remains_busy_until_worker_finishes() {
    for cancel in [false, true] {
        let state = Arc::new(AppState::new());
        let worker_state = state.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (finish_tx, finish_rx) = std::sync::mpsc::channel();
        let task = tokio::spawn(async move {
            worker_state
                .generate_with(Instant::now() + Duration::from_millis(300), move || {
                    started_tx.send(()).unwrap();
                    finish_rx.recv().unwrap();
                    Err::<(), _>(service::Error::unavailable("test worker failed"))
                })
                .await
        });
        started_rx.await.unwrap();
        assert_eq!(
            issuance_status(state.clone()).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        if cancel {
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        } else {
            assert!(task.await.unwrap().is_err());
        }
        assert_eq!(
            issuance_status(state.clone()).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(state.generation.available_permits(), 0);
        finish_tx.send(()).unwrap();
        let permit = tokio::time::timeout(Duration::from_secs(2), state.generation.acquire())
            .await
            .unwrap()
            .unwrap();
        drop(permit);
        assert!(
            state
                .generate_with(Instant::now() + Duration::from_secs(1), || Ok(()))
                .await
                .is_ok()
        );
    }
}

fn isolated(name: &str) -> bool {
    const CHILD: &str = "CERTIFICATE_SERVICE_REGRESSION_CHILD";
    if std::env::var_os(CHILD).is_some() {
        return false;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
    true
}

#[test]
fn readiness_tracks_root_identity_and_keyfork_availability() {
    if isolated("service_tests::readiness_tracks_root_identity_and_keyfork_availability") {
        return;
    }
    keyforkd::test_util::run_test(&[9; 32], |socket| -> keyforkd::test_util::Panicable {
        let ca = service::root_ca(Instant::now() + service::REQUEST_BUDGET)
            .unwrap()
            .strip_secret_key_material();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let healthy = Arc::new(AppState {
            expected_ca: Some(ca.clone()),
            ..AppState::new()
        });
        runtime.block_on(async {
            healthy.check_ready().await.unwrap();
            let response = router(healthy.clone())
                .oneshot(Request::get("/health").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                serde_json::json!({"status":"ready", "service":"public-cert-service"})
            );
            // Recreating the HTTP service preserves the existing enclave custody root.
            AppState {
                expected_ca: Some(ca),
                ..AppState::new()
            }
            .check_ready()
            .await
            .unwrap();
            let wrong = sequoia_openpgp::cert::CertBuilder::new()
                .generate()
                .unwrap()
                .0;
            let mismatch = Arc::new(AppState {
                expected_ca: Some(wrong),
                ..AppState::new()
            });
            assert!(mismatch.check_ready().await.is_err());
            assert_eq!(
                issuance_status(mismatch.clone()).await,
                StatusCode::SERVICE_UNAVAILABLE
            );
            let response = router(mismatch)
                .oneshot(Request::get("/health").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            let hidden = socket.with_extension("unavailable");
            std::fs::rename(socket, &hidden).unwrap();
            let response = router(healthy.clone())
                .oneshot(Request::get("/health").body(Body::empty()).unwrap())
                .await
                .unwrap();
            std::fs::rename(&hidden, socket).unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            healthy.check_ready().await.unwrap();
        });
        Ok(())
    })
    .unwrap();
}

#[test]
fn unresponsive_keyfork_io_is_bounded() {
    if isolated("service_tests::unresponsive_keyfork_io_is_bounded") {
        return;
    }
    let path = std::path::PathBuf::from(format!("/tmp/cert-{}.sock", uuid::Uuid::new_v4()));
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    // Only this isolated test process uses the environment.
    unsafe {
        std::env::set_var("KEYFORKD_SOCKET_PATH", &path);
    }
    let (finish_tx, finish_rx) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let (_socket, _) = listener.accept().unwrap();
        finish_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    });
    let start = Instant::now();
    let result = service::derive_key(
        &derivation::default_openpgp_ca_path(),
        start + Duration::from_millis(100),
    );
    let elapsed = start.elapsed();
    finish_tx.send(()).unwrap();
    server.join().unwrap();
    std::fs::remove_file(path).unwrap();
    assert!(result.is_err());
    assert!(
        elapsed < Duration::from_secs(2),
        "Keyfork I/O took {elapsed:?}"
    );
}
