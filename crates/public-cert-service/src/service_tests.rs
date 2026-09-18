use super::*;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use std::time::{Duration, Instant};
use tower::ServiceExt;

fn test_state() -> AppState {
    let mut state = AppState::new();
    state.set_issuance_token(Some("ab".repeat(32)));
    state
}

async fn issuance_status(state: Arc<AppState>) -> StatusCode {
    router(state)
        .oneshot(
            Request::post("/v1/public-certificates")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", "ab".repeat(32)))
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
        let state = Arc::new(test_state());
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
            ..test_state()
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
                ..test_state()
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
                ..test_state()
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
            healthy.readiness.expire();
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

#[tokio::test]
async fn issuance_auth_precedes_body_processing_and_does_not_gate_release() {
    for configured in [false, true] {
        let state = if configured {
            test_state()
        } else {
            AppState::new()
        };
        let app = router(Arc::new(state));
        for supplied in [None, Some("Bearer incorrect"), Some("Bearer ")] {
            let mut request =
                Request::post("/v1/public-certificates").header("content-type", "application/json");
            if let Some(value) = supplied {
                request = request.header("authorization", value);
            }
            let result = app
                .clone()
                .oneshot(request.body(Body::from("not json")).unwrap())
                .await
                .unwrap();
            assert_eq!(
                result.status(),
                if configured {
                    StatusCode::UNAUTHORIZED
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                }
            );
        }
        let result = app
            .clone()
            .oneshot(
                Request::post("/v1/public-certificates")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {}", "ab".repeat(32)))
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            result.status(),
            if configured {
                StatusCode::UNPROCESSABLE_ENTITY
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            }
        );
        let result = app
            .oneshot(
                Request::post("/v1/releases/begin")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
}

#[tokio::test]
async fn readiness_coalesces_and_retains_refresh_after_timeout_or_disconnect() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    for cancel in [false, true] {
        let cache = Arc::new(admission::Readiness::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let (start_tx, start_rx) = tokio::sync::oneshot::channel();
        let (finish_tx, finish_rx) = std::sync::mpsc::channel();
        let count = calls.clone();
        let worker_cache = cache.clone();
        let first = tokio::spawn(async move {
            worker_cache
                .check(Instant::now() + Duration::from_millis(50), move || {
                    count.fetch_add(1, Ordering::SeqCst);
                    start_tx.send(()).unwrap();
                    finish_rx.recv().unwrap();
                    false
                })
                .await
        });
        start_rx.await.unwrap();
        if cancel {
            first.abort();
            let _ = first.await;
        } else {
            assert!(!first.await.unwrap());
        }
        let mut waiters = Vec::new();
        for _ in 0..10 {
            let cache = cache.clone();
            let count = calls.clone();
            waiters.push(tokio::spawn(async move {
                cache
                    .check(Instant::now() + Duration::from_secs(2), move || {
                        count.fetch_add(1, Ordering::SeqCst);
                        true
                    })
                    .await
            }));
        }
        tokio::task::yield_now().await;
        finish_tx.send(()).unwrap();
        for waiter in waiters {
            assert!(!waiter.await.unwrap());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(
            !cache
                .check(Instant::now() + Duration::from_secs(1), || panic!(
                    "cached failure refreshed"
                ))
                .await
        );
        tokio::time::sleep(Duration::from_millis(2050)).await;
        assert!(
            cache
                .check(Instant::now() + Duration::from_secs(1), || true)
                .await
        );
        assert!(
            cache
                .check(Instant::now() + Duration::from_secs(1), || panic!(
                    "cached success refreshed"
                ))
                .await
        );
    }
}
