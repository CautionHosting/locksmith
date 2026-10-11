use super::*;
use std::time::{Duration, Instant};

#[tokio::test]
async fn release_workers_stay_counted_after_timeout_or_disconnect() {
    for cancel in [false, true] {
        let state = Arc::new(AppState::new());
        let mut finishers = Vec::new();
        let mut tasks = Vec::new();
        for _ in 0..4 {
            let (start_tx, start_rx) = tokio::sync::oneshot::channel();
            let (finish_tx, finish_rx) = std::sync::mpsc::channel();
            let state = state.clone();
            tasks.push(tokio::spawn(async move {
                execute(
                    &state,
                    Instant::now()
                        + if cancel {
                            Duration::from_secs(30)
                        } else {
                            Duration::from_millis(100)
                        },
                    move || {
                        start_tx.send(()).unwrap();
                        finish_rx.recv().unwrap();
                        Ok(())
                    },
                )
                .await
            }));
            start_rx.await.unwrap();
            finishers.push(finish_tx);
        }
        assert_eq!(
            execute::<()>(&state, Instant::now() + Duration::from_secs(1), || panic!(
                "excess worker admitted"
            ))
            .await
            .unwrap_err()
            .0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        for task in tasks {
            if cancel {
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
            } else {
                assert_eq!(
                    task.await.unwrap().unwrap_err().0,
                    StatusCode::SERVICE_UNAVAILABLE
                );
            }
        }
        assert_eq!(state.release_workers.available_permits(), 0);
        assert_eq!(
            execute::<()>(&state, Instant::now() + Duration::from_secs(1), || panic!(
                "timed-out worker freed capacity"
            ))
            .await
            .unwrap_err()
            .0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        for finish in finishers {
            finish.send(()).unwrap();
        }
        let permits = tokio::time::timeout(
            Duration::from_secs(2),
            state.release_workers.acquire_many(4),
        )
        .await
        .unwrap()
        .unwrap();
        drop(permits);
        assert!(
            execute(&state, Instant::now() + Duration::from_secs(1), || Ok(()))
                .await
                .is_ok()
        );
    }
}
