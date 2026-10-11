use super::*;
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

struct Listener {
    address: SocketAddr,
    task: tokio::task::JoinHandle<Result<(), ReceiveShardsError>>,
    // Dropping this ends the session, as when reconstitution returns.
    shards: Option<tokio::sync::mpsc::Receiver<Payload>>,
}
impl Drop for Listener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn start() -> (Listener, TcpStream) {
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let (tx, shards) = tokio::sync::mpsc::channel(255);
    let (status, _) = tokio::sync::broadcast::channel(255);
    let listener = Listener {
        address,
        task: tokio::spawn(server(address, Arc::new(vec![]), tx, status)),
        shards: Some(shards),
    };
    let first = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match TcpStream::connect(address).await {
                Ok(stream) => break stream,
                Err(_) => tokio::time::sleep(Duration::from_millis(1)).await,
            }
        }
    })
    .await
    .unwrap();
    (listener, first)
}

async fn assert_closed(stream: &mut TcpStream) {
    let result = tokio::time::timeout(Duration::from_secs(2), stream.read_u8())
        .await
        .expect("connection must close");
    assert!(matches!(result, Err(ref e) if matches!(e.kind(),
        std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset)));
}

async fn assert_open(stream: &mut TcpStream) {
    assert!(
        tokio::time::timeout(Duration::from_millis(25), stream.read_u8())
            .await
            .is_err(),
        "an admitted idle connection should remain open"
    );
}

#[tokio::test]
async fn connection_capacity_rejects_excess_and_reuses_released_slot() {
    let (listener, first) = start().await;
    let mut clients = vec![first];
    for _ in 1..MAX_RECOVERY_CONNECTIONS {
        clients.push(TcpStream::connect(listener.address).await.unwrap());
    }
    let mut excess = TcpStream::connect(listener.address).await.unwrap();
    assert_closed(&mut excess).await;
    assert_open(clients.last_mut().unwrap()).await;

    // A malformed header terminates one admitted handler and releases its permit.
    clients[0].write_u32(u32::MAX).await.unwrap();
    assert_closed(&mut clients[0]).await;
    let mut replacement = TcpStream::connect(listener.address).await.unwrap();
    assert_open(&mut replacement).await;
    let mut excess = TcpStream::connect(listener.address).await.unwrap();
    assert_closed(&mut excess).await;
    assert!(!listener.task.is_finished());
}

#[tokio::test]
async fn ended_session_releases_unsubmitted_clients() {
    let (mut listener, first) = start().await;
    let mut clients = vec![first];
    for _ in 1..MAX_RECOVERY_CONNECTIONS {
        clients.push(TcpStream::connect(listener.address).await.unwrap());
    }
    assert_open(clients.last_mut().unwrap()).await;
    // A restarted recovery must not inherit the previous session's connections.
    listener.task.abort();
    listener.shards = None;
    for client in &mut clients {
        assert_closed(client).await;
    }
}

#[tokio::test]
async fn stalled_header_and_body_expire_without_stopping_listener() {
    let (listener, mut header) = start().await;
    let mut body = TcpStream::connect(listener.address).await.unwrap();
    header.write_all(&[0]).await.unwrap();
    body.write_u32(crate::MAX_FRAME_BODY).await.unwrap();
    body.write_all(&[0; 32]).await.unwrap();
    assert_open(&mut header).await;
    assert_open(&mut body).await;
    let mut clients = vec![header, body];
    for _ in clients.len()..MAX_RECOVERY_CONNECTIONS {
        clients.push(TcpStream::connect(listener.address).await.unwrap());
    }
    let mut excess = TcpStream::connect(listener.address).await.unwrap();
    assert_closed(&mut excess).await;

    tokio::time::pause();
    tokio::time::advance(FIRST_FRAME_TIMEOUT - Duration::from_secs(1)).await;
    assert!(
        matches!(clients[0].try_read(&mut [0]), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
    );
    tokio::time::advance(Duration::from_secs(2)).await;
    tokio::time::resume();
    for client in &mut clients {
        assert_closed(client).await;
    }
    assert!(
        !listener.task.is_finished(),
        "quorum collection has no connection deadline"
    );
    let mut replacements = Vec::new();
    for _ in 0..MAX_RECOVERY_CONNECTIONS {
        replacements.push(TcpStream::connect(listener.address).await.unwrap());
    }
    assert_open(replacements.last_mut().unwrap()).await;
    let mut excess = TcpStream::connect(listener.address).await.unwrap();
    assert_closed(&mut excess).await;
}

#[cfg(feature = "unsafe-e2e")]
#[tokio::test]
async fn post_attestation_stall_expires_at_connection_deadline() {
    if std::env::var("CAUTION_UNSAFE_KEY_SERVICE_E2E").as_deref() != Ok("1") {
        return;
    }
    let (listener, mut client) = start().await;
    crate::send(
        &mut client,
        models::GeneratePublicKeyRequest {
            nonce: "ab".repeat(16),
        },
    )
    .await
    .unwrap();
    let _: models::GeneratePublicKeyResponse = crate::receive(&mut client).await.unwrap();

    // Past the first frame, a holder may still be signing: only the connection deadline applies.
    tokio::time::pause();
    tokio::time::advance(FIRST_FRAME_TIMEOUT + Duration::from_secs(1)).await;
    assert!(
        matches!(client.try_read(&mut [0]), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
    );
    tokio::time::advance(RECOVERY_CONNECTION_TIMEOUT).await;
    tokio::time::resume();
    assert_closed(&mut client).await;
    assert!(!listener.task.is_finished());
}
