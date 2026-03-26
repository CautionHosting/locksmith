use blahaj::{Share, Sharks};
use bootproof::format::{Format, nitro::Nitro};
use dterror::*;
use std::{panic::Location, time::SystemTime};
use structstruck::strike;
use tokio::io::AsyncWriteExt;
use tracing::{debug, error};
use x25519_dalek::{EphemeralSecret, PublicKey};

pub type Payload = (Vec<u8>, u8);

strike! {
    #[structstruck::each[derive(Debug)]]
    #[derive(thiserror::Error)]
    #[error("Could not send shard ({kind:?}) [{location}]")]
    pub struct ReceiveShardsError {
        kind: pub enum ReceiveShardsErrorKind {
            BindSocket,
            Accept,
            NoMoreShards,
            InvalidShare,
            RecoverShards,
            ReceiveFirstPayload,
            DeserializeFirstPayload,
            GenerateAttestation,
            SendSecondPayload,
        },
        location: &'static Location<'static>,
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    }
}

impl FromContexts for ReceiveShardsError {
    type LongLivedContext = ();
    type ShortLivedContext = ReceiveShardsErrorKind;

    fn from_contexts(
        _long_lived_ctx: Self::LongLivedContext,
        short_lived_ctx: Self::ShortLivedContext,
        location: &'static std::panic::Location<'static>,
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    ) -> Self {
        Self {
            kind: short_lived_ctx,
            location,
            source: Some(source),
        }
    }
}

#[derive(Debug)]
struct RequestStub {
    bytes: [u8; 4]
}

impl std::fmt::Display for RequestStub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.bytes {
            write!(f, "{byte:X}")?;
        }
        Ok(())
    }
}

impl RequestStub {
    fn new() -> Self {
        let mut bytes = [0u8; 4];

        let time_bytes = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("time is linear")
            .as_nanos()
            .to_be_bytes();

        bytes.copy_from_slice(&time_bytes[12..]);

        Self { bytes }
    }
}

// TODO: Make its own error type.
#[tracing::instrument(skip_all)]
async fn server(
    address: std::net::SocketAddr,
    tx: tokio::sync::mpsc::Sender<Payload>,
) -> Result<(), ReceiveShardsError> {
    use ReceiveShardsErrorKind as ErrorKind;

    let server = tokio::net::TcpListener::bind(address)
        .await
        .with_contexts((), ErrorKind::BindSocket)?;
    debug!(?address, "bound server");

    // If we can't accept clients _twice_, let's kill the server.
    let mut previous_error: Option<std::io::Error> = None;
    loop {
        debug!("polling for client");
        let (client, addr) = match server.accept().await {
            Ok((client, addr)) => {
                previous_error = None;
                debug!(?addr, "accepting new client");
                (client, addr)
            }
            Err(e) => {
                error!(?e, "encountered error accepting client");
                if let Some(previous) = previous_error.take() {
                    error!(?previous, "received two errors in a row, shutting down");
                    return Result::<(), ReceiveShardsError>::Err(ReceiveShardsError {
                        kind: ErrorKind::Accept,
                        location: Location::caller(),
                        source: Some(Box::new(e)),
                    });
                }
                previous_error = Some(e);
                continue;
            }
        };

        tokio::spawn(handle_client(client, tx.clone(), RequestStub::new()));
    }
}

// TODO: Make its own error type.
#[tracing::instrument(skip_all, fields(%request_stub))]
async fn handle_client(
    mut client: tokio::net::TcpStream,
    tx: tokio::sync::mpsc::Sender<Payload>,
    request_stub: RequestStub,
) -> Result<(), ReceiveShardsError> {
    use ReceiveShardsErrorKind as ErrorKind;

    let secret = EphemeralSecret::random();
    let request_bytes = keyfork_frame::asyncext::try_decode_from(&mut client)
        .await
        .with_contexts((), ErrorKind::ReceiveFirstPayload)?;
    let request: crate::models::GeneratePublicKeyRequest =
        serde_json::from_slice(&request_bytes)
            .with_contexts((), ErrorKind::DeserializeFirstPayload)?;

    let attestation = Nitro
        .generate(
            Some(&PublicKey::from(&secret).as_bytes()[..]),
            request.nonce.as_bytes().into(),
        )
        .map_err(|source| ReceiveShardsError {
            kind: ReceiveShardsErrorKind::GenerateAttestation,
            location: Location::caller(),
            source: Some(source),
        })?;

    let response = crate::models::GeneratePublicKeyResponse { attestation };
    let response_string = serde_json::to_string(&response).expect("response is serializable");
    let framed_response = keyfork_frame::try_encode(response_string.as_bytes())
        .expect("response is < u32::MAX bytes");
    client
        .write_all(&framed_response)
        .await
        .with_contexts((), ErrorKind::SendSecondPayload)?;

    todo!()
}

// TODO: Make its own error type.
#[tracing::instrument(skip_all)]
async fn reconstitute_shards(
    mut rx: tokio::sync::mpsc::Receiver<Payload>,
) -> Result<Vec<u8>, ReceiveShardsError> {
    use ReceiveShardsErrorKind as ErrorKind;

    let mut shards = vec![];
    let mut threshold = 1u8;
    while shards.len() < usize::from(threshold) {
        debug!("awaiting new shard");
        let shard;
        (shard, threshold) = rx.recv().await.ok_or(ReceiveShardsError {
            kind: ErrorKind::NoMoreShards,
            location: Location::caller(),
            source: None,
        })?;
        shards.push(shard);
    }

    let shares = shards
        .into_iter()
        .map(|shard| Share::try_from(&*shard))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_source| ReceiveShardsError {
            kind: ErrorKind::InvalidShare,
            location: Location::caller(),
            source: None,
        })?;

    let sharks = Sharks(threshold);
    sharks
        .recover(&shares)
        .map_err(|_source| ReceiveShardsError {
            kind: ErrorKind::RecoverShards,
            location: Location::caller(),
            source: None,
        })
}

#[tracing::instrument(skip_all)]
pub async fn receive_shards(address: std::net::SocketAddr) -> Result<Vec<u8>, ReceiveShardsError> {
    use ReceiveShardsErrorKind as ErrorKind;

    // Payloads are: shard || threshold
    let (tx, rx) = tokio::sync::mpsc::channel::<Payload>(255);

    let server_handle = tokio::spawn(server(address, tx));
    let data = reconstitute_shards(rx).await?;

    // once we have enough shards, we should no longer accept new clients.
    server_handle.abort();

    Ok(data)
}
