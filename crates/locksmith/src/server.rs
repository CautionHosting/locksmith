use crate::models;
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, consts::U12},
};
use blahaj::{Share, Sharks};
use bootproof::format::{Format, nitro::Nitro};
use dterror::*;
use hkdf::Hkdf;
use keymaker_models::generate_quorum::GenerateQuorumResponse;
use sha2::Sha256;
use std::panic::Location;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::SystemTime;
use structstruck::strike;
use tracing::{debug, error};
use x25519_dalek::{EphemeralSecret, PublicKey};

pub type Payload = (Vec<u8>, u8);

type ArcU8 = Arc<AtomicU8>;

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
            ReceiveRequest,
            SendResponse,
            GenerateAttestation,
            FailedSendRejection,
            InvalidSignature,
            DeserializeSignedPayload,
            HkdfExpansionInvalid,
            HexDecodePayload,
            DecryptPayload,
            JsonDecodePayload,
            AddShard,
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
    bytes: [u8; 4],
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
    bundle: GenerateQuorumResponse,
    tx: tokio::sync::mpsc::Sender<Payload>,
    reconstituted_amount: ArcU8,
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
        let (client, _addr) = match server.accept().await {
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

        tokio::spawn(handle_client(
            client,
            bundle.clone(),
            tx.clone(),
            reconstituted_amount.clone(),
            RequestStub::new(),
        ));
    }
}

// TODO: Make its own error type.
#[tracing::instrument(skip_all, fields(%request_stub))]
async fn handle_client(
    mut client: tokio::net::TcpStream,
    bundle: GenerateQuorumResponse,
    tx: tokio::sync::mpsc::Sender<Payload>,
    reconstituted_amount: ArcU8,
    request_stub: RequestStub,
) -> Result<(), ReceiveShardsError> {
    use ReceiveShardsErrorKind as ErrorKind;

    let secret = EphemeralSecret::random();
    let request: models::GeneratePublicKeyRequest = crate::receive(&mut client)
        .await
        .with_contexts((), ErrorKind::ReceiveRequest)?;

    debug!("generating attestation");
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

    let request: models::SendSignedEncryptedShardRequest = crate::send_and_receive(
        &mut client,
        models::GeneratePublicKeyResponse { attestation },
    )
    .await
    .with_contexts((), ErrorKind::ReceiveRequest)?;

    debug!("verifying signed request from user");
    let signed_request = match crate::openpgp::verify_detached(
        &bundle.keyring,
        &request.signed_payload,
        &request.signature,
    ) {
        Ok(()) => {
            debug!("accepting signature from user");
            let decoded: models::SendEncryptedShardRequest =
                serde_json::from_str(&request.signed_payload)
                    .with_contexts((), ErrorKind::DeserializeSignedPayload)?;
            decoded
        }
        Err(source) => {
            error!("denying signature from user");
            let mut error_messages = match &source.kind {
                crate::openpgp::VerifyErrorKind::AllSignaturesInvalid { validation_errors } => {
                    validation_errors.clone()
                }
                _ => vec![],
            };

            error_messages.insert(0, "No matching certificate found for signature".into());

            crate::send(
                &mut client,
                models::SendSignedEncryptedShardResponse::Rejected {
                    reason: error_messages.join("\n- "),
                },
            )
            .await
            .with_contexts((), ErrorKind::FailedSendRejection)?;
            return Err(ReceiveShardsError {
                kind: ReceiveShardsErrorKind::InvalidSignature,
                location: Location::caller(),
                source: Some(source.into()),
            });
        }
    };

    // TODO: If any of the following fails, the client will not be notified.
    // Ideally we should move this into its own function and do a similar matching pattern as to
    // what we do above.
    let shared_secret = secret.diffie_hellman(&PublicKey::from(signed_request.public_key));
    assert!(
        shared_secret.was_contributory(),
        "shared secret might be insecure"
    );
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());

    let mut shared_key_data = [0u8; 256 / 8];
    hkdf.expand(b"key", &mut shared_key_data)
        .with_contexts((), ErrorKind::HkdfExpansionInvalid)?;
    let shared_key =
        Aes256Gcm::new_from_slice(&shared_key_data).expect("known static length is valid");

    let mut nonce_data = [0u8; 12];
    hkdf.expand(b"nonce", &mut nonce_data)
        .with_contexts((), ErrorKind::HkdfExpansionInvalid)?;
    let nonce = Nonce::<U12>::from_slice(&nonce_data);

    let decoded_encrypted_payload = smex::decode_to_vec(&signed_request.encrypted_payload)
        .with_contexts((), ErrorKind::HexDecodePayload)?;

    let decrypted_payload = shared_key
        .decrypt(nonce, decoded_encrypted_payload.as_slice())
        .with_contexts((), ErrorKind::DecryptPayload)?;

    let decoded_payload: models::SendShardRequest = serde_json::from_slice(&decrypted_payload)
        .with_contexts((), ErrorKind::JsonDecodePayload)?;

    tx.send((decoded_payload.shard, decoded_payload.threshold))
        .await
        .with_contexts((), ErrorKind::AddShard)?;

    let remaining = decoded_payload.threshold - reconstituted_amount.load(Ordering::SeqCst);

    debug!(remaining, "sending response to user");
    crate::send(
        &mut client,
        models::SendSignedEncryptedShardResponse::Accepted { remaining },
    )
    .await
    .with_contexts((), ErrorKind::SendResponse)?;

    Ok(())
}

// TODO: Make its own error type.
#[tracing::instrument(skip_all)]
async fn reconstitute_shards(
    mut rx: tokio::sync::mpsc::Receiver<Payload>,
    reconstituted_amount: ArcU8,
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
        reconstituted_amount.fetch_add(1, Ordering::SeqCst);
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
pub async fn receive_shards(
    address: std::net::SocketAddr,
    bundle: &GenerateQuorumResponse,
) -> Result<Vec<u8>, ReceiveShardsError> {
    use ReceiveShardsErrorKind as ErrorKind;

    // Payloads are: shard || threshold
    let (tx, rx) = tokio::sync::mpsc::channel::<Payload>(255);

    let reconstituted_amount = ArcU8::new(0.into());

    let server_handle = tokio::spawn(server(
        address,
        bundle.clone(),
        tx,
        reconstituted_amount.clone(),
    ));
    let data = reconstitute_shards(rx, reconstituted_amount).await?;

    // once we have enough shards, we should no longer accept new clients.
    server_handle.abort();

    Ok(data)
}
