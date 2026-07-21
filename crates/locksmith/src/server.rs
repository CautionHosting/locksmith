use crate::{bundle::QuorumBundle, models};
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, consts::U12},
};
use blahaj::{Share, Sharks};
use bootproof::format::{Format, nitro::Nitro};
use dterror::*;
use hkdf::Hkdf;
use keymaker_models::generate_quorum::v1::Key;
use sha2::Sha256;
use std::fmt::Write;
use std::panic::Location;
use std::time::SystemTime;
use structstruck::strike;
use tracing::{debug, error};
use x25519_dalek::{EphemeralSecret, PublicKey};

#[derive(Debug, Clone)]
struct Payload {
    request: models::SendShardRequest,
    request_stub: RequestStub,
}

#[derive(Debug, Clone)]
struct ReconstitutionStatus {
    remaining: u8,
    request_stub: RequestStub,
}

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
            SyncShardReconstitutionStatus,
            BundleAccess,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    bundle: QuorumBundle,
    tx: tokio::sync::mpsc::Sender<Payload>,
    broadcast_tx: tokio::sync::broadcast::Sender<ReconstitutionStatus>,
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
            broadcast_tx.subscribe(),
            RequestStub::new(),
        ));
    }
}

// TODO: Make its own error type.
#[tracing::instrument(skip_all, fields(%request_stub))]
async fn handle_client(
    mut client: tokio::net::TcpStream,
    bundle: QuorumBundle,
    tx: tokio::sync::mpsc::Sender<Payload>,
    mut broadcast_rx: tokio::sync::broadcast::Receiver<ReconstitutionStatus>,
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
    let bundle = bundle.to_latest();
    let mut keyring = String::new();
    for key in &bundle.keyring {
        match key {
            Key::OpenPGP { cert } => {
                keyring.push_str(cert);
                keyring.push('\n');
            }
            Key::WebAuthn { .. } => {
                unimplemented!("WebAuthn shard transport is not implemented yet")
            }
        }
    }
    let signed_request = match crate::openpgp::verify_detached(
        &keyring,
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
            let mut error_messages = vec![];
            if let crate::openpgp::VerifyErrorKind::AllSignaturesInvalid { validation_errors } =
                &source.kind
            {
                for error in validation_errors {
                    let mut indentation = 0;
                    error_messages.push(format!("- {error}"));
                    let mut source = error.source();
                    while let Some(new_source) = source {
                        indentation += 1;
                        let mut prefix = "  ".repeat(indentation);
                        write!(prefix, "- {new_source}").expect("can concat error");
                        error_messages.push(prefix + new_source.to_string().as_str());
                        source = new_source.source();
                    }
                }
            };

            error_messages.insert(0, "No matching certificate found for signature:".into());

            crate::send(
                &mut client,
                models::SendSignedEncryptedShardResponse::Rejected {
                    reason: error_messages.join("\n"),
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

    tx.send(Payload {
        request: decoded_payload,
        request_stub,
    })
    .await
    .with_contexts((), ErrorKind::AddShard)?;

    // TODO: Provide a broadcast channel for the shard receiver to send back the status of how many
    // remain. It also means we can remove the AtomicU8, since the receiver can broadcast a
    // combination of { request: RequestStub, remaining: u8 }

    let remaining = loop {
        let status = broadcast_rx
            .recv()
            .await
            .with_contexts((), ErrorKind::SyncShardReconstitutionStatus)?;
        debug!(?status, "received status");
        if status.request_stub == request_stub {
            break status.remaining;
        }
    };

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
    broadcast_tx: tokio::sync::broadcast::Sender<ReconstitutionStatus>,
) -> Result<Vec<u8>, ReceiveShardsError> {
    use ReceiveShardsErrorKind as ErrorKind;

    let mut shards = vec![];
    let mut threshold = 1u8;
    while shards.len() < usize::from(threshold) {
        debug!("awaiting new shard");
        let shard;
        let request_stub;
        Payload {
            request: models::SendShardRequest { shard, threshold },
            request_stub,
        } = rx.recv().await.ok_or(ReceiveShardsError {
            kind: ErrorKind::NoMoreShards,
            location: Location::caller(),
            source: None,
        })?;
        shards.push(shard);
        broadcast_tx
            .send(ReconstitutionStatus {
                remaining: threshold.saturating_sub(
                    u8::try_from(shards.len()).expect("shards.len() is always < u8 threshold"),
                ),
                request_stub,
            })
            .with_contexts((), ErrorKind::SyncShardReconstitutionStatus)?;
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
    bundle: &QuorumBundle,
) -> Result<Vec<u8>, ReceiveShardsError> {
    // Payloads are: shard || threshold
    let (tx, rx) = tokio::sync::mpsc::channel::<Payload>(255);
    let (reconstitution_tx, reconstitution_rx) =
        tokio::sync::broadcast::channel::<ReconstitutionStatus>(255);

    let server_handle = tokio::spawn(server(
        address,
        bundle.clone(),
        tx,
        reconstitution_tx.clone(),
    ));
    let data = reconstitute_shards(rx, reconstitution_tx).await?;

    // once we have enough shards, we should no longer accept new clients.
    server_handle.abort();
    drop(reconstitution_rx);

    Ok(data)
}
