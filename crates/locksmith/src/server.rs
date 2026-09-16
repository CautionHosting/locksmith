use crate::{bundle::QuorumBundle, models};
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, consts::U12},
};
use blahaj::{Share, Sharks};
use bootproof::format::{Format, nitro::Nitro};
use dterror::*;
use hkdf::Hkdf;
use sequoia_openpgp::{Cert, Fingerprint, parse::Parse};
use sha2::Sha256;
use std::collections::HashSet;
use std::panic::Location;
use std::sync::Arc;
use std::time::SystemTime;
use structstruck::strike;
use tracing::{debug, error};
use x25519_dalek::{EphemeralSecret, PublicKey};

#[derive(Debug, Clone)]
struct Payload {
    request: models::SendShardRequest,
    holder: usize,
    request_stub: RequestStub,
}

#[derive(Debug, Clone)]
struct ReconstitutionStatus {
    response: models::SendSignedEncryptedShardResponse,
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
            InvalidQuorum,
            RecoveredKeyMismatch,
            DeriveRecoveredKey,
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
    keyrings: Arc<Vec<String>>,
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
            keyrings.clone(),
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
    keyrings: Arc<Vec<String>>,
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
    let holder = match authenticate_holder(&keyrings, &request.signed_payload, &request.signature) {
        Ok(holder) => holder,
        Err(error) => {
            crate::send(
                &mut client,
                models::SendSignedEncryptedShardResponse::Rejected {
                    reason: "Signature must identify exactly one bundle holder".into(),
                },
            )
            .await
            .with_contexts((), ErrorKind::FailedSendRejection)?;
            return Err(error);
        }
    };
    let signed_request: models::SendEncryptedShardRequest =
        serde_json::from_str(&request.signed_payload)
            .with_contexts((), ErrorKind::DeserializeSignedPayload)?;

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

    let decoded_payload: models::SendShardRequest = match serde_json::from_slice(&decrypted_payload)
    {
        Ok(request) => request,
        Err(source) => {
            crate::send(
                &mut client,
                models::SendSignedEncryptedShardResponse::Rejected {
                    reason: "Malformed share request".into(),
                },
            )
            .await
            .with_contexts((), ErrorKind::FailedSendRejection)?;
            return Err(ReceiveShardsError {
                kind: ErrorKind::JsonDecodePayload,
                source: Some(Box::new(source)),
                location: Location::caller(),
            });
        }
    };

    tx.send(Payload {
        request: decoded_payload,
        holder,
        request_stub,
    })
    .await
    .with_contexts((), ErrorKind::AddShard)?;

    let response = loop {
        let status = broadcast_rx
            .recv()
            .await
            .with_contexts((), ErrorKind::SyncShardReconstitutionStatus)?;
        if status.request_stub == request_stub {
            break status.response;
        }
    };
    crate::send(&mut client, response)
        .await
        .with_contexts((), ErrorKind::SendResponse)?;
    Ok(())
}

// Authenticate against each proof-bound holder entry, never against a claimed issuer ID.
fn authenticate_holder(
    keyrings: &[String],
    data: &str,
    signature: &str,
) -> Result<usize, ReceiveShardsError> {
    let mut matches = keyrings.iter().enumerate().filter_map(|(index, keyring)| {
        crate::openpgp::verify_detached(keyring, data, signature)
            .is_ok()
            .then_some(index)
    });
    match (matches.next(), matches.next()) {
        (Some(holder), None) => Ok(holder),
        _ => Err(recovery_error(ReceiveShardsErrorKind::InvalidSignature)),
    }
}

#[track_caller]
fn recovery_error(kind: ReceiveShardsErrorKind) -> ReceiveShardsError {
    ReceiveShardsError {
        kind,
        source: None,
        location: Location::caller(),
    }
}

struct Recovery {
    threshold: u8,
    keyrings: Arc<Vec<String>>,
    public_key: Fingerprint,
}

impl Recovery {
    fn new(bundle: &QuorumBundle) -> Result<Self, ReceiveShardsError> {
        let bundle = bundle.clone().to_latest();
        if bundle.threshold == 0
            || bundle.threshold > bundle.max
            || bundle.max > 254
            || usize::from(bundle.max) != bundle.keyring.len()
        {
            return Err(recovery_error(ReceiveShardsErrorKind::InvalidQuorum));
        }
        let keyrings = bundle
            .keyring
            .iter()
            .map(|key| {
                crate::openpgp::reconstruct_keyring(std::slice::from_ref(key))
                    .with_contexts((), ReceiveShardsErrorKind::BundleAccess)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let public_key = Cert::from_bytes(&bundle.public_key)
            .map_err(|source| ReceiveShardsError {
                kind: ReceiveShardsErrorKind::BundleAccess,
                source: Some(source.into()),
                location: Location::caller(),
            })?
            .fingerprint();
        Ok(Self {
            threshold: bundle.threshold,
            keyrings: Arc::new(keyrings),
            public_key,
        })
    }
}

// Same deterministic primary key derivation as Keymaker; certificate signatures and
// expiration timestamps are deliberately excluded from the comparison.
fn recovered_fingerprint(secret: &[u8]) -> Result<Fingerprint, ReceiveShardsError> {
    use keyfork_derive_openpgp::{XPrv, derive_util::DerivationIndex};
    use sequoia_openpgp::{packet::UserID, types::KeyFlags};
    let entropy: [u8; 32] = secret
        .try_into()
        .map_err(|_| recovery_error(ReceiveShardsErrorKind::RecoverShards))?;
    let seed = keyfork_mnemonic::Mnemonic::from_array(entropy).generate_seed(None);
    let path = keyfork_derive_path_data::paths::OPENPGP
        .clone()
        .chain_push(DerivationIndex::new(0, true).expect("account 0 is valid"));
    let key = XPrv::new(seed)
        .expect("fixed length seed is valid")
        .derive_path(&path)
        .with_contexts((), ReceiveShardsErrorKind::DeriveRecoveredKey)?;
    let cert = keyfork_derive_openpgp::derive(
        &key,
        &[KeyFlags::empty().set_certification()],
        &UserID::from("Keymaker-generated key"),
    )
    .map_err(|source| ReceiveShardsError {
        kind: ReceiveShardsErrorKind::DeriveRecoveredKey,
        source: Some(source.into()),
        location: Location::caller(),
    })?;
    Ok(cert.fingerprint())
}

// TODO: Make its own error type.
#[tracing::instrument(skip_all)]
async fn reconstitute_shards(
    mut rx: tokio::sync::mpsc::Receiver<Payload>,
    broadcast_tx: tokio::sync::broadcast::Sender<ReconstitutionStatus>,
    recovery: &Recovery,
) -> Result<Vec<u8>, ReceiveShardsError> {
    use models::SendSignedEncryptedShardResponse::{Accepted, Rejected};
    let mut shares = vec![];
    let mut holders = HashSet::new();
    let mut coordinates = HashSet::new();
    loop {
        let Payload {
            request,
            holder,
            request_stub,
        } = rx
            .recv()
            .await
            .ok_or_else(|| recovery_error(ReceiveShardsErrorKind::NoMoreShards))?;
        let reason = if request.threshold != recovery.threshold {
            Some("Threshold does not match the verified bundle")
        } else if holder >= recovery.keyrings.len() {
            Some("Unknown holder")
        } else if request.shard.len() != 33 || request.shard[0] == 0 {
            Some("Malformed share: expected a nonzero coordinate and 32 bytes")
        } else if holders.contains(&holder) {
            Some("Holder already contributed a share")
        } else if coordinates.contains(&request.shard[0]) {
            Some("Share coordinate already contributed")
        } else {
            None
        };
        if let Some(reason) = reason {
            broadcast_tx
                .send(ReconstitutionStatus {
                    request_stub,
                    response: Rejected {
                        reason: reason.into(),
                    },
                })
                .with_contexts((), ReceiveShardsErrorKind::SyncShardReconstitutionStatus)?;
            continue;
        }
        let share = Share::try_from(request.shard.as_slice())
            .map_err(|_| recovery_error(ReceiveShardsErrorKind::InvalidShare))?;
        holders.insert(holder);
        coordinates.insert(request.shard[0]);
        shares.push(share);
        let remaining =
            recovery.threshold - u8::try_from(shares.len()).expect("bounded by threshold");
        let result = if remaining == 0 {
            Some(
                Sharks(recovery.threshold)
                    .recover(&shares)
                    .map_err(|_| recovery_error(ReceiveShardsErrorKind::RecoverShards))
                    .and_then(|secret| {
                        if recovered_fingerprint(&secret)? != recovery.public_key {
                            return Err(recovery_error(
                                ReceiveShardsErrorKind::RecoveredKeyMismatch,
                            ));
                        }
                        Ok(secret)
                    }),
            )
        } else {
            None
        };
        let response = match &result {
            Some(Err(_)) => Rejected {
                reason: "Recovered secret does not match the bundle public key".into(),
            },
            _ => Accepted { remaining },
        };
        broadcast_tx
            .send(ReconstitutionStatus {
                request_stub,
                response,
            })
            .with_contexts((), ReceiveShardsErrorKind::SyncShardReconstitutionStatus)?;
        if let Some(result) = result {
            return result;
        }
    }
}

#[tracing::instrument(skip_all)]
pub async fn receive_shards(
    address: std::net::SocketAddr,
    bundle: &QuorumBundle,
) -> Result<Vec<u8>, ReceiveShardsError> {
    // The caller supplies a bundle loaded through proof verification.
    let recovery = Recovery::new(bundle)?;
    let (tx, rx) = tokio::sync::mpsc::channel::<Payload>(255);
    let (reconstitution_tx, _reconstitution_rx) =
        tokio::sync::broadcast::channel::<ReconstitutionStatus>(255);
    let server_handle = tokio::spawn(server(
        address,
        recovery.keyrings.clone(),
        tx,
        reconstitution_tx.clone(),
    ));
    let data = reconstitute_shards(rx, reconstitution_tx, &recovery).await;
    // Stop accepting clients on both success and failure.
    server_handle.abort();
    let _ = server_handle.await;
    data
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;
