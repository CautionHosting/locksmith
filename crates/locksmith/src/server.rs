#[cfg(test)]
use crate::bundle::QuorumBundle;
use crate::{bundle::RecoverySource, models};
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, consts::U12},
};
use blahaj::{Share, Sharks};
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

const MAX_RECOVERY_CONNECTIONS: usize = 32;
const RECOVERY_CONNECTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);
// Every client sends its nonce as soon as it connects; an idle peer must not keep a slot.
const FIRST_FRAME_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

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
            FirstFrameTimeout,
            SendResponse,
            GenerateAttestation,
            FailedSendRejection,
            InvalidSignature,
            SignatureClockSkew,
            AmbiguousSignature,
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
    keyrings: Arc<Vec<HolderKeyring>>,
    tx: tokio::sync::mpsc::Sender<Payload>,
    broadcast_tx: tokio::sync::broadcast::Sender<ReconstitutionStatus>,
) -> Result<(), ReceiveShardsError> {
    use ReceiveShardsErrorKind as ErrorKind;

    let server = tokio::net::TcpListener::bind(address)
        .await
        .with_contexts((), ErrorKind::BindSocket)?;
    debug!(?address, "bound server");
    let connections = Arc::new(tokio::sync::Semaphore::new(MAX_RECOVERY_CONNECTIONS));

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

        let Ok(permit) = connections.clone().try_acquire_owned() else {
            continue; // Drop excess clients immediately; never queue waiting tasks.
        };
        let handler = handle_client(
            client,
            keyrings.clone(),
            tx.clone(),
            broadcast_tx.subscribe(),
            RequestStub::new(),
        );
        tokio::spawn(async move {
            let _permit = permit;
            if tokio::time::timeout(RECOVERY_CONNECTION_TIMEOUT, handler).await.is_err() {
                tracing::debug!("recovery connection timed out");
            }
        });
    }
}

// TODO: Make its own error type.
#[tracing::instrument(skip_all, fields(%request_stub))]
async fn handle_client(
    mut client: tokio::net::TcpStream,
    keyrings: Arc<Vec<HolderKeyring>>,
    tx: tokio::sync::mpsc::Sender<Payload>,
    mut broadcast_rx: tokio::sync::broadcast::Receiver<ReconstitutionStatus>,
    request_stub: RequestStub,
) -> Result<(), ReceiveShardsError> {
    use ReceiveShardsErrorKind as ErrorKind;

    // Reconstitution ending (recovered, or restarting after a mismatch) closes the shard channel.
    // An unsubmitted client can no longer count, so release its connection now; submitted
    // clients still receive their final status.
    let (request, holder) = tokio::select! {
        submission = receive_submission(&mut client, &keyrings) => submission?,
        () = tx.closed() => {
            debug!("reconstitution ended before the client submitted");
            return Ok(());
        }
    };

    tx.send(Payload {
        request,
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

async fn receive_submission(
    client: &mut tokio::net::TcpStream,
    keyrings: &[HolderKeyring],
) -> Result<(models::SendShardRequest, usize), ReceiveShardsError> {
    use ReceiveShardsErrorKind as ErrorKind;

    let secret = EphemeralSecret::random();
    let request: models::GeneratePublicKeyRequest =
        tokio::time::timeout(FIRST_FRAME_TIMEOUT, crate::receive(client))
            .await
            .with_contexts((), ErrorKind::FirstFrameTimeout)?
            .with_contexts((), ErrorKind::ReceiveRequest)?;

    debug!("generating attestation");
    let attestation = crate::release::generate_live(
            &PublicKey::from(&secret).as_bytes()[..],
            &request.nonce,
        )
        .map_err(|source| ReceiveShardsError {
            kind: ReceiveShardsErrorKind::GenerateAttestation,
            location: Location::caller(),
            source: Some(Box::new(source)),
        })?;

    let request: models::SendSignedEncryptedShardRequest = crate::send_and_receive(
        client,
        models::GeneratePublicKeyResponse { attestation },
    )
    .await
    .with_contexts((), ErrorKind::ReceiveRequest)?;

    debug!("verifying signed request from user");
    let holder = match authenticate_holder(keyrings, &request.signed_payload, &request.signature) {
        Ok(holder) => holder,
        Err(error) => {
            crate::send(
                client,
                models::SendSignedEncryptedShardResponse::Rejected {
                    reason: error.signature_rejection_reason().into(),
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
                client,
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
    Ok((decoded_payload, holder))
}

// Authenticate against each proof-bound holder entry, never against a claimed issuer ID.
fn authenticate_holder(
    keyrings: &[HolderKeyring],
    data: &str,
    signature: &str,
) -> Result<usize, ReceiveShardsError> {
    let mut holder = None;
    let mut rejection = recovery_error(ReceiveShardsErrorKind::InvalidSignature);
    for (index, keyring) in keyrings.iter().enumerate() {
        match keyring.verify(data, signature) {
            Ok(()) if holder.is_some() => {
                tracing::warn!("signature matches multiple bundle holders");
                return Err(recovery_error(ReceiveShardsErrorKind::AmbiguousSignature));
            }
            Ok(()) => holder = Some(index),
            Err(error) => {
                if matches!(error.kind, ReceiveShardsErrorKind::SignatureClockSkew)
                    || rejection.source.is_none()
                {
                    rejection = error;
                }
            }
        }
    }
    if let Some(holder) = holder {
        return Ok(holder);
    }
    // Parser errors can contain entire attacker-controlled armor buffers. Emit
    // one fixed-category diagnostic per rejection, independent of holder count.
    tracing::warn!(
        holders_checked = keyrings.len(),
        cause = rejection.signature_log_cause(),
        "holder signature verification failed"
    );
    Err(rejection)
}

impl ReceiveShardsError {
    /// The share set failed as a whole and cannot be attributed to one holder, so recovery
    /// can only start over with fresh submissions.
    pub fn restarts_recovery(&self) -> bool {
        matches!(
            self.kind,
            ReceiveShardsErrorKind::RecoverShards | ReceiveShardsErrorKind::RecoveredKeyMismatch
        )
    }

    fn signature_log_cause(&self) -> &'static str {
        use crate::openpgp::VerifyErrorKind;
        let verification = self
            .source
            .as_ref()
            .and_then(|source| source.downcast_ref::<crate::openpgp::VerifyError>());
        match verification.map(|error| &error.kind) {
            Some(VerifyErrorKind::SignatureFromFuture) => "signature clock skew",
            Some(VerifyErrorKind::LoadCertificates) => "invalid holder certificate",
            Some(VerifyErrorKind::LoadSignatures) => "invalid signature armor",
            Some(VerifyErrorKind::InvalidSignatureCount) => "invalid signature count",
            Some(VerifyErrorKind::AllSignaturesInvalid { .. }) => "invalid holder signature",
            None => "holder certificate or signature verification failed",
        }
    }

    fn signature_rejection_reason(&self) -> &'static str {
        match self.kind {
            ReceiveShardsErrorKind::SignatureClockSkew => {
                "Signature is more than 60 seconds ahead of the enclave clock; check signer and enclave clocks"
            }
            ReceiveShardsErrorKind::AmbiguousSignature => {
                "Signature matches multiple bundle holders"
            }
            _ => "Signature did not verify for any bundle holder",
        }
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

#[derive(Clone)]
struct HolderKeyring {
    certificate: String,
    generation_time: Option<SystemTime>,
}
impl HolderKeyring {
    fn verify(&self, data: &str, signature: &str) -> Result<(), ReceiveShardsError> {
        if let Some(at) = self.generation_time {
            crate::custody::verify_holder_signature(&self.certificate, data, signature, at)
                .with_contexts((), ReceiveShardsErrorKind::InvalidSignature)
        } else {
            crate::openpgp::verify_detached(&self.certificate, data, signature).map_err(|source| {
                let kind = match source.kind {
                    crate::openpgp::VerifyErrorKind::SignatureFromFuture => {
                        ReceiveShardsErrorKind::SignatureClockSkew
                    }
                    _ => ReceiveShardsErrorKind::InvalidSignature,
                };
                ReceiveShardsError::from_contexts((), kind, Location::caller(), Box::new(source))
            })
        }
    }
}

struct Recovery {
    threshold: u8,
    keyrings: Arc<Vec<HolderKeyring>>,
    public_key: Fingerprint,
    bundle_hash: Option<String>,
}

impl Recovery {
    #[cfg(test)]
    fn new(bundle: &impl RecoverySource) -> Result<Self, ReceiveShardsError> {
        Self::new_at(bundle, None)
    }
    fn new_at(bundle: &impl RecoverySource, at: Option<SystemTime>) -> Result<Self, ReceiveShardsError> {
        let bundle_hash = bundle
            .bundle_hash()
            .with_contexts((), ReceiveShardsErrorKind::BundleAccess)?;
        let bundle = bundle.recovery();
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
                let certificate = crate::openpgp::reconstruct_keyring(std::slice::from_ref(key))
                    .with_contexts((), ReceiveShardsErrorKind::BundleAccess)?;
                let generation_time = if matches!(key, keymaker_models::generate_quorum::v1::Key::WebAuthn { .. }) {
                    Some(crate::custody::generation_time(at).with_contexts((), ReceiveShardsErrorKind::BundleAccess)?)
                } else { None };
                Ok(HolderKeyring { certificate, generation_time })
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
            bundle_hash,
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
    loop {
        let Payload {
            request,
            holder,
            request_stub,
        } = rx
            .recv()
            .await
            .ok_or_else(|| recovery_error(ReceiveShardsErrorKind::NoMoreShards))?;
        let reason = if recovery.bundle_hash.is_some()
            && request.bundle_hash.is_some()
            && request.bundle_hash != recovery.bundle_hash
        {
            Some("Share was dealt from a different bundle")
        } else if request.threshold != recovery.threshold {
            Some("Threshold does not match the verified bundle")
        } else if holder >= recovery.keyrings.len() {
            Some("Unknown holder")
        } else if request.shard.len() != 33 || request.shard[0] == 0 {
            Some("Malformed share: expected a nonzero coordinate and 32 bytes")
        } else if usize::from(request.shard[0]) != holder + 1 {
            // Keymaker deals coordinates 1..=max in keyring order.
            Some("Share coordinate does not match the holder's bundle position")
        } else if holders.contains(&holder) {
            Some("Holder already contributed a share")
        } else {
            None
        };
        if reason.is_none() && recovery.bundle_hash.is_some() && request.bundle_hash.is_none() {
            tracing::warn!(holder, "accepting share without a bundle hash from an older client");
        }
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
    bundle: &impl RecoverySource,
) -> Result<Vec<u8>, ReceiveShardsError> {
    receive_shards_at(address, bundle, None).await
}

/// The generation timestamp must come from the verified Keymaker proof.
/// WebAuthn snapshots require this timestamp; the legacy entry point remains PGP-only.
pub async fn receive_shards_at(
    address: std::net::SocketAddr,
    bundle: &impl RecoverySource,
    generation_time: Option<SystemTime>,
) -> Result<Vec<u8>, ReceiveShardsError> {
    let recovery = Recovery::new_at(bundle, generation_time)?;
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

#[cfg(test)]
#[path = "connection_tests.rs"]
mod connection_tests;
