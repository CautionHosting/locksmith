use crate::{bundle::QuorumBundle, models};
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, consts::U12},
};
use bootproof_sdk::format::{VerifiableSignedAttestationFormat, nitro::Nitro};
use dterror::*;
use hkdf::Hkdf;
use keyfork_shard::{Format, openpgp::OpenPGP};
use keymaker_models::generate_quorum::v1;
use rand::Rng;
use sequoia_openpgp::{
    cert::CertParser,
    parse::Parse,
    policy::{NullPolicy, StandardPolicy},
};
use serde_cbor::Value as CborValue;
use sha2::Sha256;
use std::panic::Location;
use std::time::SystemTime;
use structstruck::strike;
use x25519_dalek::{EphemeralSecret, PublicKey};

// NOTE: We need to inline the keyfork-shard reconstitution system here. We don't have a way to
// detect malicious users, so we need to be able to send _any_ public key and accept arbitrary,
// verifiable payloads. There's also no way to accept multiple payloads at once with the existing
// Keyfork receiver.

strike! {
    #[structstruck::each[derive(Debug)]]
    #[derive(thiserror::Error)]
    #[error("Could not send shard ({kind:?}) [{location}]")]
    pub struct SendShardError {
        kind: pub enum SendShardErrorKind {
            ConnectToRemote,
            ParseShardfile,
            ParsePrivateKeys,
            DecryptShard,
            SendRequest,
            InvalidPCRs,
            VerifyAttestation,
            InvalidUserData,
            InvalidByteLen(usize),
            HkdfExpansionInvalid,
            RecryptShard,
            HexEncodeRecryptedShard,
            SignHexEncodedRecryptedShard,
            BundleAccess,
            InvalidQuorum,
            NoMatchingHolderKeys,
            ShareHolderMismatch,
            ShareThresholdMismatch,
        },
        location: &'static Location<'static>,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    }
}

impl FromContexts for SendShardError {
    type LongLivedContext = ();
    type ShortLivedContext = SendShardErrorKind;

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

impl SendShardError {
    #[track_caller]
    fn invalid(kind: SendShardErrorKind) -> Self {
        Self {
            kind,
            location: Location::caller(),
            source: None,
        }
    }
}

pub(crate) fn decrypt_shard(
    bundle: &v1::GenerateQuorumResponse,
    private_key_path: Option<&std::path::Path>,
    prompt: std::rc::Rc<std::sync::Mutex<Box<dyn keyfork_prompt::PromptHandler>>>,
) -> Result<(models::SendShardRequest, String), SendShardError> {
    decrypt_selected_shard(bundle, private_key_path, prompt, None)
}

fn decrypt_selected_shard(
    bundle: &v1::GenerateQuorumResponse,
    private_key_path: Option<&std::path::Path>,
    prompt: std::rc::Rc<std::sync::Mutex<Box<dyn keyfork_prompt::PromptHandler>>>,
    holder: Option<&str>,
) -> Result<(models::SendShardRequest, String), SendShardError> {
    use SendShardErrorKind as Kind;
    if bundle.threshold == 0
        || bundle.threshold > bundle.max
        || bundle.max > 254
        || usize::from(bundle.max) != bundle.keyring.len()
    {
        return Err(SendShardError::invalid(Kind::InvalidQuorum));
    }
    #[cfg(feature = "rpgpie")]
    if let (None, Some(holder)) = (private_key_path, holder) {
        let (shard, threshold, index) = crate::openpgp::selected_card::decrypt(bundle, holder, prompt)
            .with_contexts((), Kind::DecryptShard)?;
        let request = models::SendShardRequest { shard, threshold };
        let keyring = signing_keyring(bundle, &request, Some(index))?;
        return Ok((request, keyring));
    }
    let keyring = crate::openpgp::reconstruct_keyring(&bundle.keyring)
        .with_contexts((), Kind::BundleAccess)?;
    let private_keys = private_key_path
        .map(OpenPGP::discover_certs)
        .transpose()
        .with_contexts((), Kind::ParsePrivateKeys)?;
    let (selected, private_keys) = if let Some(private_keys) = private_keys {
        let certificates = CertParser::from_bytes(&keyring)
            .and_then(|parser| parser.collect::<sequoia_openpgp::Result<Vec<_>>>())
            .map_err(|source| {
                SendShardError::from_contexts(
                    (),
                    Kind::BundleAccess,
                    Location::caller(),
                    source.into(),
                )
            })?;
        if certificates.len() != bundle.keyring.len() {
            return Err(SendShardError::invalid(Kind::InvalidQuorum));
        }
        let mut policy = StandardPolicy::new();
        policy.good_critical_notations(&["organization-id@caution.co", "bundle-id@caution.co"]);
        let decryption_policy = NullPolicy::new();
        let selected = certificates
            .iter()
            .enumerate()
            .find_map(|(index, cert)| {
                if holder.is_some_and(|holder| cert.fingerprint().to_string() != holder) { return None; }
                private_keys
                    .iter()
                    .find(|private| {
                        if private.fingerprint() != cert.fingerprint() {
                            return false;
                        }
                        let secrets: std::collections::HashSet<_> = private
                            .keys()
                            .secret()
                            .map(|key| key.fingerprint())
                            .collect();
                        let can_sign = cert
                            .keys()
                            .with_policy(&policy, None)
                            .supported()
                            .alive()
                            .revoked(false)
                            .for_signing()
                            .any(|key| secrets.contains(&key.fingerprint()));
                        // Old encryption keys must remain usable for previously generated shares.
                        let can_decrypt = cert
                            .keys()
                            .with_policy(&decryption_policy, None)
                            .for_storage_encryption()
                            .any(|key| secrets.contains(&key.fingerprint()));
                        can_sign && can_decrypt
                    })
                    .map(|private| (index, private.clone()))
            })
            .ok_or_else(|| SendShardError::invalid(Kind::NoMatchingHolderKeys))?;
        (Some(selected.0), Some(vec![selected.1]))
    } else {
        (None, None)
    };
    let messages = OpenPGP
        .parse_shard_file(bundle.shardfile.as_bytes())
        .with_contexts((), Kind::ParseShardfile)?;
    let (share, threshold) = OpenPGP
        .decrypt_one_shard(private_keys, &messages, prompt)
        .with_contexts((), Kind::DecryptShard)?;
    let request = models::SendShardRequest {
        shard: Vec::from(&share),
        threshold,
    };
    let keyring = signing_keyring(bundle, &request, selected)?;
    if let Some(holder) = holder {
        let cert = sequoia_openpgp::Cert::from_bytes(keyring.as_bytes()).map_err(|_| SendShardError::invalid(Kind::NoMatchingHolderKeys))?;
        if cert.fingerprint().to_string() != holder { return Err(SendShardError::invalid(Kind::ShareHolderMismatch)); }
    }
    Ok((request, keyring))
}

fn signing_keyring(
    bundle: &v1::GenerateQuorumResponse,
    request: &models::SendShardRequest,
    selected: Option<usize>,
) -> Result<String, SendShardError> {
    use SendShardErrorKind as Kind;
    if request.threshold != bundle.threshold {
        return Err(SendShardError::invalid(Kind::ShareThresholdMismatch));
    }
    // Keymaker zips bundle holders with the dealer's coordinates 1..=max.
    let holder = request
        .shard
        .first()
        .and_then(|coordinate| coordinate.checked_sub(1))
        .map(usize::from)
        .filter(|holder| *holder < bundle.keyring.len())
        .filter(|holder| selected.is_none_or(|selected| *holder == selected));
    let holder = holder
        .filter(|_| request.shard.len() == 33)
        .ok_or_else(|| SendShardError::invalid(Kind::ShareHolderMismatch))?;
    crate::openpgp::reconstruct_keyring(&bundle.keyring[holder..=holder])
        .with_contexts((), Kind::BundleAccess)
}

#[tracing::instrument(skip_all)]
pub async fn send_shard(
    address: std::net::SocketAddr,
    pcrs: std::collections::HashMap<u8, Vec<u8>>,
    bundle: &QuorumBundle,
    opt_private_key_path: Option<std::path::PathBuf>,
) -> Result<models::SendSignedEncryptedShardResponse, SendShardError> {
    send_selected_shard(address, pcrs, bundle, opt_private_key_path, None).await
}

pub async fn send_selected_shard(
    address: std::net::SocketAddr,
    pcrs: std::collections::HashMap<u8, Vec<u8>>,
    bundle: &QuorumBundle,
    opt_private_key_path: Option<std::path::PathBuf>,
    holder: Option<String>,
) -> Result<models::SendSignedEncryptedShardResponse, SendShardError> {
    use SendShardErrorKind as ErrorKind;

    // Establish a connection with the server
    let mut connection = tokio::net::TcpStream::connect(address)
        .await
        .with_contexts((), ErrorKind::ConnectToRemote)?;

    // Generate a nonce for attestation purposes
    let mut rng = rand::rngs::OsRng;
    let nonce = {
        let mut nonce = [0u8; 12];
        rng.fill(&mut nonce);
        nonce
    };
    let nonce_hex = smex::encode_to_string(nonce);

    // Send our nonce and receive the server's public key
    let response: models::GeneratePublicKeyResponse = crate::send_and_receive(
        &mut connection,
        models::GeneratePublicKeyRequest {
            nonce: nonce_hex.clone(),
        },
    )
    .await
    .with_contexts((), ErrorKind::SendRequest)?;

    // Verify the attestation and extract the provided public key
    let attestation =
        Nitro::new(response.attestation, pcrs).with_contexts((), ErrorKind::InvalidPCRs)?;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("time is linear");
    let document = attestation
        .verify(duration, &nonce_hex)
        .with_contexts((), ErrorKind::VerifyAttestation)?;
    let public_key_bytes = get_user_data(document).with_contexts((), ErrorKind::InvalidUserData)?;
    let their_public_key = PublicKey::from(public_key_bytes);

    // Generate our shared HKDF base
    let our_key = EphemeralSecret::random();
    let our_pubkey = PublicKey::from(&our_key).to_bytes();
    let shared_secret = our_key.diffie_hellman(&PublicKey::from(their_public_key));
    assert!(
        shared_secret.was_contributory(),
        "shared secret might be insecure"
    );
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());

    // Create the AES key
    let mut shared_key_data = [0u8; 256 / 8];
    hkdf.expand(b"key", &mut shared_key_data)
        .with_contexts((), ErrorKind::HkdfExpansionInvalid)?;
    let shared_key =
        Aes256Gcm::new_from_slice(&shared_key_data).expect("known static length is valid");

    // Create a shared nonce
    let mut nonce_data = [0u8; 12];
    hkdf.expand(b"nonce", &mut nonce_data)
        .with_contexts((), ErrorKind::HkdfExpansionInvalid)?;
    let nonce = Nonce::<U12>::from_slice(&nonce_data);

    // Get our shard
    //
    let temp_ph = std::rc::Rc::new(std::sync::Mutex::new(
        keyfork_prompt::default_handler().expect("please give us a handler"),
    ));
    let bundle = bundle.clone().to_latest();
    let (request, keyring) =
        decrypt_selected_shard(&bundle, opt_private_key_path.as_deref(), temp_ph.clone(), holder.as_deref())?;

    // Create the encrypted payload
    //
    // decrypt_one_shard actually decodes the share, but we have to re-encode it again
    // to encrypt it. this could probably be optimized.
    let send_shard_request_bytes =
        serde_json::to_vec(&request).expect("request is always serializable");
    let encrypted_send_shard_request_bytes = shared_key
        .encrypt(nonce, send_shard_request_bytes.as_slice())
        .with_contexts((), ErrorKind::RecryptShard)?;
    let encoded_encrypted_send_shard_request =
        smex::encode_to_string(encrypted_send_shard_request_bytes);

    // create the request to be signed
    let send_encrypted_shard_request = serde_json::to_string(&models::SendEncryptedShardRequest {
        encrypted_payload: encoded_encrypted_send_shard_request,
        public_key: our_pubkey,
    })
    .expect("request is always serializable");

    // sign the request
    let signature = crate::openpgp::sign(
        &keyring,
        &send_encrypted_shard_request,
        &mut **temp_ph.lock().expect("unpoisoned mutex"),
        opt_private_key_path.as_deref(),
    )
    .with_contexts((), ErrorKind::SignHexEncodedRecryptedShard)?;

    // send the signed, encrypted, request and check our status
    let reconstitution_status: models::SendSignedEncryptedShardResponse = crate::send_and_receive(
        &mut connection,
        models::SendSignedEncryptedShardRequest {
            signed_payload: send_encrypted_shard_request,
            signature,
        },
    )
    .await
    .with_contexts((), ErrorKind::SendRequest)?;

    Ok(reconstitution_status)
}

#[derive(Debug, thiserror::Error)]
pub enum GetPublicKeyError {
    #[error("could not deserialize document")]
    Deserialize {
        #[from]
        error: serde_cbor::Error,
    },

    #[error("public_key.len() => {0} != 32")]
    InvalidKeyLen(usize),
}

#[derive(Debug, serde::Deserialize)]
struct OpaqueContainsUserData {
    user_data: serde_bytes::ByteBuf,
}

fn get_user_data(document: CborValue) -> Result<[u8; 32], GetPublicKeyError> {
    let user_data_container: OpaqueContainsUserData = serde_cbor::value::from_value(document)?;
    user_data_container
        .user_data
        .into_vec()
        .try_into()
        .map_err(|v: Vec<u8>| GetPublicKeyError::InvalidKeyLen(v.len()))
}

#[cfg(all(test, feature = "rpgpie"))]
#[path = "client_tests.rs"]
pub(crate) mod tests;
