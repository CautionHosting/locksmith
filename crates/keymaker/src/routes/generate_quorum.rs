use axum::{Json, extract::State, http::StatusCode};
use bootproof::format::{Format as _, nitro::Nitro};
use dterror::*;
use keyfork_derive_openpgp::derive_util as derive;
use keyfork_shard::{
    Format,
    openpgp::{OpenPGP, openpgp},
};
use openpgp::{
    cert::{Cert, CertParser},
    packet::UserID,
    parse::Parse,
    serialize::Serialize as _,
    types::KeyFlags,
};
use std::collections::HashSet;
use std::panic::Location;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::AppState;
use keymaker_models::{
    Proofed,
    generate_quorum::{
        GenerateQuorumBundle, GenerateQuorumRequest, GenerateQuorumResponse,
        deterministic_bundle_hash, deterministic_necroproof_nonce, v1,
    },
};

structstruck::strike! {
    #[structstruck::each[derive(Debug)]]
    #[derive(thiserror::Error)]
    #[error("could not generate quorum ({kind:?}) [{location}]")]
    #[non_exhaustive]
    pub struct GenerateQuorumError {
        kind: pub enum GenerateQuorumErrorKind {
            Entropy,
            InvalidQuorumParameters,
            InvalidCertificate { index: usize, reason: &'static str },
            Shard,
            DeriveOpenPGPCert,
            SerializeOpenPGPCert,
            HashBundle,
            DeriveNecroproofNonce,
            GenerateNecroproof,
        },
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
        location: &'static Location<'static>,
    }
}

impl FromContexts for GenerateQuorumError {
    type LongLivedContext = ();
    type ShortLivedContext = GenerateQuorumErrorKind;

    fn from_contexts(
        _long_lived_ctx: Self::LongLivedContext,
        short_lived_ctx: Self::ShortLivedContext,
        location: &'static Location<'static>,
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    ) -> Self {
        Self {
            kind: short_lived_ctx,
            source: Some(source),
            location,
        }
    }
}

impl axum::response::IntoResponse for GenerateQuorumError {
    fn into_response(self) -> axum::response::Response {
        let status_code = match self.kind {
            GenerateQuorumErrorKind::Entropy
            | GenerateQuorumErrorKind::Shard
            | GenerateQuorumErrorKind::DeriveOpenPGPCert
            | GenerateQuorumErrorKind::SerializeOpenPGPCert
            | GenerateQuorumErrorKind::HashBundle
            | GenerateQuorumErrorKind::DeriveNecroproofNonce
            | GenerateQuorumErrorKind::GenerateNecroproof => StatusCode::INTERNAL_SERVER_ERROR,
            GenerateQuorumErrorKind::InvalidQuorumParameters
            | GenerateQuorumErrorKind::InvalidCertificate { .. } => StatusCode::BAD_REQUEST,
        };

        crate::middleware::error_handling::ErrorResponse::from_error(&self)
            .into_response(status_code)
    }
}

impl GenerateQuorumError {
    #[track_caller]
    fn invalid(kind: GenerateQuorumErrorKind) -> Self {
        Self {
            kind,
            source: None,
            location: Location::caller(),
        }
    }
}

fn validate_request(request: &v1::GenerateQuorumRequest) -> Result<Vec<Cert>, GenerateQuorumError> {
    use GenerateQuorumErrorKind as Kind;
    if request.threshold == 0
        || request.threshold > request.max
        || request.max == 255
        || usize::from(request.max) != request.keyring.len()
    {
        return Err(GenerateQuorumError::invalid(Kind::InvalidQuorumParameters));
    }
    let mut policy = openpgp::policy::StandardPolicy::new();
    policy.good_critical_notations(&["organization-id@caution.co", "bundle-id@caution.co"]);
    let mut primary_keys = HashSet::new();
    let mut encryption_keys = HashSet::new();
    let mut certs = Vec::with_capacity(request.keyring.len());
    for (index, key) in request.keyring.iter().enumerate() {
        let armored = match key {
            v1::Key::OpenPGP { cert } | v1::Key::WebAuthn { cert, .. } => cert,
        };
        let invalid =
            |reason| GenerateQuorumError::invalid(Kind::InvalidCertificate { index, reason });
        let mut parser =
            CertParser::from_bytes(armored).map_err(|_| invalid("malformed certificate"))?;
        let cert = parser
            .next()
            .ok_or_else(|| invalid("missing certificate"))?
            .map_err(|_| invalid("malformed certificate"))?;
        if parser.next().is_some() {
            return Err(invalid("each holder must contain exactly one certificate"));
        }
        let valid_cert = cert
            .with_policy(&policy, None)
            .map_err(|_| invalid("certificate does not satisfy policy"))?;
        if valid_cert.alive().is_err()
            || matches!(
                valid_cert.revocation_status(),
                openpgp::types::RevocationStatus::Revoked(_)
            )
        {
            return Err(invalid("certificate is expired or revoked"));
        }
        let keys = || {
            cert.keys()
                .with_policy(&policy, None)
                .supported()
                .alive()
                .revoked(false)
        };
        if cert.is_tsk()
            || keys().for_signing().next().is_none()
            || keys().for_authentication().next().is_none()
            || keys().for_storage_encryption().next().is_none()
        {
            return Err(invalid(
                "requires a public certificate with live signing, authentication and storage-encryption keys",
            ));
        }
        if !primary_keys.insert(cert.fingerprint()) {
            return Err(invalid("duplicate holder certificate"));
        }
        for key in keys().for_storage_encryption() {
            if !encryption_keys.insert(key.key().mpis().clone()) {
                return Err(invalid("holders must not share an encryption key"));
            }
        }
        certs.push(cert);
    }
    Ok(certs)
}

fn generate_entropy() -> Result<[u8; 32], GenerateQuorumError> {
    #[cfg(feature = "unsafe-e2e")]
    if std::env::var("CAUTION_UNSAFE_KEY_SERVICE_E2E").as_deref() == Ok("1") {
        warn!("UNSAFE E2E: using constant quorum entropy");
        return Ok([7u8; 32]);
    }
    keyfork_entropy::ensure_safe();
    keyfork_entropy::generate_entropy_of_const_size()
        .with_contexts((), GenerateQuorumErrorKind::Entropy)
}

fn generate_necroproof(bundle_hash: &[u8], nonce: &[u8]) -> Result<Vec<u8>, GenerateQuorumError> {
    #[cfg(feature = "unsafe-e2e")]
    if std::env::var("CAUTION_UNSAFE_KEY_SERVICE_E2E").as_deref() == Ok("1") {
        warn!("UNSAFE E2E: returning a fake Keymaker proof");
        return Ok(nonce.to_vec());
    }
    Nitro
        .generate(Some(bundle_hash), Some(nonce))
        .map_err(|source| {
            GenerateQuorumError::from_contexts(
                (),
                GenerateQuorumErrorKind::GenerateNecroproof,
                Location::caller(),
                source,
            )
        })
}

/// Generate encrypted shares and bind the original structured holders into the proofed bundle.
#[axum::debug_handler]
#[tracing::instrument(skip_all)]
pub async fn generate_quorum(
    State(app_state): State<Arc<AppState>>,
    Json(request): Json<GenerateQuorumRequest>,
) -> Result<Json<GenerateQuorumResponse>, GenerateQuorumError> {
    #[cfg(feature = "selfnuke")]
    tokio::task::spawn({
        // NOTE: The system should be terminated after this route has been called, regardless of
        // whether it was successful or not. We set a deadline of 10 seconds to complete the
        // operation and send the response to the client before rebooting. No one else will be able
        // to obtain a reboot permit, as we purposefully forget the permit without releasing it.
        let reboot_permit = app_state
            .reboot_permit
            .acquire()
            .await
            .expect("semaphore is never closed");
        std::mem::forget(reboot_permit);
        async move {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            nix::sys::reboot::reboot(nix::sys::reboot::RebootMode::RB_AUTOBOOT)
                .expect("should be able to reboot system");
        }
    });

    use GenerateQuorumErrorKind as ErrorKind;
    let request = request.to_latest();
    let certs = validate_request(&request)?;
    let v1::GenerateQuorumRequest {
        bundle_id,
        label,
        threshold,
        max,
        keyring,
    } = request;

    debug!(?label, ?threshold, ?max);
    let entropy = generate_entropy()?;

    let opgp = OpenPGP;

    let mut shardfile_bytes = vec![];
    opgp.shard_and_encrypt(threshold, max, &entropy, &*certs, &mut shardfile_bytes)
        .map_err(|source| {
            warn!("untraceable shard error: {source}");
            GenerateQuorumError {
                kind: GenerateQuorumErrorKind::Shard,
                source: None,
                location: Location::caller(),
            }
        })?;

    let shardfile =
        String::try_from(shardfile_bytes).expect("should always get utf8 encoded bytes");

    let userid = UserID::from("Keymaker-generated key");
    let mnemonic = keyfork_mnemonic::Mnemonic::from_array(entropy);
    let seed = mnemonic.generate_seed(None);
    let xprv =
        keyfork_derive_openpgp::XPrv::new(seed).expect("const length Ed25519 key is always valid");
    let index = derive::DerivationIndex::new(0, true).expect("account 0 is always valid");
    let path = keyfork_derive_path_data::paths::OPENPGP
        .clone()
        .chain_push(index);

    let subkeys = [
        KeyFlags::empty().set_certification(),
        KeyFlags::empty().set_signing(),
        KeyFlags::empty()
            .set_transport_encryption()
            .set_storage_encryption(),
        KeyFlags::empty().set_authentication(),
    ];
    let cert = keyfork_derive_openpgp::derive(
        &xprv
            .derive_path(&path)
            .with_contexts((), ErrorKind::DeriveOpenPGPCert)?,
        &subkeys,
        &userid,
    )
    .with_contexts((), ErrorKind::DeriveOpenPGPCert)?;

    let mut secret_recipient_public_key_bytes = vec![];
    let mut armored = openpgp::armor::Writer::new(
        &mut secret_recipient_public_key_bytes,
        openpgp::armor::Kind::PublicKey,
    )
    .with_contexts((), ErrorKind::SerializeOpenPGPCert)?;
    cert.serialize(&mut armored)
        .map_err(|source| GenerateQuorumError {
            kind: ErrorKind::SerializeOpenPGPCert,
            source: Some(source.into_boxed_dyn_error()),
            location: Location::caller(),
        })
        .with_contexts((), ErrorKind::SerializeOpenPGPCert)?;
    armored
        .finalize()
        .with_contexts((), ErrorKind::SerializeOpenPGPCert)?;

    let public_key = String::try_from(secret_recipient_public_key_bytes)
        .expect("should always get valid utf8 from armor");

    let data = GenerateQuorumBundle::V1(v1::GenerateQuorumResponse {
        bundle_id,
        label,
        keyring,
        shardfile,
        public_key,
    });
    let bundle_hash = deterministic_bundle_hash(&data).with_contexts((), ErrorKind::HashBundle)?;
    let nonce = deterministic_necroproof_nonce(&bundle_hash)
        .with_contexts((), ErrorKind::DeriveNecroproofNonce)?;
    let necroproof = generate_necroproof(&bundle_hash, &nonce)?;

    Ok(Json(Proofed { data, necroproof }))
}

#[cfg(test)]
#[path = "generate_quorum_tests.rs"]
mod tests;
