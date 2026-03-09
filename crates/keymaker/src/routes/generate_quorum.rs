use axum::{Json, http::StatusCode};
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
use std::panic::Location;
use tracing::{debug, warn};

use keymaker_models::generate_quorum::{GenerateQuorumRequest, GenerateQuorumResponse};

fn hash_keyring(keyring: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};

    let mut hash = Sha256::new();
    hash.update(keyring);

    hash.finalize().to_vec()
}

#[derive(Debug, thiserror::Error)]
#[error("could not parse valid certificates [{location}]")]
pub struct ParseCertificatesError {
    location: &'static Location<'static>,
    #[source]
    source: anyhow::Error,
}

impl From<anyhow::Error> for ParseCertificatesError {
    #[track_caller]
    fn from(source: anyhow::Error) -> Self {
        Self {
            location: Location::caller(),
            source,
        }
    }
}

fn parse_certs(armored_input: &str) -> Result<Vec<Cert>, ParseCertificatesError> {
    let cert_parser = CertParser::from_bytes(armored_input)?;
    let mut certs = vec![];
    let policy = openpgp::policy::StandardPolicy::new();

    for parseable_cert in cert_parser {
        let cert = parseable_cert?;
        let valid_cert = cert.with_policy(&policy, None)?;
        let has_auth = valid_cert.keys().for_authentication().next().is_some();
        let has_enc = valid_cert.keys().for_storage_encryption().next().is_some();

        if has_auth && has_enc {
            certs.push(cert);
        } else {
            warn!(
                ?has_auth,
                ?has_enc,
                key_id = ?valid_cert.keyid(),
                "key does not have both auth and enc"
            );
        }
    }

    Ok(certs)
}

structstruck::strike! {
    #[structstruck::each[derive(Debug)]]
    #[derive(thiserror::Error)]
    #[error("could not generate quorum [{location}]")]
    #[non_exhaustive]
    pub struct GenerateQuorumError {
        kind: pub enum GenerateQuorumErrorKind {
            Entropy,
            ParseCerts,
            Shard,
            DeriveOpenPGPCert,
            SerializeOpenPGPCert,
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
            | GenerateQuorumErrorKind::SerializeOpenPGPCert => StatusCode::INTERNAL_SERVER_ERROR,
            GenerateQuorumErrorKind::ParseCerts => StatusCode::BAD_REQUEST,
        };

        crate::middleware::error_handling::ErrorResponse::from_error(&self)
            .into_response(status_code)
    }
}

/// Generate a new quorum for the provided keys.
///
/// The provided keyrings are concatenated with each other and hashed. The keyrings are then
/// provided to keyforkd to verify incoming requests to reachieve quorum. keyforkd compares the
/// keyring hashes against the ones baked into its enclave image before allowing a shard to be
/// entered into quorum.
#[axum::debug_handler]
#[tracing::instrument(skip_all)]
pub async fn generate_quorum(
    Json(GenerateQuorumRequest {
        label,
        threshold,
        max,
        keyring,
    }): Json<GenerateQuorumRequest>,
) -> Result<Json<GenerateQuorumResponse>, GenerateQuorumError> {
    use GenerateQuorumErrorKind as ErrorKind;
    let keyring_hash = hash_keyring(keyring.as_bytes());

    debug!(?label, ?threshold, ?max, ?keyring_hash);
    keyfork_entropy::ensure_safe();

    let certs = parse_certs(&keyring).with_contexts((), GenerateQuorumErrorKind::ParseCerts)?;

    let opgp = OpenPGP;
    let entropy: [u8; 32] =
        keyfork_entropy::generate_entropy_of_const_size().with_contexts((), ErrorKind::Entropy)?;

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

    let secret_recipient_public_key = String::try_from(secret_recipient_public_key_bytes)
        .expect("should always get valid utf8 from armor");

    Ok(Json(GenerateQuorumResponse {
        label,
        keyring,
        keyring_hash,
        shardfile,
        secret_recipient_public_key,
        necroproof: vec![],
    }))
}
