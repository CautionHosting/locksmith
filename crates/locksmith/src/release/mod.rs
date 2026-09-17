//! Enclave-owned, single-use WebAuthn authorization for one destination-bound share.
//! Keep this state inside the custody enclave. A Platform login is never release authorization.
pub mod crypto;
mod protocol;
pub use protocol::*;

use crate::bundle::{KeymakerPcrPolicy, load_response_with_timestamp};
use bootproof_sdk::format::{VerifiableSignedAttestationFormat, nitro::Nitro};
use dterror::{FromContexts, ResultExt};
use keymaker_models::generate_quorum::{deterministic_bundle_hash, v1};
use rand::RngCore;
use sequoia_openpgp::{
    Cert, packet::signature::subpacket::SubpacketValue, parse::Parse, policy::StandardPolicy,
};
use serde::Serialize;
use serde_cbor::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant, SystemTime},
};
use webauthn_rs::{Webauthn, WebauthnBuilder, prelude::*};

pub const TTL: Duration = Duration::from_secs(180);
const CAPACITY: usize = 64;
const ORG: &str = "organization-id@caution.co";
const BUNDLE: &str = "bundle-id@caution.co";

#[derive(Debug, thiserror::Error)]
#[error("share release failed ({kind}) [{location}]")]
pub struct Error {
    kind: &'static str,
    location: &'static std::panic::Location<'static>,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}
impl FromContexts for Error {
    type LongLivedContext = ();
    type ShortLivedContext = &'static str;
    fn from_contexts(
        _: (),
        kind: &'static str,
        location: &'static std::panic::Location<'static>,
        source: Box<dyn std::error::Error + Send + Sync>,
    ) -> Self {
        Self {
            kind,
            location,
            source: Some(source),
        }
    }
}
impl Error {
    #[track_caller]
    pub fn invalid(kind: &'static str) -> Self {
        Self {
            kind,
            location: std::panic::Location::caller(),
            source: None,
        }
    }
}

/// Domain-separated canonical response/request binding used by both peers.
pub fn hash<T: Serialize>(value: &T) -> Result<String, Error> {
    let canonical =
        serde_cbor::value::to_value(value).with_contexts((), "canonical release value")?;
    let bytes = serde_cbor::to_vec(&("caution-share-release-v1", canonical))
        .with_contexts((), "encode release value")?;
    Ok(smex::encode_to_string(Sha256::digest(bytes)))
}
pub fn random_nonce() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    smex::encode_to_string(bytes)
}
fn check_nonce(nonce: &str) -> Result<(), Error> {
    if nonce.len() != 64 || !nonce.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::invalid("nonce must be 32 random bytes in hex"));
    }
    Ok(())
}
pub fn pcrs(policy: &Measurements) -> Result<HashMap<u8, Vec<u8>>, Error> {
    if policy.len() != 3 || !(0..=2).all(|i| policy.contains_key(&i)) {
        return Err(Error::invalid("exact PCR0/1/2 policy required"));
    }
    policy
        .iter()
        .map(|(&i, value)| {
            let bytes = smex::decode_to_vec(value).with_contexts((), "PCR hex")?;
            if bytes.len() != 48 || bytes.iter().all(|b| *b == 0) {
                return Err(Error::invalid("invalid or debug PCR"));
            }
            Ok((i, bytes))
        })
        .collect()
}
fn now() -> Result<Duration, Error> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .with_contexts((), "system clock")
}
/// Live verification, including explicit signed timestamp freshness and exact nonce.
pub fn verify_live(proof: &[u8], policy: &Measurements, nonce: &str) -> Result<Vec<u8>, Error> {
    check_nonce(nonce)?;
    let measurements = pcrs(policy)?;
    #[cfg(feature = "unsafe-e2e")]
    if std::env::var("CAUTION_UNSAFE_KEY_SERVICE_E2E").as_deref() == Ok("1")
        && measurements.values().all(|p| p == &[0xab; 48])
    {
        if let Some(bytes) = proof.strip_prefix(b"caution-release-test-v1:") {
            let (bound_nonce, data): (String, Vec<u8>) =
                serde_json::from_slice(bytes).with_contexts((), "synthetic release evidence")?;
            if bound_nonce != nonce {
                return Err(Error::invalid("synthetic release nonce"));
            }
            return Ok(data);
        }
    }
    let now = now()?;
    let payload = Nitro::new(proof, measurements)
        .with_contexts((), "Nitro document")?
        .verify(now, &nonce)
        .with_contexts((), "fresh Nitro proof")?;
    let Value::Map(map) = payload else {
        return Err(Error::invalid("Nitro payload"));
    };
    let Some(Value::Integer(timestamp)) = map.get(&Value::Text("timestamp".into())) else {
        return Err(Error::invalid("Nitro timestamp"));
    };
    let timestamp =
        u64::try_from(*timestamp).map_err(|_| Error::invalid("Nitro timestamp range"))?;
    if u128::from(timestamp) > now.as_millis() + 60_000
        || now.as_millis().saturating_sub(u128::from(timestamp)) > TTL.as_millis()
    {
        return Err(Error::invalid("stale or future Nitro evidence"));
    }
    match map.get(&Value::Text("user_data".into())) {
        Some(Value::Bytes(bytes)) => Ok(bytes.clone()),
        _ => Err(Error::invalid("Nitro user_data")),
    }
}
pub fn verify_response<T: Serialize>(
    response: &Attested<T>,
    policy: &Measurements,
    nonce: &str,
) -> Result<(), Error> {
    let data = verify_live(&response.attestation, policy, nonce)?;
    if data != hash(&response.data)?.as_bytes() {
        return Err(Error::invalid("release response binding"));
    }
    Ok(())
}
fn attest<T: Serialize>(data: T, nonce: &str) -> Result<Attested<T>, Error> {
    let digest = hash(&data)?;
    let attestation = generate_live(digest.as_bytes(), nonce)?;
    Ok(Attested { data, attestation })
}

/// Test proofs are opt-in at compile time and process startup; verifiers also require the exact synthetic PCR policy.
pub(crate) fn generate_live(data: &[u8], nonce: &str) -> Result<Vec<u8>, Error> {
    #[cfg(feature = "unsafe-e2e")]
    if std::env::var("CAUTION_UNSAFE_KEY_SERVICE_E2E").as_deref() == Ok("1") {
        let mut proof = b"caution-release-test-v1:".to_vec();
        proof.extend(
            serde_json::to_vec(&(nonce, data)).with_contexts((), "synthetic release evidence")?,
        );
        return Ok(proof);
    }
    use bootproof::format::Format;
    bootproof::format::nitro::Nitro
        .generate(Some(data), Some(nonce.as_bytes()))
        .map_err(|source| {
            Error::from_contexts(
                (),
                "attest release response",
                std::panic::Location::caller(),
                source,
            )
        })
}

struct Pending {
    deadline: Instant,
    context: Context,
    bundle: v1::GenerateQuorumResponse,
    credentials: Vec<SecurityKey>,
    prepared: Option<(SecurityKeyAuthentication, [u8; 32])>,
}
/// No serializable authentication state; restart invalidates every pending operation.
pub struct Authorizer {
    webauthn: Webauthn,
    keymaker_policy: KeymakerPcrPolicy,
    ca: Cert,
    pending: Mutex<HashMap<String, Pending>>,
}
impl Authorizer {
    pub fn new(
        rp_id: &str,
        origin: &str,
        keymaker_policy: KeymakerPcrPolicy,
        ca: Cert,
    ) -> Result<Self, Error> {
        let origin = Url::parse(origin).with_contexts((), "release origin")?;
        if origin.scheme() != "https" {
            return Err(Error::invalid("HTTPS release origin required"));
        }
        let webauthn = WebauthnBuilder::new(rp_id, &origin)
            .with_contexts((), "release RP/origin")?
            .build()
            .with_contexts((), "release WebAuthn verifier")?;
        if ca.is_tsk() || keymaker_policy.sets.is_empty() {
            return Err(Error::invalid("public CA and Keymaker policy required"));
        }
        // Bundle policies must independently pin all non-debug measurement slots.
        for set in &keymaker_policy.sets {
            let policy = set
                .pcrs
                .iter()
                .map(|(&i, p)| (i, smex::encode_to_string(p)))
                .collect();
            pcrs(&policy)?;
        }
        Ok(Self {
            webauthn,
            keymaker_policy,
            ca,
            pending: Mutex::new(HashMap::new()),
        })
    }
    pub fn begin(&self, request: BeginRequest) -> Result<Attested<Begun>, Error> {
        let deadline = Instant::now() + TTL;
        let expires_at_unix_seconds = now()?.as_secs() + TTL.as_secs();
        check_nonce(&request.client_nonce)?;
        pcrs(&request.destination_policy)?;
        let request_hash = hash(&request)?;
        let bundle_hash = smex::encode_to_string(
            deterministic_bundle_hash(&request.bundle.data).with_contexts((), "bundle hash")?,
        );
        let (bundle, at) = load_response_with_timestamp(request.bundle, &self.keymaker_policy)
            .with_contexts((), "Keymaker proof")?;
        let bundle = bundle.to_latest();
        if bundle.threshold == 0
            || bundle.threshold > bundle.max
            || usize::from(bundle.max) != bundle.keyring.len()
            || bundle.max > 254
        {
            return Err(Error::invalid("quorum dimensions"));
        }
        let mut matches = Vec::new();
        let mut certificate_index = 0u8;
        for (position, key) in bundle.keyring.iter().enumerate() {
            let (cert, credentials) = match key {
                v1::Key::OpenPGP { cert } => (cert, None),
                v1::Key::WebAuthn { cert, credential } => (cert, Some(credential)),
            };
            let cert = Cert::from_bytes(cert.as_bytes()).map_err(|source| {
                Error::from_contexts(
                    (),
                    "holder certificate",
                    std::panic::Location::caller(),
                    source.into(),
                )
            })?;
            if cert.fingerprint().to_string() == request.holder {
                matches.push((position, certificate_index, cert, credentials));
            }
            if credentials.is_some() {
                certificate_index += 1;
            }
        }
        if matches.len() != 1 {
            return Err(Error::invalid(
                "holder must identify exactly one certificate",
            ));
        }
        let (position, index, cert, credentials) = matches.pop().unwrap();
        let credentials =
            credentials.ok_or_else(|| Error::invalid("selected holder uses external PGP"))?;
        if credentials.is_empty() || credentials.len() > 64 {
            return Err(Error::invalid("credential snapshot size"));
        }
        let credentials: Vec<SecurityKey> = credentials
            .iter()
            .map(|c| serde_json::from_str(c).with_contexts((), "credential snapshot"))
            .collect::<Result<_, _>>()?;
        let mut ids = std::collections::HashSet::new();
        if credentials
            .iter()
            .any(|c| c.cred_id().is_empty() || !ids.insert(c.cred_id().clone()))
        {
            return Err(Error::invalid("duplicate or empty credentials"));
        }
        #[cfg(feature = "unsafe-e2e")]
        let at = at.or_else(|| {
            (std::env::var("CAUTION_UNSAFE_KEY_SERVICE_E2E").as_deref() == Ok("1"))
                .then(SystemTime::now)
        });
        let organization_id = certified_context(
            &cert,
            &self.ca,
            bundle.bundle_id,
            index,
            at.ok_or_else(|| Error::invalid("authenticated generation timestamp required"))?,
        )?;
        let context = Context {
            version: Version::V1,
            bundle_hash,
            bundle_id: bundle.bundle_id,
            organization_id,
            holder: request.holder,
            holder_position: position as u8,
            certificate_index: index,
            destination_policy: request.destination_policy,
            transport_nonce: random_nonce(),
            expires_at_unix_seconds,
        };
        let session_id = random_nonce();
        let response = attest(
            Begun {
                request_hash,
                session_id: session_id.clone(),
                context: context.clone(),
            },
            &request.client_nonce,
        )?;
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| Error::invalid("authorization store unavailable"))?;
        pending.retain(|_, p| p.deadline > Instant::now());
        if pending.len() >= CAPACITY {
            return Err(Error::invalid("pending release capacity reached"));
        }
        pending.insert(
            session_id,
            Pending {
                deadline,
                context,
                bundle,
                credentials,
                prepared: None,
            },
        );
        Ok(response)
    }
    pub fn prepare(&self, request: PrepareRequest) -> Result<Attested<Prepared>, Error> {
        check_nonce(&request.client_nonce)?;
        // Remove before processing; any failure invalidates the attempt.
        let mut state = self.take(&request.session_id)?;
        if state.prepared.is_some() {
            return Err(Error::invalid("release already prepared"));
        }
        let destination_key: [u8; 32] = verify_live(
            &request.destination_attestation,
            &state.context.destination_policy,
            &state.context.transport_nonce,
        )?
        .try_into()
        .map_err(|_| Error::invalid("destination X25519 key length"))?;
        let (mut options, authentication) = self
            .webauthn
            .start_securitykey_authentication(&state.credentials)
            .with_contexts((), "start WebAuthn release")?;
        options.public_key.user_verification = webauthn_rs_proto::UserVerificationPolicy::Required;
        let data = Prepared {
            request_hash: hash(&request)?,
            session_id: request.session_id.clone(),
            context: state.context.clone(),
            destination_attestation_hash: hash(&request.destination_attestation)?,
            destination_key,
            options,
        };
        let response = attest(data, &request.client_nonce)?;
        state.prepared = Some((authentication, destination_key));
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| Error::invalid("authorization store unavailable"))?;
        if state.deadline <= Instant::now() || pending.len() >= CAPACITY {
            return Err(Error::invalid("release expired or capacity reached"));
        }
        pending.insert(request.session_id, state);
        Ok(response)
    }
    fn take(&self, id: &str) -> Result<Pending, Error> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| Error::invalid("authorization store unavailable"))?;
        let state = pending
            .remove(id)
            .ok_or_else(|| Error::invalid("unknown or consumed release"))?;
        if state.deadline <= Instant::now() {
            return Err(Error::invalid("release expired"));
        }
        Ok(state)
    }
    /// Verification and atomic consumption precede the private-key operation. No reusable grant escapes.
    pub fn complete<T>(
        &self,
        request: CompleteRequest,
        recrypt: impl FnOnce(&Context, &v1::GenerateQuorumResponse, [u8; 32]) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let state = self.take(&request.session_id)?;
        let (authentication, key) = state
            .prepared
            .ok_or_else(|| Error::invalid("release not prepared"))?;
        let result = self
            .webauthn
            .finish_securitykey_authentication(&request.assertion, &authentication)
            .with_contexts((), "WebAuthn release assertion")?;
        if !result.user_verified() {
            return Err(Error::invalid("verified user verification required"));
        }
        if state.deadline <= Instant::now() {
            return Err(Error::invalid("release expired"));
        }
        recrypt(&state.context, &state.bundle, key)
    }
}

fn certified_context(
    cert: &Cert,
    ca: &Cert,
    bundle_id: [u8; 16],
    index: u8,
    at: SystemTime,
) -> Result<[u8; 16], Error> {
    let mut policy = StandardPolicy::new();
    policy.good_critical_notations(&[ORG, BUNDLE]);
    crate::custody::validate_ca_anchor(ca, at)?;
    if cert.is_tsk() {
        return Err(Error::invalid("bundle must contain public certificates"));
    }
    let valid = cert.with_policy(&policy, at).map_err(|source| {
        Error::from_contexts(
            (),
            "holder certificate at generation",
            std::panic::Location::caller(),
            source.into(),
        )
    })?;
    valid.alive().map_err(crate::custody::pgp_error)?;
    if matches!(valid.revocation_status(), sequoia_openpgp::types::RevocationStatus::Revoked(_)) {
        return Err(Error::invalid("revoked holder certificate"));
    }
    let expected = format!("Caution public certificate index={index}");
    let uid = valid
        .userids()
        .revoked(false)
        .find(|uid| uid.userid().value() == expected.as_bytes())
        .ok_or_else(|| Error::invalid("certificate index"))?;
    let mut organization = None;
    for signature in uid.valid_certifications_by_key(&policy, at, ca.primary_key().key()) {
        if signature.unhashed_area().iter().any(|p| matches!(p.value(), SubpacketValue::NotationData(n) if [ORG,BUNDLE].contains(&n.name()))) { return Err(Error::invalid("unhashed certificate context")); }
        let read = |name| -> Result<Vec<u8>, Error> {
            let values: Vec<_> = signature
                .notation_data()
                .filter(|n| n.name() == name)
                .collect();
            if values.len() != 1 {
                return Err(Error::invalid("missing or duplicate certificate context"));
            }
            let value = std::str::from_utf8(values[0].value())
                .with_contexts((), "certificate context UTF8")?;
            smex::decode_to_vec(value).with_contexts((), "certificate context hex")
        };
        if read(BUNDLE)? != bundle_id {
            return Err(Error::invalid("certificate bundle mismatch"));
        }
        let org: [u8; 16] = read(ORG)?
            .try_into()
            .map_err(|_| Error::invalid("organization UUID length"))?;
        if organization.is_some_and(|old| old != org) {
            return Err(Error::invalid("conflicting organizations"));
        }
        organization = Some(org);
    }
    organization.ok_or_else(|| Error::invalid("missing CA certification"))
}

#[cfg(test)]
mod tests;
