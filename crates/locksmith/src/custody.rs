//! Durable custody identities. Certificate expiry is checked when a holder enters
//! a verified bundle, not when its share is released. Live authorization remains
//! the responsibility of the release protocol and destination session.
use crate::release::Error;
use dterror::FromContexts;
use sequoia_openpgp::{
    Cert, Packet, PacketPile,
    parse::Parse,
    policy::{HashAlgoSecurity, Policy, StandardPolicy},
};
use std::time::SystemTime;

pub(crate) fn pgp_error(source: anyhow::Error) -> Error {
    Error::from_contexts(
        (),
        "custody certificate verification",
        std::panic::Location::caller(),
        source.into(),
    )
}
fn policy() -> StandardPolicy<'static> {
    let mut policy = StandardPolicy::new();
    policy.good_critical_notations(&["organization-id@caution.co", "bundle-id@caution.co"]);
    policy
}

/// The configured primary CA key is an explicit trust anchor, not a short-lived
/// identity discovered from a service. Keep its bindings, capabilities, algorithm
/// and revocation checks; key expiration alone does not retire this anchor.
pub fn validate_ca_anchor(ca: &Cert, at: SystemTime) -> Result<(), Error> {
    if ca.is_tsk()
        || !ca
            .keys()
            .with_policy(&policy(), at)
            .supported()
            .revoked(false)
            .for_certification()
            .any(|key| key.fingerprint() == ca.fingerprint())
    {
        return Err(Error::invalid("invalid or revoked configured CA anchor"));
    }
    Ok(())
}

/// Verify a current transport signature using the exact signing keys that were
/// eligible in the proof-bound snapshot at authenticated generation time.
/// Callers must obtain `at` from verified Keymaker evidence, never request data.
pub fn verify_holder_signature(
    cert: &str,
    data: &str,
    signature: &str,
    at: SystemTime,
) -> Result<(), Error> {
    let cert = Cert::from_bytes(cert).map_err(pgp_error)?;
    if cert.is_tsk() {
        return Err(Error::invalid("public holder certificate required"));
    }
    let policy = policy();
    let valid = cert.with_policy(&policy, at).map_err(pgp_error)?;
    valid.alive().map_err(pgp_error)?;
    if matches!(
        valid.revocation_status(),
        sequoia_openpgp::types::RevocationStatus::Revoked(_)
    ) {
        return Err(Error::invalid("revoked holder certificate"));
    }
    let packets: Vec<_> = PacketPile::from_bytes(signature)
        .map_err(pgp_error)?
        .into_children()
        .collect();
    let [Packet::Signature(signature)] = packets.as_slice() else {
        return Err(Error::invalid(
            "exactly one detached holder signature required",
        ));
    };
    policy
        .signature(signature, HashAlgoSecurity::CollisionResistance)
        .map_err(pgp_error)?;
    // Check the signature's own lifetime at release time, without backdating it.
    signature
        .signature_alive(SystemTime::now(), std::time::Duration::from_secs(60))
        .map_err(pgp_error)?;
    if valid
        .keys()
        .supported()
        .alive()
        .revoked(false)
        .for_signing()
        .any(|key| signature.verify_message(key.key(), data.as_bytes()).is_ok())
    {
        Ok(())
    } else {
        Err(Error::invalid("invalid custody holder signature"))
    }
}

/// Synthetic fixtures have no authenticated time. The existing unsafe feature
/// and exact runtime flag are required before using the local clock in tests.
pub fn generation_time(at: Option<SystemTime>) -> Result<SystemTime, Error> {
    if let Some(at) = at {
        return Ok(at);
    }
    #[cfg(feature = "unsafe-e2e")]
    if std::env::var("CAUTION_UNSAFE_KEY_SERVICE_E2E").as_deref() == Ok("1") {
        return Ok(SystemTime::now());
    }
    Err(Error::invalid(
        "authenticated bundle generation time required",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sequoia_openpgp::{
        cert::{CertBuilder, CertRevocationBuilder},
        packet::signature::SignatureBuilder,
        serialize::{
            SerializeInto,
            stream::{Armorer, Message, Signer},
        },
        types::{ReasonForRevocation, SignatureType},
    };
    use std::{io::Write, time::Duration};

    #[test]
    fn expired_snapshot_verifies_current_signature_only_if_eligible_at_generation() {
        let now = SystemTime::now();
        let created = now - Duration::from_secs(3 * 86400);
        let (cert, _) = CertBuilder::new()
            .set_creation_time(created)
            .set_validity_period(Duration::from_secs(86400))
            .add_userid("holder")
            .add_signing_subkey()
            .generate()
            .unwrap();
        let mut pair = cert
            .keys()
            .secret()
            .nth(1)
            .unwrap()
            .key()
            .clone()
            .into_keypair()
            .unwrap();
        let mut bytes = Vec::new();
        let message = Armorer::new(Message::new(&mut bytes))
            .kind(sequoia_openpgp::armor::Kind::Signature)
            .build()
            .unwrap();
        let mut signer = Signer::with_template(
            message,
            pair.clone(),
            SignatureBuilder::new(SignatureType::Binary),
        )
        .detached()
        .build()
        .unwrap();
        signer.write_all(b"release").unwrap();
        signer.finalize().unwrap();
        let signature = String::from_utf8(bytes).unwrap();
        let public = cert.clone().strip_secret_key_material();
        let armored = String::from_utf8(public.armored().to_vec().unwrap()).unwrap();
        let generation = created + Duration::from_secs(3600);
        verify_holder_signature(&armored, "release", &signature, generation).unwrap();
        assert!(verify_holder_signature(&armored, "release", &signature, now).is_err());
        assert!(
            verify_holder_signature(
                &armored,
                "release",
                &signature,
                created - Duration::from_secs(1)
            )
            .is_err()
        );
        assert!(verify_holder_signature(&armored, "altered", &signature, generation).is_err());
        let (wrong, _) = CertBuilder::new()
            .set_creation_time(created)
            .add_signing_subkey()
            .generate()
            .unwrap();
        let wrong = String::from_utf8(
            wrong
                .strip_secret_key_material()
                .armored()
                .to_vec()
                .unwrap(),
        )
        .unwrap();
        assert!(verify_holder_signature(&wrong, "release", &signature, generation).is_err());
        // A signature's current creation time is preserved, never backdated.
        let sig = SignatureBuilder::new(SignatureType::Binary)
            .sign_message(&mut pair, b"release")
            .unwrap();
        assert!(sig.signature_creation_time().unwrap() > generation);
    }

    #[test]
    fn configured_ca_expiry_does_not_retire_anchor_but_revocation_does() {
        let created = SystemTime::now() - Duration::from_secs(3 * 86400);
        let (ca, _) = CertBuilder::new()
            .set_creation_time(created)
            .set_validity_period(Duration::from_secs(86400))
            .add_userid("CA")
            .generate()
            .unwrap();
        let public = ca.clone().strip_secret_key_material();
        validate_ca_anchor(&public, created + Duration::from_secs(3600)).unwrap();
        validate_ca_anchor(&public, SystemTime::now()).unwrap();
        let mut signer = ca
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap();
        let revoked = CertRevocationBuilder::new()
            .set_reason_for_revocation(ReasonForRevocation::KeyCompromised, b"test")
            .unwrap()
            .build(&mut signer, &ca, None)
            .unwrap();
        let revoked = public.insert_packets(revoked).unwrap();
        assert!(validate_ca_anchor(&revoked, SystemTime::now()).is_err());
    }
}
