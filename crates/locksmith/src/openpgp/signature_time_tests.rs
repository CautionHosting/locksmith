use super::*;
use pgp::types::Timestamp;
use sequoia_openpgp::{
    Cert,
    cert::{CertBuilder, CertRevocationBuilder},
    packet::signature::SignatureBuilder,
    serialize::{Serialize, SerializeInto},
    types::{ReasonForRevocation, SignatureType},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const NOW: u32 = 1_790_000_000;
const CREATED: u32 = NOW - 4 * 86400;
const DATA: &str = "clock regression payload";

fn time(seconds: u32) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(u64::from(seconds))
}

fn holder(validity: Option<Duration>) -> Cert {
    CertBuilder::new()
        .set_creation_time(time(CREATED))
        .set_validity_period(validity)
        .add_userid("clock regression holder")
        .add_signing_subkey()
        .generate()
        .unwrap()
        .0
}

fn public(cert: &Cert) -> String {
    String::from_utf8(
        cert.clone()
            .strip_secret_key_material()
            .armored()
            .to_vec()
            .unwrap(),
    )
    .unwrap()
}

fn sign(cert: &Cert, created: u32, primary: bool) -> String {
    let mut signer = cert
        .keys()
        .secret()
        .nth(usize::from(!primary))
        .unwrap()
        .key()
        .clone()
        .into_keypair()
        .unwrap();
    let signature = SignatureBuilder::new(SignatureType::Binary)
        .set_signature_creation_time(time(created))
        .unwrap()
        .sign_message(&mut signer, DATA)
        .unwrap();
    let mut armor =
        sequoia_openpgp::armor::Writer::new(Vec::new(), sequoia_openpgp::armor::Kind::Signature)
            .unwrap();
    sequoia_openpgp::Packet::Signature(signature)
        .serialize(&mut armor)
        .unwrap();
    String::from_utf8(armor.finalize().unwrap()).unwrap()
}

fn check(cert: &Cert, data: &str, signature: &str) -> Result<(), VerifyError> {
    verify_detached_at(&public(cert), data, signature, Timestamp::from_secs(NOW))
}

fn invalid(result: Result<(), VerifyError>) {
    assert!(matches!(
        result.unwrap_err().kind,
        VerifyErrorKind::AllSignaturesInvalid { .. }
    ));
}

#[test]
fn future_skew_boundary_and_aged_holder() {
    let cert = holder(None);
    for ahead in [0, 4, 60] {
        check(&cert, DATA, &sign(&cert, NOW + ahead, false)).unwrap();
    }
    assert!(matches!(
        check(&cert, DATA, &sign(&cert, NOW + 61, false))
            .unwrap_err()
            .kind,
        VerifyErrorKind::SignatureFromFuture,
    ));
    // The skew bound must not accidentally become a maximum signature age.
    check(&cert, DATA, &sign(&cert, NOW - 3600, false)).unwrap();
}

#[test]
fn clock_diagnostic_requires_a_valid_signature() {
    let cert = holder(None);
    let signature = sign(&cert, NOW + 61, false);
    invalid(check(&cert, "tampered", &signature));
    invalid(check(&holder(None), DATA, &signature));
}

#[test]
fn preserves_key_creation_capability_expiry_and_revocation_checks() {
    let cert = holder(None);
    invalid(check(&cert, DATA, &sign(&cert, CREATED - 1, false)));
    // The primary key can sign mathematically, but has certification-only flags.
    invalid(check(&cert, DATA, &sign(&cert, NOW, true)));

    let expired = holder(Some(Duration::from_secs(86400)));
    invalid(check(&expired, DATA, &sign(&expired, NOW, false)));

    let mut signer = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .unwrap()
        .into_keypair()
        .unwrap();
    let revocation = CertRevocationBuilder::new()
        .set_signature_creation_time(time(NOW - 3600))
        .unwrap()
        .set_reason_for_revocation(ReasonForRevocation::KeyCompromised, b"test")
        .unwrap()
        .build(&mut signer, &cert, None)
        .unwrap();
    let signature = sign(&cert, NOW, false);
    let revoked = cert.insert_packets(revocation).unwrap();
    invalid(check(&revoked, DATA, &signature));
}

#[test]
fn rejects_malformed_and_multiple_signatures() {
    let cert = holder(None);
    assert!(check(&cert, DATA, "not a signature").is_err());
    let signature = sign(&cert, NOW, false);
    let signatures = rpgpie::signature::load(&mut std::io::Cursor::new(signature)).unwrap();
    let mut encoded = Vec::new();
    rpgpie::signature::save(
        &[signatures[0].clone(), signatures[0].clone()],
        true,
        &mut encoded,
    )
    .unwrap();
    assert!(matches!(
        check(&cert, DATA, &String::from_utf8(encoded).unwrap())
            .unwrap_err()
            .kind,
        VerifyErrorKind::InvalidSignatureCount,
    ));
}
