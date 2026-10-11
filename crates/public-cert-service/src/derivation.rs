use bootproof::format::{Format as _, nitro::Nitro};
use keyfork_derive_openpgp::openpgp;
use keyfork_derive_path_data::paths;
use keyfork_derive_util::{DerivationIndex, DerivationPath};
use openpgp::{
    Cert, Packet,
    packet::{UserID, signature::SignatureBuilder, signature::subpacket::NotationDataFlags},
    types::{KeyFlags, SignatureType},
};
use public_certificate_models::{Proofed, PublicCertificateBundle, PublicCertificateResponse, v1};
use sha2::{Digest as _, Sha256};
use std::time::Instant;

/// ASCII namespace component for Caution Keymaker-derived OpenPGP certificates.
pub const KEYMAKER_NAMESPACE: u32 = u32::from_be_bytes(*b"kmkr");

/// Critical OpenPGP notation containing the organization UUID bytes in lowercase hex.
pub const ORGANIZATION_ID_NOTATION: &str = "organization-id@caution.co";

/// Critical OpenPGP notation containing the bundle UUID bytes in lowercase hex.
pub const BUNDLE_ID_NOTATION: &str = "bundle-id@caution.co";

/// Return the base derivation path for public certificates generated for Keymaker bundles.
///
/// The path is `m/pgp'/kmkr'`.  The service constructs this internally; callers never submit
/// derivation paths, fingerprints, or certificate indices.
#[must_use]
pub fn kmkr_base_path() -> DerivationPath {
    paths::OPENPGP.clone().chain_push(
        DerivationIndex::new(KEYMAKER_NAMESPACE, true)
            .expect("ASCII static namespace is a valid derivation index"),
    )
}

/// Return the default OpenPGP CA path from the current Keyfork quorum.
#[must_use]
pub fn default_openpgp_ca_path() -> DerivationPath {
    paths::OPENPGP
        .clone()
        .chain_push(DerivationIndex::new(0, true).expect("static index is valid"))
}

/// Convert canonical UUID bytes into the four hardened path indices used by the public
/// certificate service.
///
/// Each UUID is split into four big-endian `u32` words and the highest bit is cleared before
/// hardening.  This conversion is intentionally lossy; consumers must verify the full UUIDs from
/// the proofed bundle data and certificate notations, not only from the path.
#[must_use]
pub fn uuid_indices(id: [u8; 16]) -> [DerivationIndex; 4] {
    std::array::from_fn(|word_index| {
        let offset = word_index * 4;
        let word = u32::from_be_bytes([id[offset], id[offset + 1], id[offset + 2], id[offset + 3]])
            & 0x7fff_ffff;

        DerivationIndex::new(word, true).expect("masked UUID word is a valid derivation index")
    })
}

/// Return the complete account path for a derived public certificate.
///
/// The path is:
///
/// `m/pgp'/kmkr'/<org-0>'/.../<org-3>'/<bundle-0>'/.../<bundle-3>'/<index>'`.
#[must_use]
pub fn certificate_path(
    organization_id: [u8; 16],
    bundle_id: [u8; 16],
    index: u8,
) -> DerivationPath {
    let mut path = kmkr_base_path();
    for component in uuid_indices(organization_id)
        .into_iter()
        .chain(uuid_indices(bundle_id))
        .chain([DerivationIndex::new(u32::from(index), true)
            .expect("u8 index is a valid derivation index")])
    {
        path.push(component);
    }
    path
}

#[derive(Debug, thiserror::Error)]
pub enum ArmorPublicCertificateError {
    #[error("failed to start OpenPGP public-key armor writer")]
    StartArmor(#[source] std::io::Error),

    #[error("failed to export OpenPGP certificate")]
    ExportCertificate(#[source] anyhow::Error),

    #[error("failed to finish OpenPGP public-key armor")]
    FinishArmor(#[source] std::io::Error),

    #[error("armored OpenPGP certificate was not valid UTF-8")]
    ArmoredCertificateUtf8(#[source] std::string::FromUtf8Error),
}

#[derive(Debug, thiserror::Error)]
pub enum BindPublicCertificateError {
    #[error("failed to build Caution certification notation")]
    BuildNotation(#[source] anyhow::Error),

    #[error("failed to extract Caution CA signing key")]
    ExtractCaSigningKey(#[source] anyhow::Error),

    #[error("failed to sign public certificate user ID")]
    SignUserId(#[source] anyhow::Error),

    #[error("failed to attach Caution CA user ID certification")]
    AttachCertification(#[source] anyhow::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum DeterministicBundleHashError {
    #[error("failed to serialize public certificate bundle for hashing")]
    SerializeBundle(#[source] serde_cbor::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum DerivePublicCertificateError {
    #[error("key service root key unavailable")]
    Unavailable(#[source] crate::service::Error),
    #[error("failed to connect to keyforkd")]
    ConnectKeyforkd(#[source] keyforkd_client::Error),

    #[error("failed to request default OpenPGP CA key from keyforkd")]
    RequestDefaultCaKey(#[source] keyforkd_client::Error),

    #[error("failed to request derived public certificate key from keyforkd")]
    RequestDerivedKey(#[source] keyforkd_client::Error),

    #[error("failed to derive default OpenPGP CA certificate")]
    DeriveDefaultCaCertificate(#[source] keyfork_derive_openpgp::Error),

    #[error("failed to derive OpenPGP certificate")]
    DeriveOpenPgpCertificate(#[source] keyfork_derive_openpgp::Error),

    #[error("failed to bind public certificate to Caution CA")]
    BindPublicCertificate(#[source] BindPublicCertificateError),

    #[error("failed to armor OpenPGP certificate")]
    ArmorPublicCertificate(#[source] ArmorPublicCertificateError),

    #[error("failed to hash public certificate bundle")]
    HashBundle(#[source] DeterministicBundleHashError),

    #[error("failed to generate bootproof necroproof for public certificate bundle")]
    GenerateNecroproof(#[source] bootproof::format::BoxError),
}

#[must_use]
pub fn public_certificate_userid(index: u8) -> UserID {
    UserID::from(format!("Caution public certificate index={index}"))
}

#[must_use]
pub fn public_certificate_key_flags() -> [KeyFlags; 4] {
    [
        KeyFlags::empty().set_certification(),
        KeyFlags::empty().set_signing(),
        KeyFlags::empty()
            .set_transport_encryption()
            .set_storage_encryption(),
        KeyFlags::empty().set_authentication(),
    ]
}

fn armor_public_certificate(cert: &Cert) -> Result<String, ArmorPublicCertificateError> {
    let mut certificate_bytes = Vec::new();
    let mut armored =
        openpgp::armor::Writer::new(&mut certificate_bytes, openpgp::armor::Kind::PublicKey)
            .map_err(ArmorPublicCertificateError::StartArmor)?;

    openpgp::serialize::Marshal::export(cert, &mut armored)
        .map_err(ArmorPublicCertificateError::ExportCertificate)?;
    armored
        .finalize()
        .map_err(ArmorPublicCertificateError::FinishArmor)?;

    String::from_utf8(certificate_bytes)
        .map_err(ArmorPublicCertificateError::ArmoredCertificateUtf8)
}

fn bind_public_certificate_to_caution_ca(
    cert: Cert,
    ca_cert: &Cert,
    organization_id: [u8; 16],
    bundle_id: [u8; 16],
) -> Result<Cert, BindPublicCertificateError> {
    let mut ca_signer = ca_cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .map_err(BindPublicCertificateError::ExtractCaSigningKey)?
        .into_keypair()
        .map_err(BindPublicCertificateError::ExtractCaSigningKey)?;

    let notation_flags = NotationDataFlags::empty().set_human_readable();
    let builder = SignatureBuilder::new(SignatureType::PositiveCertification)
        .set_notation(
            ORGANIZATION_ID_NOTATION,
            hex::encode(organization_id).as_bytes(),
            notation_flags.clone(),
            true,
        )
        .map_err(BindPublicCertificateError::BuildNotation)?
        .set_notation(
            BUNDLE_ID_NOTATION,
            hex::encode(bundle_id).as_bytes(),
            notation_flags,
            true,
        )
        .map_err(BindPublicCertificateError::BuildNotation)?;

    let certifications = cert
        .userids()
        .map(|userid| {
            userid
                .userid()
                .bind(&mut ca_signer, &cert, builder.clone())
                .map(Packet::Signature)
                .map_err(BindPublicCertificateError::SignUserId)
        })
        .collect::<Result<Vec<_>, _>>()?;

    cert.insert_packets(certifications)
        .map_err(BindPublicCertificateError::AttachCertification)
}

pub fn deterministic_bundle_hash(
    bundle: &PublicCertificateBundle,
) -> Result<[u8; 32], DeterministicBundleHashError> {
    let serialized =
        serde_cbor::to_vec(bundle).map_err(DeterministicBundleHashError::SerializeBundle)?;
    Ok(Sha256::digest(serialized).into())
}

pub fn derive_public_certificate(
    request: v1::PublicCertificateRequest,
    bundle_id: [u8; 16],
) -> Result<PublicCertificateResponse, DerivePublicCertificateError> {
    derive_public_certificate_until(
        request,
        bundle_id,
        None,
        Instant::now() + crate::service::REQUEST_BUDGET,
    )
}

pub(crate) fn derive_public_certificate_until(
    request: v1::PublicCertificateRequest,
    bundle_id: [u8; 16],
    expected_ca: Option<&Cert>,
    deadline: Instant,
) -> Result<PublicCertificateResponse, DerivePublicCertificateError> {
    let ca_cert =
        crate::service::root_ca(deadline).map_err(DerivePublicCertificateError::Unavailable)?;
    if expected_ca.is_some_and(|expected| expected.fingerprint() != ca_cert.fingerprint()) {
        return Err(DerivePublicCertificateError::Unavailable(
            crate::service::Error::unavailable("configured CA does not match key service root key"),
        ));
    }
    let key_flags = public_certificate_key_flags();

    let mut certificates = Vec::with_capacity(usize::from(request.certificate_count.get()));

    for index in 0..request.certificate_count.get() {
        let path = certificate_path(request.organization_id, bundle_id, index);
        let derived_xprv = crate::service::derive_key(&path, deadline)
            .map_err(DerivePublicCertificateError::Unavailable)?;
        let userid = public_certificate_userid(index);
        let cert = keyfork_derive_openpgp::derive(&derived_xprv, &key_flags, &userid)
            .map_err(DerivePublicCertificateError::DeriveOpenPgpCertificate)?;
        let cert = bind_public_certificate_to_caution_ca(
            cert,
            &ca_cert,
            request.organization_id,
            bundle_id,
        )
        .map_err(DerivePublicCertificateError::BindPublicCertificate)?;

        certificates.push(
            armor_public_certificate(&cert)
                .map_err(DerivePublicCertificateError::ArmorPublicCertificate)?,
        );
    }

    let data = PublicCertificateBundle::V1(v1::PublicCertificateBundle {
        organization_id: request.organization_id,
        bundle_id,
        certificates,
    });
    let bundle_hash =
        deterministic_bundle_hash(&data).map_err(DerivePublicCertificateError::HashBundle)?;
    crate::service::remaining(deadline).map_err(DerivePublicCertificateError::Unavailable)?;
    let necroproof = generate_necroproof(&bundle_hash)?;
    crate::service::remaining(deadline).map_err(DerivePublicCertificateError::Unavailable)?;

    Ok(Proofed { data, necroproof })
}

fn generate_necroproof(bundle_hash: &[u8]) -> Result<Vec<u8>, DerivePublicCertificateError> {
    #[cfg(feature = "unsafe-e2e")]
    if std::env::var("CAUTION_UNSAFE_KEY_SERVICE_E2E").as_deref() == Ok("1") {
        tracing::warn!("UNSAFE E2E: returning a fake public-certificate proof");
        return Ok(bundle_hash.to_vec());
    }
    Nitro
        .generate(Some(bundle_hash), None)
        .map_err(DerivePublicCertificateError::GenerateNecroproof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_proof_requires_feature_and_environment() {
        const CHILD: &str = "PUBLIC_CERT_HOOK_TEST_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let enabled = cfg!(feature = "unsafe-e2e")
                && std::env::var("CAUTION_UNSAFE_KEY_SERVICE_E2E").as_deref() == Ok("1");
            let proof = generate_necroproof(&[3; 32]);
            assert_eq!(proof.as_ref().is_ok_and(|proof| proof == &[3; 32]), enabled);
            return;
        }
        for flag in [None, Some(""), Some("0"), Some("1")] {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child
                .args([
                    "--exact",
                    "derivation::tests::unsafe_proof_requires_feature_and_environment",
                ])
                .env(CHILD, "1")
                .env_remove("CAUTION_UNSAFE_KEY_SERVICE_E2E");
            if let Some(flag) = flag {
                child.env("CAUTION_UNSAFE_KEY_SERVICE_E2E", flag);
            }
            let output = child.output().unwrap();
            assert!(
                String::from_utf8_lossy(&output.stdout)
                    .contains("test result: ok. 1 passed; 0 failed;"),
                "child must execute exactly one test: {:?}",
                output
            );
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    const ORG_ID: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x84, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    const BUNDLE_ID: [u8; 16] = [
        0xff, 0xee, 0xdd, 0xcc, 0x7b, 0xaa, 0x99, 0x88, 0x10, 0x20, 0x30, 0x40, 0x80, 0x00, 0x00,
        0x00,
    ];

    #[test]
    fn kmkr_base_path_uses_openpgp_namespace_then_keymaker_namespace() {
        assert_eq!(kmkr_base_path().to_string(), "m/7366512'/1802333042'");
    }

    #[test]
    fn uuid_indices_use_canonical_byte_order_and_mask_high_bit() {
        let indices = uuid_indices(ORG_ID).map(|index| index.to_string());

        assert_eq!(
            indices,
            ["1122867'", "72705655'", "144288443'", "1289613055'"]
        );
    }

    #[test]
    fn complete_path_preserves_org_then_bundle_then_index_order() {
        assert_eq!(
            certificate_path(ORG_ID, BUNDLE_ID, 3).to_string(),
            "m/7366512'/1802333042'/1122867'/72705655'/144288443'/1289613055'/2146360780'/2074777992'/270544960'/0'/3'"
        );
    }

    #[test]
    fn default_openpgp_ca_path_matches_locksmith_default() {
        assert_eq!(default_openpgp_ca_path().to_string(), "m/7366512'/0'");
    }

    #[test]
    fn swapping_org_and_bundle_changes_the_path() {
        assert_ne!(
            certificate_path(ORG_ID, BUNDLE_ID, 0),
            certificate_path(BUNDLE_ID, ORG_ID, 0)
        );
    }

    #[test]
    fn public_certificate_userid_binds_only_index() {
        assert_eq!(
            public_certificate_userid(3).value(),
            b"Caution public certificate index=3"
        );
    }

    #[test]
    fn v1_contract_fixture_preserves_exact_certificate_encoding() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/v1-contract.json"
        )))
        .unwrap();
        assert_eq!(fixture["fixture_version"], 1);
        let expected = &fixture["public_certificates"];
        let data: PublicCertificateBundle =
            serde_json::from_value(expected["data"].clone()).unwrap();
        assert_eq!(
            hex::encode(serde_cbor::to_vec(&data).unwrap()),
            expected["cbor_hex"]
        );
        assert_eq!(
            hex::encode(deterministic_bundle_hash(&data).unwrap()),
            expected["sha256"]
        );
        assert!(expected["proof_nonce"].is_null());
        assert!(
            serde_json::from_value::<PublicCertificateBundle>(fixture["quorum"]["data"].clone())
                .is_err()
        );
        assert_eq!(
            public_certificate_key_flags(),
            [
                KeyFlags::empty().set_certification(),
                KeyFlags::empty().set_signing(),
                KeyFlags::empty()
                    .set_transport_encryption()
                    .set_storage_encryption(),
                KeyFlags::empty().set_authentication(),
            ]
        );
        let original_hash = deterministic_bundle_hash(&data).unwrap();
        for changed in ["organization_id", "bundle_id", "certificates"] {
            let mut value = expected["data"].clone();
            match changed {
                "certificates" => value[changed][0] = "changed certificate".into(),
                _ => value[changed][0] = 42.into(),
            }
            let changed: PublicCertificateBundle = serde_json::from_value(value).unwrap();
            assert_ne!(deterministic_bundle_hash(&changed).unwrap(), original_hash);
        }
    }

    #[test]
    fn deterministic_bundle_hash_is_stable() {
        let bundle = PublicCertificateBundle::V1(v1::PublicCertificateBundle {
            organization_id: ORG_ID,
            bundle_id: BUNDLE_ID,
            certificates: vec!["cert-a".to_string(), "cert-b".to_string()],
        });

        assert_eq!(
            hex::encode(deterministic_bundle_hash(&bundle).unwrap()),
            hex::encode(deterministic_bundle_hash(&bundle).unwrap())
        );
    }
}
