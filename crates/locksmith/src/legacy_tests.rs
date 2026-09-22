use super::*;
use crate::client::tests::{PrivateKeyFile, prompt};
use keyfork_shard::{Format, openpgp::OpenPGP};
use sequoia_openpgp::{
    cert::{CertBuilder, amalgamation::ValidAmalgamation},
    serialize::{Serialize, stream::*},
    types::KeyFlags,
};
use std::{io::Write, path::PathBuf};

pub(crate) fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/v0")
        .join(name)
}
pub(crate) fn imported() -> ImportedV0 {
    import(
        &std::fs::read_to_string(fixture("bundle.json")).unwrap(),
        Some(&fixture("alice.private.asc")),
        None,
        prompt(),
    )
    .unwrap()
}
pub(crate) fn derived_key(entropy: [u8; 32]) -> Cert {
    use keyfork_derive_openpgp::{XPrv, derive_util::DerivationIndex};
    let seed = keyfork_mnemonic::Mnemonic::from_array(entropy).generate_seed(None);
    let path = keyfork_derive_path_data::paths::OPENPGP
        .clone()
        .chain_push(DerivationIndex::new(0, true).unwrap());
    let key = XPrv::new(seed).unwrap().derive_path(&path).unwrap();
    let cert = keyfork_derive_openpgp::derive(
        &key,
        &[
            KeyFlags::empty().set_certification(),
            KeyFlags::empty().set_signing(),
            KeyFlags::empty()
                .set_transport_encryption()
                .set_storage_encryption(),
            KeyFlags::empty().set_authentication(),
        ],
        &pgp::packet::UserID::from("Keymaker-generated key"),
    )
    .unwrap();
    // Fixture-only: retain derived key material, but remove the dependency's
    // one-day validity from the primary certificate and every subkey.
    let mut primary = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .unwrap()
        .into_keypair()
        .unwrap();
    let policy = StandardPolicy::new();
    let mut packets = vec![Packet::SecretKey(
        cert.primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap(),
    )];
    for uid in cert.with_policy(&policy, None).unwrap().userids() {
        let signature =
            pgp::packet::signature::SignatureBuilder::from(uid.binding_signature().clone())
                .set_signature_creation_time(
                    uid.binding_signature().signature_creation_time().unwrap(),
                )
                .unwrap()
                .set_key_validity_period(None)
                .unwrap()
                .sign_userid_binding(&mut primary, cert.primary_key().key(), uid.userid())
                .unwrap();
        packets.extend([
            Packet::UserID(uid.userid().clone()),
            Packet::Signature(signature),
        ]);
    }
    for key in cert.keys().subkeys().with_policy(&policy, None).secret() {
        let signature =
            pgp::packet::signature::SignatureBuilder::from(key.binding_signature().clone())
                .set_signature_creation_time(
                    key.binding_signature().signature_creation_time().unwrap(),
                )
                .unwrap()
                .set_key_validity_period(None)
                .unwrap()
                .sign_subkey_binding(&mut primary, cert.primary_key().key(), key.key())
                .unwrap();
        packets.extend([
            Packet::SecretSubkey(key.key().clone()),
            Packet::Signature(signature),
        ]);
    }
    Cert::from_packets(packets.into_iter()).unwrap()
}

#[test]
fn frozen_quorum_remains_eligible_for_future_encryption() {
    let bundle =
        ImportedV0::from_json(&std::fs::read_to_string(fixture("imported.json")).unwrap()).unwrap();
    let cert = Cert::from_bytes(bundle.recovery().public_key).unwrap();
    let policy = StandardPolicy::new();
    // 2100-01-01: exercise the production recipient filter after the old expiry.
    let future = std::time::UNIX_EPOCH + std::time::Duration::from_secs(4_102_444_800);
    let keys: Vec<_> = cert
        .keys()
        .with_policy(&policy, future)
        .supported()
        .alive()
        .revoked(false)
        .collect();
    assert_eq!(keys.len(), cert.keys().count());
    assert!(keys.iter().all(|key| key.key_expiration_time().is_none()));
    let recipients: Vec<_> = cert
        .keys()
        .with_policy(&policy, future)
        .supported()
        .alive()
        .revoked(false)
        .for_storage_encryption()
        .collect();
    assert!(!recipients.is_empty());
    let mut ciphertext = Vec::new();
    let encrypted = Encryptor2::for_recipients(Message::new(&mut ciphertext), recipients)
        .build()
        .unwrap();
    let mut literal = LiteralWriter::new(encrypted).build().unwrap();
    literal.write_all(b"future encryption").unwrap();
    literal.finalize().unwrap();
}

#[test]
#[ignore = "explicit fixture regeneration only; generated private keys are public test data"]
fn generate_fixture() {
    let certs: Vec<_> = ["Alice V0 public TEST KEY", "Bob V0 public TEST KEY"]
        .into_iter()
        .map(|name| {
            CertBuilder::new()
                .set_creation_time(
                    std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
                )
                .add_userid(name)
                .add_signing_subkey()
                .add_storage_encryption_subkey()
                .add_authentication_subkey()
                .generate()
                .unwrap()
                .0
        })
        .collect();
    std::fs::create_dir_all(fixture("")).unwrap();
    for (name, cert) in ["alice", "bob"].iter().zip(&certs) {
        std::fs::write(
            fixture(&[name, ".private.asc"].concat()),
            cert.as_tsk().armored().to_vec().unwrap(),
        )
        .unwrap();
    }
    let mut keyring = pgp::armor::Writer::new(Vec::new(), pgp::armor::Kind::PublicKey).unwrap();
    for cert in &certs {
        cert.serialize(&mut keyring).unwrap();
    }
    let keyring = String::from_utf8(keyring.finalize().unwrap()).unwrap();
    let mut shards = Vec::new();
    OpenPGP
        .shard_and_encrypt(2, 2, &[7; 32], certs.as_slice(), &mut shards)
        .unwrap();
    let quorum = derived_key([7; 32]);
    let original = OriginalV0 {
        label: HashMap::from([("name".into(), "Frozen V0 test fixture".into())]),
        keyring_hash: Sha256::digest(keyring.as_bytes()).to_vec(),
        keyring,
        shardfile: String::from_utf8(shards).unwrap(),
        public_key: String::from_utf8(quorum.armored().to_vec().unwrap()).unwrap(),
        necroproof: vec![],
    };
    std::fs::write(
        fixture("bundle.json"),
        serde_json::to_vec_pretty(&original).unwrap(),
    )
    .unwrap();
    let policy = StandardPolicy::new();
    let recipients = quorum
        .keys()
        .with_policy(&policy, None)
        .for_storage_encryption();
    let mut ciphertext = Vec::new();
    let armored = Armorer::new(Message::new(&mut ciphertext)).build().unwrap();
    let encrypted = Encryptor2::for_recipients(armored, recipients)
        .build()
        .unwrap();
    let mut literal = LiteralWriter::new(encrypted).build().unwrap();
    literal.write_all(b"encrypted before V0 import").unwrap();
    literal.finalize().unwrap();
    std::fs::write(fixture("pre-import.asc"), ciphertext).unwrap();
    let imported = imported();
    std::fs::write(
        fixture("imported.json"),
        serde_json::to_vec_pretty(&imported).unwrap(),
    )
    .unwrap();
}

#[test]
fn frozen_import_preserves_material_and_identity_without_reconstructing() {
    let a = imported();
    let b = import(
        &std::fs::read_to_string(fixture("bundle.json")).unwrap(),
        Some(&fixture("bob.private.asc")),
        None,
        prompt(),
    )
    .unwrap();
    let original: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture("bundle.json")).unwrap()).unwrap();
    let frozen =
        ImportedV0::from_json(&std::fs::read_to_string(fixture("imported.json")).unwrap()).unwrap();
    assert_eq!(a.content_hash().unwrap(), b.content_hash().unwrap());
    assert_eq!(a.content_hash().unwrap(), frozen.content_hash().unwrap());
    assert_eq!(serde_json::to_value(&a).unwrap()["original"], original);
    assert_eq!(a.recovery().threshold, 2);
    let text = serde_json::to_string(&a).unwrap();
    assert!(!text.contains("bundle_id"));
    assert!(!text.contains("PRIVATE KEY"));
    assert!(crate::bundle::load_recovery_json(&text, None, false).is_err());
    let (loaded, at) = crate::bundle::load_recovery_json(&text, None, true).unwrap();
    assert!(at.is_none());
    assert!(loaded.bundle_id().is_none());
}

#[test]
fn reject_raw_v1_malformed_and_inconsistent_bundles_without_panics() {
    for text in [
        "{}",
        "null",
        "[]",
        r#"{"data":{"version":"V1"},"necroproof":[]}"#,
    ] {
        assert!(import(text, None, None, prompt()).is_err());
        assert!(crate::bundle::load_recovery_json(text, None, true).is_err());
    }
    let source = std::fs::read_to_string(fixture("bundle.json")).unwrap();
    assert!(crate::bundle::load_recovery_json(&source, None, true).is_err());
    let mut raw: serde_json::Value = serde_json::from_str(&source).unwrap();
    raw["keyring_hash"] = serde_json::json!([0]);
    assert!(import_candidates(&raw.to_string()).is_err());
    let stale = include_str!("../../../bundle-2-of-4.json");
    assert!(
        import_candidates(stale)
            .unwrap_err()
            .to_string()
            .contains("checksum mismatch")
    );
    for bytes in [vec![], vec![1], vec![9, 2], vec![1, 2]] {
        assert!(metadata(&bytes).is_err());
    }
    for text in ["", "garbage", &imported().original.public_key] {
        assert!(messages(text).is_err());
    }
    let mut raw: serde_json::Value = serde_json::from_str(&source).unwrap();
    raw["shardfile"] = serde_json::json!("");
    assert!(import_candidates(&raw.to_string()).is_err());
}

#[test]
fn imported_metadata_is_rechecked_before_software_release() {
    let good = imported();
    let private = Cert::from_file(fixture("alice.private.asc")).unwrap();
    assert_eq!(
        decrypt_share(good.recovery(), &private, 0, prompt())
            .unwrap()
            .0[0],
        1
    );
    let mut changed = good.clone();
    changed.threshold = 1;
    changed.validate().unwrap(); // Public validation deliberately cannot authenticate encrypted metadata.
    assert!(decrypt_share(changed.recovery(), &private, 0, prompt()).is_err());
    let mut changed = good.clone();
    changed.keyring.reverse();
    assert!(decrypt_share(changed.recovery(), &private, 0, prompt()).is_err());
    let mut changed = good.clone();
    changed.keyring[1] = changed.keyring[0].clone();
    assert!(changed.validate().is_err());
    let outsider = crate::client::tests::holder();
    assert!(decrypt_share(good.recovery(), &outsider, 0, prompt()).is_err());
    let file = PrivateKeyFile::new(&[&outsider]);
    assert!(
        import(
            &serde_json::to_string(&good.original).unwrap(),
            Some(&file.0),
            None,
            prompt()
        )
        .is_err()
    );
}

pub(crate) fn decrypt_pre_import(entropy: [u8; 32]) -> Vec<u8> {
    decrypt_ciphertext(&fixture("pre-import.asc"), entropy)
}

pub(crate) fn decrypt_ciphertext(path: &std::path::Path, entropy: [u8; 32]) -> Vec<u8> {
    let message = EncryptedMessage::from_reader(std::fs::File::open(path).unwrap())
        .unwrap()
        .remove(0);
    crate::openpgp::legacy_decrypt::decrypt(&message, &derived_key(entropy), None, prompt())
        .unwrap()
}
