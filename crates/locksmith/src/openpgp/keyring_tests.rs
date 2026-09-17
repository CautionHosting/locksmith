use super::*;
use crate::openpgp::{sign, verify_detached};
use keymaker_models::{
    Proofed,
    generate_quorum::{GenerateQuorumBundle, deterministic_bundle_hash, v1},
};
use sequoia_openpgp::{Cert, cert::prelude::*, serialize::SerializeInto};
use std::{
    path::PathBuf,
    time::{Duration, SystemTime},
};

fn holder() -> Cert {
    CertBuilder::new()
        .set_creation_time(SystemTime::now() - Duration::from_secs(120))
        .add_userid("Locksmith test holder")
        .add_signing_subkey()
        .add_transport_encryption_subkey()
        .generate()
        .unwrap()
        .0
}

fn entry(cert: &Cert) -> Key {
    Key::OpenPGP {
        cert: String::from_utf8(cert.armored().to_vec().unwrap()).unwrap(),
    }
}

fn fingerprints(keyring: &str) -> Vec<sequoia_openpgp::Fingerprint> {
    CertParser::from_bytes(keyring)
        .unwrap()
        .map(|cert| cert.unwrap().fingerprint())
        .collect()
}

struct PrivateKeyFile(PathBuf);

impl PrivateKeyFile {
    fn new(cert: &Cert) -> Self {
        let dir = std::env::temp_dir().join(rand::random::<u128>().to_string());
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("holder.asc");
        std::fs::write(&path, cert.as_tsk().armored().to_vec().unwrap()).unwrap();
        Self(path)
    }
}

impl Drop for PrivateKeyFile {
    fn drop(&mut self) {
        std::fs::remove_dir_all(self.0.parent().unwrap()).unwrap();
    }
}

// Unencrypted software test keys must never need user interaction.
struct NoPrompt;

impl keyfork_prompt::PromptHandler for NoPrompt {
    fn prompt_input(&mut self, _: &str) -> keyfork_prompt::Result<String> {
        panic!("unexpected prompt")
    }
    fn prompt_wordlist(&mut self, _: &str, _: &[&str]) -> keyfork_prompt::Result<String> {
        panic!("unexpected prompt")
    }
    fn prompt_passphrase(&mut self, _: &str) -> keyfork_prompt::Result<String> {
        panic!("unexpected prompt")
    }
    fn prompt_message(&mut self, _: keyfork_prompt::Message) -> keyfork_prompt::Result<()> {
        panic!("unexpected prompt")
    }
    fn prompt_choice_num(
        &mut self,
        _: &str,
        _: &[Box<dyn keyfork_prompt::Choice>],
    ) -> keyfork_prompt::Result<usize> {
        panic!("unexpected prompt")
    }
    fn prompt_validated_wordlist(
        &mut self,
        _: &str,
        _: u8,
        _: &[&str],
        _: &mut dyn FnMut(String) -> keyfork_prompt::BoxResult,
    ) -> keyfork_prompt::Result<()> {
        panic!("unexpected prompt")
    }
    fn prompt_validated_passphrase(
        &mut self,
        _: &str,
        _: u8,
        _: &mut dyn FnMut(String) -> keyfork_prompt::BoxResult,
    ) -> keyfork_prompt::Result<()> {
        panic!("unexpected prompt")
    }
}

#[test]
fn every_holder_can_sign_and_be_verified() {
    let holders = [holder(), holder()];
    let keys = holders.iter().map(entry).collect::<Vec<_>>();
    let keyring = reconstruct_keyring(&keys).unwrap();
    assert_eq!(
        keyring
            .matches("-----BEGIN PGP PUBLIC KEY BLOCK-----")
            .count(),
        1
    );
    assert_eq!(
        fingerprints(&keyring),
        holders.iter().map(Cert::fingerprint).collect::<Vec<_>>()
    );
    assert_eq!(
        rpgpie::certificate::Certificate::load(&mut std::io::Cursor::new(&keyring))
            .unwrap()
            .len(),
        holders.len()
    );
    let payload = r#"{"encrypted_payload":"test","public_key":[1,2,3]}"#;
    for cert in &holders {
        let private_key = PrivateKeyFile::new(cert);
        let signature = sign(&keyring, payload, &mut NoPrompt, Some(&private_key.0)).unwrap();
        verify_detached(&keyring, payload, &signature).unwrap();
        assert!(verify_detached(&keyring, "modified payload", &signature).is_err());
    }
    let outsider = holder();
    let private_key = PrivateKeyFile::new(&outsider);
    let outsider_keyring = reconstruct_keyring(&[entry(&outsider)]).unwrap();
    let signature = sign(
        &outsider_keyring,
        payload,
        &mut NoPrompt,
        Some(&private_key.0),
    )
    .unwrap();
    assert!(verify_detached(&keyring, payload, &signature).is_err());
}

#[test]
fn single_holder_and_legacy_combined_entry_preserve_certificates() {
    let first = holder();
    let second = holder();
    assert_eq!(
        fingerprints(&reconstruct_keyring(&[entry(&first)]).unwrap()),
        vec![first.fingerprint()]
    );

    // Build a legacy, single armor block containing multiple certificates independently.
    let mut armor = armor::Writer::new(Vec::new(), armor::Kind::PublicKey).unwrap();
    first.serialize(&mut armor).unwrap();
    second.serialize(&mut armor).unwrap();
    let legacy = Key::OpenPGP {
        cert: String::from_utf8(armor.finalize().unwrap()).unwrap(),
    };
    let keyring = reconstruct_keyring(&[legacy]).unwrap();
    assert_eq!(
        fingerprints(&keyring),
        vec![first.fingerprint(), second.fingerprint()]
    );
    let private_key = PrivateKeyFile::new(&second);
    let signature = sign(
        &keyring,
        "legacy payload",
        &mut NoPrompt,
        Some(&private_key.0),
    )
    .unwrap();
    verify_detached(&keyring, "legacy payload", &signature).unwrap();
}

#[test]
fn malformed_and_unsupported_entries_fail_without_partial_keyring() {
    use ReconstructKeyringErrorKind as Kind;
    let first = entry(&holder());
    assert_eq!(
        reconstruct_keyring(&[]).unwrap_err().kind,
        Kind::EmptyKeyring
    );
    for cert in ["", " \n\t"] {
        assert_eq!(
            reconstruct_keyring(&[first.clone(), Key::OpenPGP { cert: cert.into() }])
                .unwrap_err()
                .kind,
            Kind::EmptyEntry(1)
        );
    }
    assert_eq!(
        reconstruct_keyring(&[
            first.clone(),
            Key::OpenPGP {
                cert: "invalid certificate".into()
            }
        ])
        .unwrap_err()
        .kind,
        Kind::ParseEntry(1)
    );
    assert_eq!(
        reconstruct_keyring(&[
            first,
            Key::WebAuthn {
                credential: vec![],
                cert: String::new()
            }
        ])
        .unwrap_err()
        .kind,
        Kind::EmptyEntry(1)
    );
}

#[test]
fn reconstruction_preserves_proofed_bundle_and_hash() {
    let envelope = Proofed {
        data: GenerateQuorumBundle::V1(v1::GenerateQuorumResponse {
            threshold: 2,
            max: 2,
            bundle_id: [7; 16],
            label: Default::default(),
            keyring: vec![entry(&holder()), entry(&holder())],
            shardfile: "unchanged shardfile".into(),
            public_key: "unchanged public key".into(),
        }),
        // Synthetic: this test checks immutability, not attestation validity.
        necroproof: vec![1, 2, 3],
    };
    let before = serde_json::to_vec(&envelope).unwrap();
    let hash = deterministic_bundle_hash(&envelope.data).unwrap();
    let GenerateQuorumBundle::V1(bundle) = &envelope.data;
    reconstruct_keyring(&bundle.keyring).unwrap();
    assert_eq!(serde_json::to_vec(&envelope).unwrap(), before);
    assert_eq!(deterministic_bundle_hash(&envelope.data).unwrap(), hash);
}
