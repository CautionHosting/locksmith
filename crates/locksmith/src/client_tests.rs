use super::*;
use sequoia_openpgp::{
    Cert, Packet, armor,
    cert::prelude::*,
    serialize::{Serialize, SerializeInto},
};
use std::{path::PathBuf, rc::Rc, sync::Mutex, time::Duration};

pub(crate) fn holder() -> Cert {
    CertBuilder::new()
        .set_creation_time(SystemTime::now() - Duration::from_secs(120))
        .add_userid("holder selection regression")
        .add_signing_subkey()
        .add_storage_encryption_subkey()
        .generate()
        .unwrap()
        .0
}

pub(crate) fn bundle(holders: &[Cert], threshold: u8) -> v1::GenerateQuorumResponse {
    let mut shardfile = Vec::new();
    OpenPGP
        .shard_and_encrypt(
            threshold,
            holders.len() as u8,
            &[7; 32],
            holders,
            &mut shardfile,
        )
        .unwrap();
    v1::GenerateQuorumResponse {
        bundle_id: [1; 16],
        label: Default::default(),
        threshold,
        max: holders.len() as u8,
        keyring: holders
            .iter()
            .map(|cert| v1::Key::OpenPGP {
                cert: String::from_utf8(cert.armored().to_vec().unwrap()).unwrap(),
            })
            .collect(),
        shardfile: String::from_utf8(shardfile).unwrap(),
        public_key: String::new(),
    }
}

pub(crate) struct PrivateKeyFile(pub(crate) PathBuf);

impl PrivateKeyFile {
    pub(crate) fn new(certs: &[&Cert]) -> Self {
        let dir = std::env::temp_dir().join(format!("locksmith-holder-{}", rand::random::<u128>()));
        std::fs::create_dir(&dir).unwrap();
        let mut armor = armor::Writer::new(Vec::new(), armor::Kind::SecretKey).unwrap();
        for cert in certs {
            cert.as_tsk().serialize(&mut armor).unwrap();
        }
        let path = dir.join("holders.asc");
        std::fs::write(&path, armor.finalize().unwrap()).unwrap();
        Self(path)
    }
}

impl Drop for PrivateKeyFile {
    fn drop(&mut self) {
        std::fs::remove_dir_all(self.0.parent().unwrap()).unwrap();
    }
}

pub(crate) fn prompt() -> Rc<Mutex<Box<dyn keyfork_prompt::PromptHandler>>> {
    Rc::new(Mutex::new(Box::new(keyfork_prompt::Headless::new())))
}

#[test]
fn software_selection_follows_bundle_order_and_signs_the_same_holder() {
    let holders = [holder(), holder()];
    let bundle = bundle(&holders, 2);
    for order in [[&holders[1], &holders[0]], [&holders[0], &holders[1]]] {
        let file = PrivateKeyFile::new(&order);
        let (request, keyring) = decrypt_shard(&bundle, Some(&file.0), prompt()).unwrap();
        assert_eq!(request.shard[0], 1);
        assert_eq!(request.threshold, 2);
        let signature = crate::openpgp::sign(
            &keyring,
            "payload",
            &mut keyfork_prompt::Headless::new(),
            Some(&file.0),
        )
        .unwrap();
        for (index, key) in bundle.keyring.iter().enumerate() {
            let keyring = crate::openpgp::reconstruct_keyring(std::slice::from_ref(key)).unwrap();
            assert_eq!(
                crate::openpgp::verify_detached(&keyring, "payload", &signature).is_ok(),
                index == 0
            );
        }
    }
    let second = PrivateKeyFile::new(&[&holders[1]]);
    assert_eq!(
        decrypt_shard(&bundle, Some(&second.0), prompt())
            .unwrap()
            .0
            .shard[0],
        2
    );
    let single = self::bundle(&holders[1..], 1);
    assert_eq!(
        decrypt_shard(&single, Some(&second.0), prompt())
            .unwrap()
            .0
            .shard[0],
        1
    );
}

#[test]
fn software_selection_requires_both_secret_keys_on_one_holder() {
    let holders = [holder(), holder()];
    let bundle = bundle(&holders, 2);
    let policy = StandardPolicy::new();
    let signing = holders[0]
        .keys()
        .with_policy(&policy, None)
        .for_signing()
        .next()
        .unwrap()
        .fingerprint();
    let decryption_only = Cert::from_packets(
        holders[0]
            .as_tsk()
            .into_packets()
            .map(|packet| match packet {
                Packet::SecretSubkey(key) if key.fingerprint() == signing => {
                    Packet::PublicSubkey(key.take_secret().0)
                }
                packet => packet,
            })
            .collect::<Vec<_>>()
            .into_iter(),
    )
    .unwrap();
    let file = PrivateKeyFile::new(&[&decryption_only]);
    assert!(matches!(
        decrypt_shard(&bundle, Some(&file.0), prompt())
            .unwrap_err()
            .kind,
        SendShardErrorKind::NoMatchingHolderKeys
    ));
    let file = PrivateKeyFile::new(&[&decryption_only, &holders[1]]);
    assert_eq!(
        decrypt_shard(&bundle, Some(&file.0), prompt())
            .unwrap()
            .0
            .shard[0],
        2
    );
    let outsider = PrivateKeyFile::new(&[&holder()]);
    assert!(matches!(
        decrypt_shard(&bundle, Some(&outsider.0), prompt())
            .unwrap_err()
            .kind,
        SendShardErrorKind::NoMatchingHolderKeys
    ));
}

#[test]
fn signing_is_scoped_to_the_decrypted_coordinate() {
    let bundle = bundle(&[holder(), holder()], 2);
    let mut request = models::SendShardRequest {
        shard: vec![1; 33],
        threshold: 2,
    };
    request.shard[0] = 2;
    let keyring = signing_keyring(&bundle, &request, None).unwrap();
    assert_eq!(
        keyring,
        crate::openpgp::reconstruct_keyring(&bundle.keyring[1..]).unwrap()
    );
    assert!(matches!(
        signing_keyring(&bundle, &request, Some(0))
            .unwrap_err()
            .kind,
        SendShardErrorKind::ShareHolderMismatch
    ));
    request.threshold = 1;
    assert!(matches!(
        signing_keyring(&bundle, &request, None).unwrap_err().kind,
        SendShardErrorKind::ShareThresholdMismatch
    ));
    request.threshold = 2;
    for shard in [vec![], vec![0; 33], vec![3; 33], vec![1; 32], vec![1; 34]] {
        request.shard = shard;
        assert!(matches!(
            signing_keyring(&bundle, &request, None).unwrap_err().kind,
            SendShardErrorKind::ShareHolderMismatch
        ));
    }
}
