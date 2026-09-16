use super::*;
use keymaker_models::generate_quorum::{GenerateQuorumBundle, v1};
use sequoia_openpgp::{
    armor,
    cert::prelude::*,
    packet::signature::SignatureBuilder,
    serialize::{Serialize, SerializeInto},
    types::{KeyFlags, SignatureType},
};

fn holder() -> Cert {
    CertBuilder::new()
        .set_creation_time(SystemTime::now() - std::time::Duration::from_secs(120))
        .add_userid("recovery test")
        .add_signing_subkey()
        .generate()
        .unwrap()
        .0
}

fn entry(cert: &Cert) -> v1::Key {
    v1::Key::OpenPGP {
        cert: String::from_utf8(cert.armored().to_vec().unwrap()).unwrap(),
    }
}

fn sign(cert: &Cert, data: &str) -> String {
    let mut signer = cert
        .keys()
        .secret()
        .nth(1)
        .unwrap()
        .key()
        .clone()
        .into_keypair()
        .unwrap();
    let signature = SignatureBuilder::new(SignatureType::Binary)
        .sign_message(&mut signer, data)
        .unwrap();
    let mut armor = armor::Writer::new(Vec::new(), armor::Kind::Signature).unwrap();
    sequoia_openpgp::Packet::Signature(signature)
        .serialize(&mut armor)
        .unwrap();
    String::from_utf8(armor.finalize().unwrap()).unwrap()
}

// Independently use the full generation recipe (including all subkeys).
fn generated_public_key(entropy: [u8; 32]) -> Cert {
    use keyfork_derive_openpgp::{XPrv, derive_util::DerivationIndex};
    let seed = keyfork_mnemonic::Mnemonic::from_array(entropy).generate_seed(None);
    let path = keyfork_derive_path_data::paths::OPENPGP
        .clone()
        .chain_push(DerivationIndex::new(0, true).unwrap());
    let key = XPrv::new(seed).unwrap().derive_path(&path).unwrap();
    keyfork_derive_openpgp::derive(
        &key,
        &[
            KeyFlags::empty().set_certification(),
            KeyFlags::empty().set_signing(),
            KeyFlags::empty()
                .set_transport_encryption()
                .set_storage_encryption(),
            KeyFlags::empty().set_authentication(),
        ],
        &sequoia_openpgp::packet::UserID::from("Keymaker-generated key"),
    )
    .unwrap()
}

fn bundle(keys: Vec<v1::Key>, threshold: u8) -> QuorumBundle {
    GenerateQuorumBundle::V1(v1::GenerateQuorumResponse {
        threshold,
        max: keys.len() as u8,
        keyring: keys,
        bundle_id: [1; 16],
        label: Default::default(),
        shardfile: String::new(),
        public_key: String::from_utf8(generated_public_key([7; 32]).armored().to_vec().unwrap())
            .unwrap(),
    })
}

#[test]
fn signatures_identify_one_holder_and_reject_ambiguous_identity() {
    let first = holder();
    let second = holder();
    let recovery = Recovery::new(&bundle(vec![entry(&first), entry(&second)], 2)).unwrap();
    for (index, cert) in [&first, &second].into_iter().enumerate() {
        let signature = sign(cert, "payload");
        assert_eq!(
            authenticate_holder(&recovery.keyrings, "payload", &signature).unwrap(),
            index
        );
        assert!(authenticate_holder(&recovery.keyrings, "tampered", &signature).is_err());
    }
    let signature = sign(&holder(), "payload");
    assert!(authenticate_holder(&recovery.keyrings, "payload", &signature).is_err());
    let repeated = Recovery::new(&bundle(vec![entry(&first), entry(&first)], 2)).unwrap();
    assert!(authenticate_holder(&repeated.keyrings, "payload", &sign(&first, "payload")).is_err());
}

#[tokio::test]
async fn invalid_bundles_fail_before_binding() {
    let unsupported = bundle(
        vec![v1::Key::WebAuthn {
            credential: vec![],
            cert: String::new(),
        }],
        1,
    );
    // An occupied address ensures a BundleAccess failure precedes any bind attempt.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let error = receive_shards(listener.local_addr().unwrap(), &unsupported)
        .await
        .unwrap_err();
    assert!(matches!(error.kind, ReceiveShardsErrorKind::BundleAccess));
    assert!(
        std::error::Error::source(&error)
            .unwrap()
            .to_string()
            .contains("UnsupportedWebAuthn")
    );
    for threshold in [0, 2] {
        assert!(matches!(
            Recovery::new(&bundle(vec![entry(&holder())], threshold)),
            Err(ReceiveShardsError {
                kind: ReceiveShardsErrorKind::InvalidQuorum,
                ..
            })
        ));
    }
}

async fn submit(
    tx: &tokio::sync::mpsc::Sender<Payload>,
    rx: &mut tokio::sync::broadcast::Receiver<ReconstitutionStatus>,
    holder: usize,
    threshold: u8,
    shard: Vec<u8>,
) -> models::SendSignedEncryptedShardResponse {
    let request_stub = RequestStub::new();
    tx.send(Payload {
        holder,
        request_stub,
        request: models::SendShardRequest { threshold, shard },
    })
    .await
    .unwrap();
    let status = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status.request_stub, request_stub);
    status.response
}

#[tokio::test]
async fn recovery_counts_only_distinct_valid_contributions() {
    use models::SendSignedEncryptedShardResponse::{Accepted, Rejected};
    let recovery = Recovery {
        threshold: 3,
        keyrings: Arc::new(vec![String::new(); 5]),
        public_key: generated_public_key([7; 32]).fingerprint(),
    };
    let shares: Vec<_> = Sharks(3)
        .dealer(&[7; 32])
        .take(5)
        .map(|s| Vec::from(&s))
        .collect();
    let (tx, rx) = tokio::sync::mpsc::channel(10);
    let (status_tx, mut status_rx) = tokio::sync::broadcast::channel(10);
    let task = tokio::spawn(async move { reconstitute_shards(rx, status_tx, &recovery).await });
    assert!(matches!(
        submit(&tx, &mut status_rx, 0, 1, shares[0].clone()).await,
        Rejected { .. }
    ));
    for bad in [vec![], vec![1; 32], vec![1; 34], vec![0; 33]] {
        assert!(matches!(
            submit(&tx, &mut status_rx, 0, 3, bad).await,
            Rejected { .. }
        ));
    }
    assert!(matches!(
        submit(&tx, &mut status_rx, 0, 3, shares[0].clone()).await,
        Accepted { remaining: 2 }
    ));
    assert!(matches!(
        submit(&tx, &mut status_rx, 0, 3, shares[1].clone()).await,
        Rejected { .. }
    ));
    assert!(matches!(
        submit(&tx, &mut status_rx, 1, 3, shares[0].clone()).await,
        Rejected { .. }
    ));
    assert!(matches!(
        submit(&tx, &mut status_rx, 1, 3, shares[1].clone()).await,
        Accepted { remaining: 1 }
    ));
    assert!(!task.is_finished(), "two shares must not complete recovery");
    assert!(matches!(
        submit(&tx, &mut status_rx, 2, 3, shares[2].clone()).await,
        Accepted { remaining: 0 }
    ));
    assert_eq!(task.await.unwrap().unwrap(), [7; 32]);
}

#[tokio::test]
async fn incorrect_reconstructed_entropy_is_rejected() {
    let recovery = Recovery {
        threshold: 1,
        keyrings: Arc::new(vec![String::new()]),
        public_key: generated_public_key([7; 32]).fingerprint(),
    };
    let shard = Vec::from(&Sharks(1).dealer(&[8; 32]).next().unwrap());
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    let (status_tx, mut status_rx) = tokio::sync::broadcast::channel(1);
    let task = tokio::spawn(async move { reconstitute_shards(rx, status_tx, &recovery).await });
    assert!(matches!(
        submit(&tx, &mut status_rx, 0, 1, shard).await,
        models::SendSignedEncryptedShardResponse::Rejected { .. }
    ));
    assert!(matches!(
        task.await.unwrap().unwrap_err().kind,
        ReceiveShardsErrorKind::RecoveredKeyMismatch
    ));
}
