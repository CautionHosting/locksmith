use super::*;
use openpgp::{cert::prelude::*, serialize::SerializeInto};
use std::time::{Duration, SystemTime};

fn holder(signing: bool, authentication: bool, encryption: bool) -> Cert {
    let mut builder = CertBuilder::new()
        .set_creation_time(SystemTime::now() - Duration::from_secs(120))
        .add_userid("Keymaker regression holder");
    if signing {
        builder = builder.add_signing_subkey();
    }
    if authentication {
        builder = builder.add_authentication_subkey();
    }
    if encryption {
        builder = builder.add_storage_encryption_subkey();
    }
    builder.generate().unwrap().0
}

fn entry(cert: &Cert) -> v1::Key {
    v1::Key::OpenPGP {
        cert: String::from_utf8(cert.armored().to_vec().unwrap()).unwrap(),
    }
}

fn request(keys: Vec<v1::Key>) -> v1::GenerateQuorumRequest {
    v1::GenerateQuorumRequest {
        bundle_id: [3; 16],
        label: [("name".into(), "test".into())].into(),
        threshold: 1,
        max: keys.len() as u8,
        keyring: keys,
    }
}

#[test]
fn rejects_invalid_quorum_parameters() {
    for (threshold, max, count) in [(0, 1, 1), (2, 1, 1), (1, 2, 1), (1, 0, 0), (1, 255, 255)] {
        let mut r = request(vec![
            v1::Key::OpenPGP {
                cert: String::new()
            };
            count
        ]);
        r.threshold = threshold;
        r.max = max;
        assert!(matches!(
            validate_request(&r).unwrap_err().kind,
            GenerateQuorumErrorKind::InvalidQuorumParameters
        ));
    }
}

#[test]
fn rejects_ineligible_and_multiple_certificates() {
    for capabilities in [
        (false, true, true),
        (true, false, true),
        (true, true, false),
    ] {
        let cert = holder(capabilities.0, capabilities.1, capabilities.2);
        assert!(validate_request(&request(vec![entry(&cert)])).is_err());
    }
    let first = holder(true, true, true);
    let second = holder(true, true, true);
    let mut combined =
        openpgp::armor::Writer::new(Vec::new(), openpgp::armor::Kind::PublicKey).unwrap();
    first.serialize(&mut combined).unwrap();
    second.serialize(&mut combined).unwrap();
    for cert in [
        String::new(),
        "malformed".into(),
        String::from_utf8(combined.finalize().unwrap()).unwrap(),
        String::from_utf8(first.as_tsk().armored().to_vec().unwrap()).unwrap(),
    ] {
        assert!(
            validate_request(&request(vec![entry(&first), v1::Key::OpenPGP { cert }])).is_err()
        );
    }
    assert!(validate_request(&request(vec![entry(&first), entry(&first)])).is_err());
}

#[test]
fn rejects_expired_and_revoked_certificates() {
    let (expired, _) = CertBuilder::new()
        .set_creation_time(SystemTime::now() - Duration::from_secs(120))
        .set_validity_period(Duration::from_secs(1))
        .add_signing_subkey()
        .add_authentication_subkey()
        .add_storage_encryption_subkey()
        .generate()
        .unwrap();
    let cert = holder(true, true, true);
    let mut signer = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .unwrap()
        .into_keypair()
        .unwrap();
    let revocation = cert
        .revoke(
            &mut signer,
            openpgp::types::ReasonForRevocation::KeyCompromised,
            b"test",
        )
        .unwrap();
    let revoked = cert.insert_packets(revocation).unwrap();
    for cert in [expired, revoked] {
        assert!(validate_request(&request(vec![entry(&cert)])).is_err());
    }
}

#[test]
fn rejects_shared_encryption_subkey() {
    let first = holder(true, true, true);
    let second = holder(true, true, false);
    let policy = openpgp::policy::StandardPolicy::new();
    let mut subkey = first
        .keys()
        .subkeys()
        .with_policy(&policy, None)
        .for_storage_encryption()
        .next()
        .unwrap()
        .key()
        .clone()
        .parts_into_public();
    // Changing packet metadata changes the fingerprint, but not who can decrypt.
    subkey
        .set_creation_time(SystemTime::now() - Duration::from_secs(60))
        .unwrap();
    let mut signer = second
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .unwrap()
        .into_keypair()
        .unwrap();
    let binding = subkey
        .bind(
            &mut signer,
            &second,
            openpgp::packet::signature::SignatureBuilder::new(
                openpgp::types::SignatureType::SubkeyBinding,
            )
            .set_key_flags(KeyFlags::empty().set_storage_encryption())
            .unwrap(),
        )
        .unwrap();
    let second = second
        .insert_packets([openpgp::Packet::PublicSubkey(subkey), binding.into()])
        .unwrap();
    let error = validate_request(&request(vec![entry(&first), entry(&second)])).unwrap_err();
    assert!(matches!(
        error.kind,
        GenerateQuorumErrorKind::InvalidCertificate {
            index: 1,
            reason: "holders must not share an encryption key"
        }
    ));
}

#[test]
fn preserves_pgp_and_webauthn_order() {
    let first = holder(true, true, true);
    let second = holder(true, true, true);
    let v1::Key::OpenPGP { cert } = entry(&second) else {
        unreachable!()
    };
    let r = request(vec![
        entry(&first),
        v1::Key::WebAuthn {
            cert,
            credential: vec!["credential-one".into(), "credential-two".into()],
        },
    ]);
    let before = serde_json::to_vec(&r).unwrap();
    let certs = validate_request(&r).unwrap();
    assert_eq!(
        certs.iter().map(Cert::fingerprint).collect::<Vec<_>>(),
        vec![first.fingerprint(), second.fingerprint()]
    );
    assert_eq!(serde_json::to_vec(&r).unwrap(), before);
}

#[test]
fn recognizes_caution_critical_notations() {
    let cert = CertBuilder::new()
        .add_userid("Caution holder")
        .add_authentication_subkey()
        .add_storage_encryption_subkey()
        .add_subkey_with(
            KeyFlags::empty().set_signing(),
            None,
            None,
            openpgp::packet::signature::SignatureBuilder::new(
                openpgp::types::SignatureType::SubkeyBinding,
            )
            .set_notation("organization-id@caution.co", b"organization", None, true)
            .unwrap()
            .set_notation("bundle-id@caution.co", b"bundle", None, true)
            .unwrap(),
        )
        .unwrap()
        .generate()
        .unwrap()
        .0;
    assert!(validate_request(&request(vec![entry(&cert)])).is_ok());
}

#[cfg(not(feature = "selfnuke"))]
#[tokio::test]
async fn invalid_handler_request_returns_400_without_entropy() {
    use axum::response::IntoResponse;
    let r = request(vec![v1::Key::OpenPGP {
        cert: "malformed".into(),
    }]);
    let error = generate_quorum(
        State(Arc::new(AppState::new())),
        Json(GenerateQuorumRequest::V1(r)),
    )
    .await
    .unwrap_err();
    assert_eq!(error.into_response().status(), StatusCode::BAD_REQUEST);
}

#[test]
fn unsafe_hooks_require_feature_and_environment() {
    const CHILD: &str = "KEYMAKER_HOOK_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let enabled = cfg!(feature = "unsafe-e2e")
            && std::env::var("CAUTION_UNSAFE_KEY_SERVICE_E2E").as_deref() == Ok("1");
        let entropy = std::panic::catch_unwind(generate_entropy);
        assert_eq!(
            matches!(entropy, Ok(Ok(value)) if value == [7; 32]),
            enabled
        );
        let proof = generate_necroproof(&[1; 32], &[2; 32]);
        assert_eq!(proof.as_ref().is_ok_and(|proof| proof == &[2; 32]), enabled);
        #[cfg(not(feature = "selfnuke"))]
        if enabled {
            let first = holder(true, true, true);
            let second = holder(true, true, true);
            let v1::Key::OpenPGP { cert } = entry(&second) else {
                unreachable!()
            };
            let r = request(vec![
                entry(&first),
                v1::Key::WebAuthn {
                    cert,
                    credential: vec!["credential".into()],
                },
            ]);
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let Json(response) = runtime
                .block_on(generate_quorum(
                    State(Arc::new(AppState::new())),
                    Json(GenerateQuorumRequest::V1(r.clone())),
                ))
                .unwrap();
            let bundle = response.data.to_latest();
            assert_eq!((bundle.threshold, bundle.max), (r.threshold, r.max));
            assert_eq!(bundle.bundle_id, r.bundle_id);
            assert_eq!(bundle.label, r.label);
            assert_eq!(bundle.keyring, r.keyring);
            assert!(
                !OpenPGP
                    .parse_shard_file(bundle.shardfile.as_bytes())
                    .unwrap()
                    .is_empty()
            );
            assert!(Cert::from_bytes(&bundle.public_key).is_ok());

            // Exercise the handler and real encrypted shares; only the Nitro proof is synthetic.
            let holders: Vec<_> = (0..5).map(|_| holder(true, true, true)).collect();
            let mut r = request(holders.iter().map(entry).collect());
            r.threshold = 3;
            let Json(response) = runtime
                .block_on(generate_quorum(
                    State(Arc::new(AppState::new())),
                    Json(GenerateQuorumRequest::V1(r)),
                ))
                .unwrap();
            let bundle = response.data.to_latest();
            assert_eq!((bundle.threshold, bundle.max), (3, 5));
            let encrypted = OpenPGP
                .parse_shard_file(bundle.shardfile.as_bytes())
                .unwrap();
            let shares: Vec<_> = holders
                .into_iter()
                .map(|holder| {
                    let (share, threshold) = OpenPGP
                        .decrypt_one_shard(
                            Some(vec![holder]),
                            &encrypted,
                            std::rc::Rc::new(std::sync::Mutex::new(Box::new(
                                keyfork_prompt::Headless::new(),
                            ))),
                        )
                        .unwrap();
                    assert_eq!(threshold, bundle.threshold);
                    share
                })
                .collect();
            let sharks = blahaj::Sharks(bundle.threshold);
            // Every pair fails and every triple recovers the test generator's entropy.
            for a in 0..5 {
                for b in a + 1..5 {
                    assert!(sharks.recover([&shares[a], &shares[b]]).is_err());
                    for c in b + 1..5 {
                        assert_eq!(
                            sharks
                                .recover([&shares[a], &shares[b], &shares[c]])
                                .unwrap(),
                            [7; 32]
                        );
                    }
                }
            }
        }
        return;
    }
    for flag in [None, Some(""), Some("0"), Some("1")] {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child
            .args([
                "--exact",
                "routes::generate_quorum::tests::unsafe_hooks_require_feature_and_environment",
            ])
            .env(CHILD, "1")
            .env_remove("CAUTION_UNSAFE_KEY_SERVICE_E2E")
            .env_remove("SHOOT_SELF_IN_FOOT")
            .env_remove("INSECURE_HARDWARE_ALLOWED");
        if let Some(flag) = flag {
            child.env("CAUTION_UNSAFE_KEY_SERVICE_E2E", flag);
        }
        let output = child.output().unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
