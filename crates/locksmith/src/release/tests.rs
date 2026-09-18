use super::*;
use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};

#[test]
fn signed_live_evidence_enforces_freshness() {
    let proof = include_bytes!("../../tests/data/aws-test.cbor");
    let measurements = HashMap::from([
        (0, smex::decode_to_vec("ef093e4c1fd13878956589833c0e396b935cdf5ae45c1cc595e1a19a6da5812850f0ef3e77df918cb2a86d88ddf9cc03").unwrap()),
        (1, smex::decode_to_vec("ef093e4c1fd13878956589833c0e396b935cdf5ae45c1cc595e1a19a6da5812850f0ef3e77df918cb2a86d88ddf9cc03").unwrap()),
        (2, smex::decode_to_vec("21b9efbc184807662e966d34f390821309eeac6802309798826296bf3e8bec7c10edb30948c90ba67310f7b964fc500a").unwrap()),
    ]);
    let nonce =
        smex::decode_to_vec("d041b23bce8678bbc7c174bd8494c4f9759386eec963ec69bfd45c1452b10636")
            .unwrap();
    let generated = Duration::from_millis(1766509563435);
    for at in [
        generated,
        generated + TTL,
        generated - Duration::from_secs(60),
    ] {
        assert!(verify_live_at(proof, measurements.clone(), &nonce, at).is_ok());
    }
    // Both clocks remain inside the fixture's certificate-validity window after
    // Bootproof's existing skew allowance, so freshness must be the rejecting check.
    for at in [
        generated + TTL + Duration::from_millis(1),
        generated - Duration::from_millis(60_001),
    ] {
        let error = verify_live_at(proof, measurements.clone(), &nonce, at).unwrap_err();
        assert_eq!(error.kind, "stale or future Nitro evidence");
    }
    assert!(verify_live_at(proof, measurements, &[1; 32], generated).is_err());
}

fn fixture(uv: bool) -> (Authorizer, WebauthnAuthenticator<SoftPasskey>, SecurityKey) {
    let origin = Url::parse("https://example.com").unwrap();
    let webauthn = WebauthnBuilder::new("example.com", &origin)
        .unwrap()
        .build()
        .unwrap();
    let mut device = WebauthnAuthenticator::new(SoftPasskey::new(uv));
    let (options, state) = webauthn
        .start_securitykey_registration(Uuid::new_v4(), "alice", "Alice", None, None, None)
        .unwrap();
    let response = device.do_registration(origin, options).unwrap();
    let credential = webauthn
        .finish_securitykey_registration(&response, &state)
        .unwrap();
    let (ca, _) = sequoia_openpgp::cert::CertBuilder::general_purpose(None, Some("test CA"))
        .generate()
        .unwrap();
    let auth = Authorizer {
        webauthn,
        keymaker_policy: KeymakerPcrPolicy { sets: vec![] },
        ca,
        pending: Mutex::new(HashMap::new()),
        quotas: Arc::default(),
    };
    (auth, device, credential)
}
fn ready(auth: &Authorizer, credential: &SecurityKey) -> (String, RequestChallengeResponse) {
    let (mut options, state) = auth
        .webauthn
        .start_securitykey_authentication(&[credential.clone()])
        .unwrap();
    options.public_key.user_verification = webauthn_rs_proto::UserVerificationPolicy::Required;
    let session = random_nonce();
    let context = Context {
        version: Version::V1,
        bundle_hash: "hash".into(),
        bundle_id: [1; 16],
        organization_id: [2; 16],
        holder: "fingerprint".into(),
        holder_position: 0,
        certificate_index: 0,
        destination_policy: Measurements::new(),
        transport_nonce: random_nonce(),
        expires_at_unix_seconds: now().unwrap().as_secs() + 180,
    };
    let bundle = v1::GenerateQuorumResponse {
        bundle_id: [1; 16],
        label: HashMap::new(),
        keyring: vec![],
        threshold: 1,
        max: 1,
        shardfile: String::new(),
        public_key: String::new(),
    };
    let reservation = auth
        .reserve(&session, &context, Instant::now() + TTL)
        .unwrap();
    auth.pending.lock().unwrap().insert(
        session.clone(),
        Pending {
            _reservation: reservation,
            deadline: Instant::now() + TTL,
            context,
            bundle,
            credentials: vec![credential.clone()],
            prepared: Some((state, [3; 32])),
        },
    );
    (session, options)
}
fn assertion(
    device: &mut WebauthnAuthenticator<SoftPasskey>,
    options: RequestChallengeResponse,
) -> PublicKeyCredential {
    device
        .do_authentication(Url::parse("https://example.com").unwrap(), options)
        .unwrap()
}
#[test]
fn verified_uv_and_single_use_are_required() {
    for uv in [false, true] {
        let (auth, mut device, credential) = fixture(uv);
        let (session, mut options) = ready(&auth, &credential);
        if !uv {
            options.public_key.user_verification =
                webauthn_rs_proto::UserVerificationPolicy::Preferred;
        }
        let assertion = assertion(&mut device, options);
        let value = serde_json::to_value(&assertion).unwrap();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let result = auth.complete::<()>(
            CompleteRequest {
                version: Version::V1,
                session_id: session.clone(),
                assertion,
            },
            |_, _, _| {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            },
        );
        assert_eq!(result.is_ok(), uv, "{result:?}");
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            usize::from(uv)
        );
        assert!(
            auth.complete::<()>(
                CompleteRequest {
                    version: Version::V1,
                    session_id: session,
                    assertion: serde_json::from_value(value).unwrap()
                },
                |_, _, _| panic!("replay reached derivation")
            )
            .is_err()
        );
    }
}
#[test]
fn expiration_and_wrong_challenge_never_derive() {
    let (auth, mut device, credential) = fixture(true);
    let (session, options) = ready(&auth, &credential);
    auth.pending
        .lock()
        .unwrap()
        .get_mut(&session)
        .unwrap()
        .deadline = Instant::now() - Duration::from_secs(1);
    let response = assertion(&mut device, options);
    assert!(
        auth.complete::<()>(
            CompleteRequest {
                version: Version::V1,
                session_id: session,
                assertion: response
            },
            |_, _, _| panic!("expired derivation")
        )
        .is_err()
    );
    let (session, _) = ready(&auth, &credential);
    let (_, other) = ready(&auth, &credential);
    let response = assertion(&mut device, other);
    assert!(
        auth.complete::<()>(
            CompleteRequest {
                version: Version::V1,
                session_id: session,
                assertion: response
            },
            |_, _, _| panic!("substituted challenge derivation")
        )
        .is_err()
    );
}
#[test]
fn wrong_credential_and_tampered_assertion_never_derive() {
    let (auth, mut device, credential) = fixture(true);
    let (_, mut stranger, stranger_credential) = fixture(true);
    for tampered in [false, true] {
        let (session, options) = ready(&auth, &credential);
        let response = if tampered {
            let response = assertion(&mut device, options);
            let mut value = serde_json::to_value(response).unwrap();
            value["response"]["signature"] = serde_json::json!("AAAA");
            serde_json::from_value(value).unwrap()
        } else {
            let mut options = options;
            options.public_key.allow_credentials[0].id =
                stranger_credential.cred_id().clone().into();
            assertion(&mut stranger, options)
        };
        assert!(
            auth.complete::<()>(
                CompleteRequest {
                    version: Version::V1,
                    session_id: session,
                    assertion: response,
                },
                |_, _, _| panic!("invalid assertion reached derivation")
            )
            .is_err()
        );
    }
}
#[test]
fn concurrent_completion_derives_once() {
    let (auth, mut device, credential) = fixture(true);
    let (session, options) = ready(&auth, &credential);
    let assertion = serde_json::to_string(&assertion(&mut device, options)).unwrap();
    let count = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let auth = &auth;
            let count = &count;
            let session = &session;
            let assertion = &assertion;
            scope.spawn(move || {
                let _ = auth.complete::<()>(
                    CompleteRequest {
                        version: Version::V1,
                        session_id: session.clone(),
                        assertion: serde_json::from_str(assertion).unwrap(),
                    },
                    |_, _, _| {
                        count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        Ok(())
                    },
                );
            });
        }
    });
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
}
#[test]
fn measurement_policy_requires_all_non_debug_slots() {
    let mut policy = Measurements::from([
        (0, "ab".repeat(48)),
        (1, "ab".repeat(48)),
        (2, "ab".repeat(48)),
    ]);
    assert!(pcrs(&policy).is_ok());
    policy.insert(2, "00".repeat(48));
    assert!(pcrs(&policy).is_err());
    policy.remove(&2);
    assert!(pcrs(&policy).is_err());
}

#[test]
fn synthetic_live_proofs_require_all_gates() {
    const CHILD: &str = "LOCKSMITH_RELEASE_PROOF_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let nonce = random_nonce();
        let mut proof = b"caution-release-test-v1:".to_vec();
        proof.extend(serde_json::to_vec(&(&nonce, vec![8u8; 32])).unwrap());
        let policy = Measurements::from([
            (0, "ab".repeat(48)),
            (1, "ab".repeat(48)),
            (2, "ab".repeat(48)),
        ]);
        let enabled = cfg!(feature = "unsafe-e2e")
            && std::env::var("CAUTION_UNSAFE_KEY_SERVICE_E2E").as_deref() == Ok("1");
        assert_eq!(verify_live(&proof, &policy, &nonce).is_ok(), enabled);
        assert!(verify_live(&proof, &policy, &random_nonce()).is_err());
        let mut wrong = policy.clone();
        wrong.insert(0, "ac".repeat(48));
        assert!(verify_live(&proof, &wrong, &nonce).is_err());
        return;
    }
    for value in [None, Some("0"), Some("1")] {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child
            .args([
                "--exact",
                "release::tests::synthetic_live_proofs_require_all_gates",
            ])
            .env(CHILD, "1")
            .env_remove("CAUTION_UNSAFE_KEY_SERVICE_E2E");
        if let Some(value) = value {
            child.env("CAUTION_UNSAFE_KEY_SERVICE_E2E", value);
        }
        let output = child.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

#[cfg(feature = "unsafe-e2e")]
#[test]
fn mock_mixed_release_preserves_holder_and_transport() {
    if std::env::var("CAUTION_UNSAFE_KEY_SERVICE_E2E").as_deref() != Ok("1") {
        return;
    }
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
    use keyfork_shard::{Format, openpgp::OpenPGP};
    use keymaker_models::generate_quorum::{
        GenerateQuorumBundle, GenerateQuorumResponse, deterministic_necroproof_nonce,
    };
    use sequoia_openpgp::{
        cert::prelude::*,
        packet::signature::{SignatureBuilder, subpacket::NotationDataFlags},
        serialize::SerializeInto,
        types::SignatureType,
    };
    use x25519_dalek::{EphemeralSecret, PublicKey};
    let (mut auth, mut device, credential) = fixture(true);
    let (cert, _) = CertBuilder::new()
        .add_userid("Caution public certificate index=0")
        .add_signing_subkey()
        .add_storage_encryption_subkey()
        .generate()
        .unwrap();
    let mut signer = auth
        .ca
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .unwrap()
        .into_keypair()
        .unwrap();
    let signature = SignatureBuilder::new(SignatureType::PositiveCertification)
        .set_notation(
            ORG,
            smex::encode_to_string([2u8; 16]),
            NotationDataFlags::empty().set_human_readable(),
            true,
        )
        .unwrap()
        .set_notation(
            BUNDLE,
            smex::encode_to_string([1u8; 16]),
            NotationDataFlags::empty().set_human_readable(),
            true,
        )
        .unwrap();
    let signature = cert
        .userids()
        .next()
        .unwrap()
        .userid()
        .bind(&mut signer, &cert, signature)
        .unwrap();
    let private = cert
        .insert_packets(vec![sequoia_openpgp::Packet::Signature(signature)])
        .unwrap();
    let external = crate::client::tests::holder();
    // Use public copies for generation: secrets never enter a bundle.
    let armor = |c: &Cert| String::from_utf8(c.armored().to_vec().unwrap()).unwrap();
    let mut bundle = crate::client::tests::bundle(&[external, private.clone()], 2);
    bundle.public_key = armor(&OpenPGP.derive_signing_key(&[7; 32]));
    bundle.keyring[1] = v1::Key::WebAuthn {
        cert: armor(&private),
        credential: vec![serde_json::to_string(&credential).unwrap()],
    };
    let data = GenerateQuorumBundle::V1(bundle.clone());
    let proof = deterministic_necroproof_nonce(&deterministic_bundle_hash(&data).unwrap()).unwrap();
    auth.ca = auth.ca.strip_secret_key_material();
    auth.keymaker_policy = KeymakerPcrPolicy {
        sets: vec![crate::bundle::KeymakerPcrSet {
            pcrs: (0..=2).map(|i| (i, vec![0xab; 48])).collect(),
            expires_at_unix_seconds: None,
        }],
    };
    let measurements = Measurements::from([
        (0, "ab".repeat(48)),
        (1, "ab".repeat(48)),
        (2, "ab".repeat(48)),
    ]);
    let nonce = random_nonce();
    let begin_request = BeginRequest {
        version: Version::V1,
        bundle: GenerateQuorumResponse {
            data,
            necroproof: proof,
        },
        holder: private.fingerprint().to_string(),
        destination_policy: measurements.clone(),
        client_nonce: nonce.clone(),
    };
    let other_request: BeginRequest =
        serde_json::from_value(serde_json::to_value(&begin_request).unwrap()).unwrap();
    let begun = auth.begin(begin_request).unwrap();
    verify_response(&begun, &measurements, &nonce).unwrap();
    let mut changed = serde_json::to_value(&begun).unwrap();
    changed["data"]["context"]["holder"] = serde_json::json!("substituted");
    let changed: Attested<Begun> = serde_json::from_value(changed).unwrap();
    assert!(verify_response(&changed, &measurements, &nonce).is_err());
    assert_eq!(begun.data.context.holder_position, 1);
    assert_eq!(begun.data.context.certificate_index, 0);
    let destination = EphemeralSecret::random();
    let destination_key = PublicKey::from(&destination).to_bytes();
    let attestation = generate_live(&destination_key, &begun.data.context.transport_nonce).unwrap();
    let other = auth.begin(other_request).unwrap();
    assert_ne!(
        begun.data.context.transport_nonce,
        other.data.context.transport_nonce
    );
    let error = auth
        .prepare(PrepareRequest {
            version: Version::V1,
            session_id: other.data.session_id.clone(),
            destination_attestation: attestation.clone(),
            client_nonce: nonce.clone(),
        })
        .unwrap_err();
    assert_eq!(error.kind, "synthetic release nonce");
    assert!(
        !auth
            .pending
            .lock()
            .unwrap()
            .contains_key(&other.data.session_id)
    );
    let prepared = auth
        .prepare(PrepareRequest {
            version: Version::V1,
            session_id: begun.data.session_id,
            destination_attestation: attestation,
            client_nonce: nonce.clone(),
        })
        .unwrap();
    verify_response(&prepared, &measurements, &nonce).unwrap();
    let assertion = assertion(&mut device, prepared.data.options);
    let encrypted = auth
        .complete(
            CompleteRequest {
                version: Version::V1,
                session_id: prepared.data.session_id,
                assertion,
            },
            |context, bundle, key| crypto::recrypt(context, bundle, key, private.clone()),
        )
        .unwrap();
    crypto::verify_request(&armor(&private), &encrypted, SystemTime::now()).unwrap();
    let transport: crate::models::SendEncryptedShardRequest =
        serde_json::from_str(&encrypted.signed_payload).unwrap();
    let shared = destination.diffie_hellman(&PublicKey::from(transport.public_key));
    let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(None, shared.as_bytes());
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    hkdf.expand(b"key", &mut key).unwrap();
    hkdf.expand(b"nonce", &mut nonce).unwrap();
    let bytes = Aes256Gcm::new_from_slice(&key)
        .unwrap()
        .decrypt(
            Nonce::from_slice(&nonce),
            smex::decode_to_vec(transport.encrypted_payload)
                .unwrap()
                .as_slice(),
        )
        .unwrap();
    let share: crate::models::SendShardRequest = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(share.threshold, 2);
    assert_eq!(share.shard[0], 2);
    assert_eq!(share.shard.len(), 33);
    let mut altered = encrypted;
    altered.signed_payload.push(' ');
    assert!(crypto::verify_request(&armor(&private), &altered, SystemTime::now()).is_err());
}

#[test]
fn certificate_context_requires_the_expected_ca_bundle_and_index() {
    use sequoia_openpgp::{
        cert::CertBuilder,
        packet::{
            Packet,
            signature::{SignatureBuilder, subpacket::NotationDataFlags},
        },
        types::SignatureType,
    };
    let (ca, _) = CertBuilder::general_purpose(None, Some("test CA"))
        .set_creation_time(SystemTime::now() - Duration::from_secs(3 * 86400))
        .set_validity_period(Duration::from_secs(86400))
        .generate()
        .unwrap();
    let (other_ca, _) = CertBuilder::general_purpose(None, Some("wrong CA"))
        .generate()
        .unwrap();
    let make = |duplicate: bool| {
        let (cert, _) = CertBuilder::new()
            .add_userid("Caution public certificate index=0")
            .add_signing_subkey()
            .add_storage_encryption_subkey()
            .generate()
            .unwrap();
        let mut signer = ca
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap();
        let mut signature = SignatureBuilder::new(SignatureType::PositiveCertification)
            .set_notation(
                ORG,
                "02020202020202020202020202020202",
                NotationDataFlags::empty().set_human_readable(),
                true,
            )
            .unwrap()
            .set_notation(
                BUNDLE,
                "01010101010101010101010101010101",
                NotationDataFlags::empty().set_human_readable(),
                true,
            )
            .unwrap();
        if duplicate {
            signature = signature
                .add_notation(
                    ORG,
                    "03030303030303030303030303030303",
                    NotationDataFlags::empty().set_human_readable(),
                    true,
                )
                .unwrap();
        }
        let signature = cert
            .userids()
            .next()
            .unwrap()
            .userid()
            .bind(&mut signer, &cert, signature)
            .unwrap();
        cert.insert_packets(vec![Packet::Signature(signature)])
            .unwrap()
            .strip_secret_key_material()
    };
    let cert = make(false);
    let at = SystemTime::now();
    assert_eq!(
        certified_context(
            &cert,
            &ca.clone().strip_secret_key_material(),
            [1; 16],
            0,
            at
        )
        .unwrap(),
        [2; 16]
    );
    assert!(
        certified_context(&cert, &other_ca.strip_secret_key_material(), [1; 16], 0, at).is_err()
    );
    assert!(
        certified_context(
            &cert,
            &ca.clone().strip_secret_key_material(),
            [3; 16],
            0,
            at
        )
        .is_err()
    );
    assert!(
        certified_context(
            &cert,
            &ca.clone().strip_secret_key_material(),
            [1; 16],
            1,
            at
        )
        .is_err()
    );
    assert!(
        certified_context(
            &make(true),
            &ca.clone().strip_secret_key_material(),
            [1; 16],
            0,
            at
        )
        .is_err()
    );
}

#[test]
fn reservations_limit_bundles_and_global_capacity_including_in_flight_sessions() {
    let (auth, _, credential) = fixture(true);
    let (session, _) = ready(&auth, &credential);
    let in_flight = auth.take(&session).unwrap();
    let context = in_flight.context.clone();
    let mut held = Vec::new();
    for _ in 1..BUNDLE_CAPACITY {
        held.push(
            auth.reserve(&random_nonce(), &context, Instant::now() + TTL)
                .unwrap(),
        );
    }
    assert!(
        auth.reserve(&random_nonce(), &context, Instant::now() + TTL)
            .err()
            .unwrap()
            .is_busy()
    );
    drop(in_flight);
    held.push(
        auth.reserve(&random_nonce(), &context, Instant::now() + TTL)
            .unwrap(),
    );
    for n in 1..=(CAPACITY - BUNDLE_CAPACITY) {
        let mut other = context.clone();
        other.bundle_id = [n as u8 + 1; 16];
        held.push(
            auth.reserve(&random_nonce(), &other, Instant::now() + TTL)
                .unwrap(),
        );
    }
    let mut other = context.clone();
    other.bundle_id = [255; 16];
    assert!(
        auth.reserve(&random_nonce(), &other, Instant::now() + TTL)
            .is_err()
    );
    drop(held);
    assert!(auth.quotas.lock().unwrap().is_empty());
    let expired = auth
        .reserve(
            &random_nonce(),
            &context,
            Instant::now() - Duration::from_secs(1),
        )
        .unwrap();
    let fresh = auth
        .reserve(&random_nonce(), &context, Instant::now() + TTL)
        .unwrap();
    assert_eq!(auth.quotas.lock().unwrap().len(), 1);
    drop((expired, fresh));
    assert!(auth.quotas.lock().unwrap().is_empty());
    let (session, _) = ready(&auth, &credential);
    assert!(
        auth.prepare(PrepareRequest {
            version: Version::V1,
            session_id: session,
            destination_attestation: vec![],
            client_nonce: random_nonce()
        })
        .is_err()
    );
    assert!(auth.quotas.lock().unwrap().is_empty());
}
