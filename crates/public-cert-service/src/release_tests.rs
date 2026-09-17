//! Actual HTTP handlers, root derivation and destination receiver with synthetic Nitro evidence.
use super::*;
use axum::{Router, body::Body, http::Request};
use keyfork_shard::{Format, openpgp::OpenPGP};
use keymaker_models::generate_quorum::{self as model, v1};
use locksmith::release::*;
use sequoia_openpgp::{cert::CertBuilder, serialize::SerializeInto};
use std::{collections::HashMap, num::NonZeroU8};
use tower::ServiceExt;
use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};
use webauthn_rs::{WebauthnBuilder, prelude::*};

async fn post<T: serde::Serialize, R: serde::de::DeserializeOwned>(
    app: &Router,
    path: &str,
    value: &T,
) -> R {
    let response = app
        .clone()
        .oneshot(
            Request::post(path)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(value).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .unwrap();
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    serde_json::from_slice(&body).unwrap()
}
#[test]
fn custody_http_and_destination_recover_mixed_quorum() {
    const CHILD: &str = "CUSTODY_RECOVERY_HTTP_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "release::tests::custody_http_and_destination_recover_mixed_quorum",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("CAUTION_UNSAFE_KEY_SERVICE_E2E", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    for all_webauthn in [false, true] {
        keyforkd::test_util::run_test(&[9; 32], move |_| -> keyforkd::test_util::Panicable {
            let ca_key = keyforkd_client::Client::discover_socket()
                .unwrap()
                .request_xprv::<keyfork_derive_openpgp::XPrvKey>(
                    &derivation::default_openpgp_ca_path(),
                )
                .unwrap();
            let ca = keyfork_derive_openpgp::derive(
                &ca_key,
                &derivation::public_certificate_key_flags(),
                &sequoia_openpgp::packet::UserID::from("Caution default OpenPGP CA"),
            )
            .unwrap()
            .strip_secret_key_material();
            let response = derivation::derive_public_certificate(
                public_certificate_models::v1::PublicCertificateRequest {
                    organization_id: [2; 16],
                    certificate_count: NonZeroU8::new(2).unwrap(),
                },
                [1; 16],
            )
            .unwrap();
            let certificates = response.data.to_latest().certificates;
            let derived = certificates[usize::from(all_webauthn)].clone();
            let policy = locksmith::bundle::KeymakerPcrPolicy {
                sets: vec![locksmith::bundle::KeymakerPcrSet {
                    pcrs: (0..=2).map(|i| (i, vec![0xab; 48])).collect(),
                    expires_at_unix_seconds: None,
                }],
            };
            let origin = Url::parse("https://example.com").unwrap();
            let webauthn = WebauthnBuilder::new("example.com", &origin)
                .unwrap()
                .build()
                .unwrap();
            let mut device = WebauthnAuthenticator::new(SoftPasskey::new(true));
            let (options, state) = webauthn
                .start_securitykey_registration(
                    uuid::Uuid::new_v4(),
                    "alice",
                    "Alice",
                    None,
                    None,
                    None,
                )
                .unwrap();
            let assertion = device.do_registration(origin.clone(), options).unwrap();
            let credential = webauthn
                .finish_securitykey_registration(&assertion, &state)
                .unwrap();
            let mut register = |name| {
                let (options, state) = webauthn
                    .start_securitykey_registration(
                        uuid::Uuid::new_v4(),
                        name,
                        name,
                        None,
                        None,
                        None,
                    )
                    .unwrap();
                let response = device.do_registration(origin.clone(), options).unwrap();
                webauthn
                    .finish_securitykey_registration(&response, &state)
                    .unwrap()
            };
            let alternate = register("Alice alternate");
            let other = register("Bob");
            let external = CertBuilder::new()
                .add_userid("external test holder")
                .add_signing_subkey()
                .add_storage_encryption_subkey()
                .generate()
                .unwrap()
                .0;
            let armor = |cert: &Cert| String::from_utf8(cert.armored().to_vec().unwrap()).unwrap();
            let first = if all_webauthn {
                Cert::from_bytes(certificates[0].as_bytes()).unwrap()
            } else {
                external.clone()
            };
            let certs = [first, Cert::from_bytes(derived.as_bytes()).unwrap()];
            let mut shards = Vec::new();
            OpenPGP
                .shard_and_encrypt(2, 2, &[7; 32], &certs[..], &mut shards)
                .unwrap();
            let mnemonic = keyfork_mnemonic::Mnemonic::from_array([7; 32]);
            let root_key = keyfork_derive_openpgp::XPrv::new(mnemonic.generate_seed(None))
                .unwrap()
                .derive_path(&derivation::default_openpgp_ca_path())
                .unwrap();
            let root_public = keyfork_derive_openpgp::derive(
                &root_key,
                &derivation::public_certificate_key_flags(),
                &sequoia_openpgp::packet::UserID::from("Keymaker-generated key"),
            )
            .unwrap();
            assert_ne!(
                root_public.fingerprint(),
                OpenPGP.derive_signing_key(&[7; 32]).fingerprint()
            );
            let data = model::GenerateQuorumBundle::V1(v1::GenerateQuorumResponse {
                bundle_id: [1; 16],
                label: HashMap::new(),
                threshold: 2,
                max: 2,
                shardfile: String::from_utf8(shards).unwrap(),
                public_key: armor(&root_public),
                keyring: vec![
                    if all_webauthn {
                        v1::Key::WebAuthn {
                            cert: certificates[0].clone(),
                            credential: vec![serde_json::to_string(&other).unwrap()],
                        }
                    } else {
                        v1::Key::OpenPGP {
                            cert: armor(&external),
                        }
                    },
                    v1::Key::WebAuthn {
                        cert: derived.clone(),
                        credential: vec![
                            serde_json::to_string(&credential).unwrap(),
                            serde_json::to_string(&alternate).unwrap(),
                        ],
                    },
                ],
            });
            let proof = model::GenerateQuorumResponse {
                necroproof: model::deterministic_necroproof_nonce(
                    &model::deterministic_bundle_hash(&data).unwrap(),
                )
                .unwrap(),
                data: data.clone(),
            };
            let auth = Authorizer::new("example.com", origin.as_str(), policy, ca).unwrap();
            let app = crate::router(Arc::new(AppState {
                release: Some(Arc::new(auth)),
            }));
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(async move {
                    tokio::time::timeout(std::time::Duration::from_secs(20), async move {
                        let measurements = Measurements::from([
                            (0, "ab".repeat(48)),
                            (1, "ab".repeat(48)),
                            (2, "ab".repeat(48)),
                        ]);
                        eprintln!("begin release");
                        let begun: Attested<Begun> = post(
                            &app,
                            "/v1/releases/begin",
                            &BeginRequest {
                                version: Version::V1,
                                bundle: proof.clone(),
                                holder: certs[1].fingerprint().to_string(),
                                destination_policy: measurements.clone(),
                                client_nonce: random_nonce(),
                            },
                        )
                        .await;
                        assert_eq!(begun.data.context.certificate_index, u8::from(all_webauthn));
                        assert_eq!(begun.data.context.holder_position, 1);
                        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                        let address = listener.local_addr().unwrap();
                        drop(listener);
                        let receive_bundle = data.clone();
                        let receiver = tokio::spawn(async move {
                            locksmith::server::receive_shards(address, &receive_bundle)
                                .await
                                .unwrap()
                        });
                        eprintln!("connect destination");
                        let destination = loop {
                            match crypto::Destination::connect(
                                address,
                                begun.data.context.transport_nonce.clone(),
                            )
                            .await
                            {
                                Ok(connection) => break connection,
                                Err(_) => {
                                    tokio::time::sleep(std::time::Duration::from_millis(10)).await
                                }
                            }
                        };
                        eprintln!("prepare release");
                        let prepared: Attested<Prepared> = post(
                            &app,
                            "/v1/releases/prepare",
                            &PrepareRequest {
                                version: Version::V1,
                                session_id: begun.data.session_id,
                                destination_attestation: destination.attestation.clone(),
                                client_nonce: random_nonce(),
                            },
                        )
                        .await;
                        let assertion = device
                            .do_authentication(origin.clone(), prepared.data.options)
                            .unwrap();
                        let request = CompleteRequest {
                            version: Version::V1,
                            session_id: prepared.data.session_id,
                            assertion,
                        };
                        eprintln!("complete release");
                        let encrypted: SendSignedEncryptedShardRequest =
                            post(&app, "/v1/releases/complete", &request).await;
                        crypto::verify_request(&derived, &encrypted).unwrap();
                        assert!(matches!(
                            destination.send(encrypted).await.unwrap(),
                            locksmith::models::SendSignedEncryptedShardResponse::Accepted {
                                remaining: 1
                            }
                        ));
                        assert!(
                            !receiver.is_finished(),
                            "application must remain locked below threshold"
                        );
                        let replay = app
                            .clone()
                            .oneshot(
                                Request::post("/v1/releases/complete")
                                    .header("content-type", "application/json")
                                    .body(Body::from(serde_json::to_vec(&request).unwrap()))
                                    .unwrap(),
                            )
                            .await
                            .unwrap();
                        assert_eq!(replay.status(), StatusCode::FORBIDDEN);
                        // Another credential for the same holder can authorize recryption,
                        // but cannot contribute a second share at the receiver.
                        let duplicate = contribute(
                            &app,
                            &proof,
                            certs[1].fingerprint().to_string(),
                            &measurements,
                            address,
                            &mut device,
                            &origin,
                            true,
                        )
                        .await;
                        assert!(matches!(
                            duplicate,
                            locksmith::models::SendSignedEncryptedShardResponse::Rejected { .. }
                        ));
                        assert!(!receiver.is_finished());
                        if all_webauthn {
                            assert!(matches!(
                                contribute(
                                    &app,
                                    &proof,
                                    certs[0].fingerprint().to_string(),
                                    &measurements,
                                    address,
                                    &mut device,
                                    &origin,
                                    false
                                )
                                .await,
                                locksmith::models::SendSignedEncryptedShardResponse::Accepted {
                                    remaining: 0
                                }
                            ));
                        } else {
                            eprintln!("external contribution");
                            let nonce = random_nonce();
                            let destination = crypto::Destination::connect(address, nonce.clone())
                                .await
                                .unwrap();
                            let key: [u8; 32] =
                                verify_live(&destination.attestation, &measurements, &nonce)
                                    .unwrap()
                                    .try_into()
                                    .unwrap();
                            let mut context = prepared.data.context;
                            context.holder_position = 0;
                            context.holder = external.fingerprint().to_string();
                            let encrypted =
                                crypto::recrypt(&context, &data.to_latest(), key, external)
                                    .unwrap();
                            assert!(matches!(
                                destination.send(encrypted).await.unwrap(),
                                locksmith::models::SendSignedEncryptedShardResponse::Accepted {
                                    remaining: 0
                                }
                            ));
                        }
                        assert_eq!(receiver.await.unwrap(), vec![7; 32]);
                    })
                    .await
                    .expect("recovery integration timed out");
                });
            Ok(())
        })
        .unwrap();
    }
}

async fn contribute(
    app: &Router,
    proof: &model::GenerateQuorumResponse,
    holder: String,
    measurements: &Measurements,
    address: std::net::SocketAddr,
    device: &mut WebauthnAuthenticator<SoftPasskey>,
    origin: &Url,
    last: bool,
) -> locksmith::models::SendSignedEncryptedShardResponse {
    let begun: Attested<Begun> = post(
        app,
        "/v1/releases/begin",
        &BeginRequest {
            version: Version::V1,
            bundle: proof.clone(),
            holder,
            destination_policy: measurements.clone(),
            client_nonce: random_nonce(),
        },
    )
    .await;
    let destination =
        crypto::Destination::connect(address, begun.data.context.transport_nonce.clone())
            .await
            .unwrap();
    let prepared: Attested<Prepared> = post(
        app,
        "/v1/releases/prepare",
        &PrepareRequest {
            version: Version::V1,
            session_id: begun.data.session_id,
            destination_attestation: destination.attestation.clone(),
            client_nonce: random_nonce(),
        },
    )
    .await;
    let mut options = prepared.data.options;
    if last {
        options.public_key.allow_credentials =
            vec![options.public_key.allow_credentials.pop().unwrap()];
    }
    let assertion = device.do_authentication(origin.clone(), options).unwrap();
    let encrypted: SendSignedEncryptedShardRequest = post(
        app,
        "/v1/releases/complete",
        &CompleteRequest {
            version: Version::V1,
            session_id: prepared.data.session_id,
            assertion,
        },
    )
    .await;
    destination.send(encrypted).await.unwrap()
}
