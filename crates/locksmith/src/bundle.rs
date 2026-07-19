use bootproof_sdk::format::{VerifiableSignedAttestationFormat as _, nitro::Nitro};
use keymaker_models::generate_quorum::{
    GenerateQuorumBundle, GenerateQuorumResponse, deterministic_bundle_hash,
    deterministic_necroproof_nonce, v1,
};
use serde_cbor::Value as CborValue;
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

#[derive(Clone, Debug)]
pub enum QuorumBundle {
    V1(v1::GenerateQuorumResponse),
}

impl QuorumBundle {
    pub fn shardfile(&self) -> &str {
        match self {
            Self::V1(bundle) => &bundle.shardfile,
        }
    }

    pub fn public_key(&self) -> &str {
        match self {
            Self::V1(bundle) => &bundle.public_key,
        }
    }

    pub fn openpgp_keyring(&self) -> Result<String, BundleAccessorError> {
        match self {
            Self::V1(bundle) => openpgp_keyring_from_v1(&bundle.keyring),
        }
    }
}

fn openpgp_keyring_from_v1(keyring: &[v1::Key]) -> Result<String, BundleAccessorError> {
    let mut armored = String::new();
    for (index, key) in keyring.iter().enumerate() {
        match key {
            v1::Key::OpenPGP { cert } => {
                armored.push_str(cert);
                armored.push('\n');
            }
            v1::Key::WebAuthn { .. } => {
                return Err(BundleAccessorError::UnsupportedWebAuthnKey { index });
            }
        }
    }
    Ok(armored)
}

#[derive(Debug, thiserror::Error)]
pub enum BundleAccessorError {
    #[error(
        "bundle keyring entry {index} requires WebAuthn setup, which this OpenPGP path does not support yet"
    )]
    UnsupportedWebAuthnKey { index: usize },
}

#[derive(Clone, Debug)]
pub struct KeymakerPcrPolicy {
    pub allowed: Vec<AllowedKeymakerPcrSet>,
}

#[derive(Clone, Debug)]
pub struct AllowedKeymakerPcrSet {
    pub pcrs: HashMap<u8, Vec<u8>>,
    pub expires_at: Option<SystemTime>,
}

impl KeymakerPcrPolicy {
    fn active_pcr_sets(&self, now: SystemTime) -> impl Iterator<Item = &HashMap<u8, Vec<u8>>> {
        self.allowed.iter().filter_map(move |allowed| {
            if allowed
                .expires_at
                .is_some_and(|expires_at| now >= expires_at)
            {
                None
            } else {
                Some(&allowed.pcrs)
            }
        })
    }

    pub fn from_json(input: &str) -> Result<Self, ParseKeymakerPcrPolicyError> {
        let policy: KeymakerPcrPolicyJson = serde_json::from_str(input)
            .map_err(|source| ParseKeymakerPcrPolicyError::ParseJson { source })?;
        let allowed = policy
            .allowed
            .into_iter()
            .enumerate()
            .map(|(set_index, allowed)| {
                let pcrs = allowed
                    .pcrs
                    .into_iter()
                    .map(|(pcr_index, value)| {
                        smex::decode_to_vec(&value)
                            .map(|value| (pcr_index, value))
                            .map_err(|source| ParseKeymakerPcrPolicyError::DecodePcr {
                                set_index,
                                pcr_index,
                                source: Box::new(source),
                            })
                    })
                    .collect::<Result<HashMap<_, _>, _>>()?;
                let expires_at = allowed
                    .expires_at_unix_seconds
                    .map(|seconds| SystemTime::UNIX_EPOCH + Duration::from_secs(seconds));
                Ok(AllowedKeymakerPcrSet { pcrs, expires_at })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { allowed })
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct KeymakerPcrPolicyJson {
    allowed: Vec<AllowedKeymakerPcrSetJson>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowedKeymakerPcrSetJson {
    pcrs: HashMap<u8, String>,
    expires_at_unix_seconds: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum ParseKeymakerPcrPolicyError {
    #[error("could not parse Keymaker PCR policy JSON")]
    ParseJson {
        #[source]
        source: serde_json::Error,
    },

    #[error("could not decode Keymaker PCR policy set {set_index} PCR {pcr_index} as hex")]
    DecodePcr {
        set_index: usize,
        pcr_index: u8,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
}

pub trait NecroproofVerifier {
    fn verify(
        &self,
        necroproof: &[u8],
        pcrs: &HashMap<u8, Vec<u8>>,
        nonce: &[u8],
        expected_user_data: &[u8],
        now: Duration,
    ) -> Result<(), VerifyNecroproofError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NitroNecroproofVerifier;

impl NecroproofVerifier for NitroNecroproofVerifier {
    fn verify(
        &self,
        necroproof: &[u8],
        pcrs: &HashMap<u8, Vec<u8>>,
        nonce: &[u8],
        expected_user_data: &[u8],
        now: Duration,
    ) -> Result<(), VerifyNecroproofError> {
        let attestation = Nitro::new(necroproof, pcrs.clone())
            .map_err(|source| VerifyNecroproofError::InvalidPcrs { source })?;
        let document = attestation
            .verify(now, &nonce)
            .map_err(|source| VerifyNecroproofError::RejectedByBootproof { source })?;
        let user_data = get_user_data(document)?;
        if user_data != expected_user_data {
            return Err(VerifyNecroproofError::UserDataMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyNecroproofError {
    #[error("keymaker necroproof PCR policy is invalid")]
    InvalidPcrs {
        #[source]
        source: bootproof_sdk::format::Error,
    },

    #[error("keymaker necroproof was rejected")]
    RejectedByBootproof {
        #[source]
        source: bootproof_sdk::format::Error,
    },

    #[error("keymaker necroproof user data did not match the quorum bundle hash")]
    UserDataMismatch,

    #[error("keymaker necroproof document does not contain bytes user_data")]
    MissingUserData,

    #[error("could not decode keymaker necroproof document")]
    DecodeDocument {
        #[source]
        source: serde_cbor::Error,
    },

    #[error("keymaker necroproof rejected by test verifier")]
    #[cfg(test)]
    Rejected,
}

#[derive(Debug, serde::Deserialize)]
struct OpaqueContainsUserData {
    user_data: serde_bytes::ByteBuf,
}

fn get_user_data(document: CborValue) -> Result<Vec<u8>, VerifyNecroproofError> {
    let CborValue::Map(map) = &document else {
        return Err(VerifyNecroproofError::MissingUserData);
    };
    if !map.contains_key(&CborValue::Text("user_data".into())) {
        return Err(VerifyNecroproofError::MissingUserData);
    }
    let user_data_container: OpaqueContainsUserData = serde_cbor::value::from_value(document)
        .map_err(|source| VerifyNecroproofError::DecodeDocument { source })?;
    Ok(user_data_container.user_data.into_vec())
}

#[derive(Debug, thiserror::Error)]
pub enum LoadQuorumBundleError {
    #[error("could not parse quorum bundle JSON")]
    ParseJson {
        #[source]
        source: serde_json::Error,
    },

    #[error("keymaker quorum bundle does not include a necroproof")]
    EmptyNecroproof,

    #[error("keymaker PCR policy did not contain any active PCR sets")]
    NoActivePcrSets,

    #[error("could not hash keymaker quorum bundle")]
    HashBundle {
        #[source]
        source: keymaker_models::generate_quorum::DeterministicBundleHashError,
    },

    #[error("could not derive keymaker quorum bundle necroproof nonce")]
    DeriveNonce {
        #[source]
        source: keymaker_models::generate_quorum::DeterministicBundleHashError,
    },

    #[error("keymaker necroproof did not match any active PCR set")]
    VerifyNecroproof { attempts: usize },
}

pub fn load_json(
    input: &str,
    policy: &KeymakerPcrPolicy,
    now: SystemTime,
) -> Result<QuorumBundle, LoadQuorumBundleError> {
    load_json_with_verifier(input, policy, now, &NitroNecroproofVerifier)
}

pub fn load_json_with_verifier(
    input: &str,
    policy: &KeymakerPcrPolicy,
    now: SystemTime,
    verifier: &impl NecroproofVerifier,
) -> Result<QuorumBundle, LoadQuorumBundleError> {
    let response: GenerateQuorumResponse = serde_json::from_str(input)
        .map_err(|source| LoadQuorumBundleError::ParseJson { source })?;
    load_response_with_verifier(response, policy, now, verifier)
}

pub fn load_response_with_verifier(
    response: GenerateQuorumResponse,
    policy: &KeymakerPcrPolicy,
    now: SystemTime,
    verifier: &impl NecroproofVerifier,
) -> Result<QuorumBundle, LoadQuorumBundleError> {
    if response.necroproof.is_empty() {
        return Err(LoadQuorumBundleError::EmptyNecroproof);
    }

    let bundle_hash = deterministic_bundle_hash(&response.data)
        .map_err(|source| LoadQuorumBundleError::HashBundle { source })?;
    let nonce = deterministic_necroproof_nonce(&bundle_hash)
        .map_err(|source| LoadQuorumBundleError::DeriveNonce { source })?;
    let now_since_epoch = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);

    let mut attempts = 0;
    for pcrs in policy.active_pcr_sets(now) {
        attempts += 1;
        if verifier
            .verify(
                &response.necroproof,
                pcrs,
                &nonce,
                &bundle_hash,
                now_since_epoch,
            )
            .is_ok()
        {
            return Ok(dispatch_bundle(response.data));
        }
    }

    if attempts == 0 {
        return Err(LoadQuorumBundleError::NoActivePcrSets);
    }

    Err(LoadQuorumBundleError::VerifyNecroproof { attempts })
}

fn dispatch_bundle(bundle: GenerateQuorumBundle) -> QuorumBundle {
    match bundle {
        GenerateQuorumBundle::V1(bundle) => QuorumBundle::V1(bundle),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keymaker_models::generate_quorum::v1;
    use std::collections::HashMap;
    use std::time::{Duration, SystemTime};

    #[derive(Default)]
    struct FakeVerifier {
        accepted_pcr0: Vec<u8>,
        calls: std::sync::Mutex<Vec<Vec<u8>>>,
    }

    impl NecroproofVerifier for FakeVerifier {
        fn verify(
            &self,
            _necroproof: &[u8],
            pcrs: &HashMap<u8, Vec<u8>>,
            _nonce: &[u8],
            _expected_user_data: &[u8],
            _now: Duration,
        ) -> Result<(), VerifyNecroproofError> {
            self.calls
                .lock()
                .expect("unpoisoned")
                .push(pcrs.get(&0).cloned().unwrap_or_default());
            if pcrs.get(&0) == Some(&self.accepted_pcr0) {
                Ok(())
            } else {
                Err(VerifyNecroproofError::Rejected)
            }
        }
    }

    fn sample_json() -> String {
        serde_json::json!({
            "data": {
                "version": "V1",
                "bundle_id": [9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9],
                "label": {"name": "demo"},
                "keyring": [{"OpenPGP": {"cert": "cert-a"}}, {"OpenPGP": {"cert": "cert-b"}}],
                "shardfile": "shards",
                "public_key": "public"
            },
            "necroproof": [1, 2, 3]
        })
        .to_string()
    }

    fn pcr_set(pcr0: u8, expires_at: Option<SystemTime>) -> AllowedKeymakerPcrSet {
        AllowedKeymakerPcrSet {
            pcrs: HashMap::from_iter([(0, vec![pcr0]), (1, vec![1]), (2, vec![2])]),
            expires_at,
        }
    }

    #[test]
    fn load_json_dispatches_v1_after_necroproof_verification() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let policy = KeymakerPcrPolicy {
            allowed: vec![pcr_set(1, None)],
        };
        let verifier = FakeVerifier {
            accepted_pcr0: vec![1],
            calls: Default::default(),
        };

        let bundle = load_json_with_verifier(&sample_json(), &policy, now, &verifier)
            .expect("verified bundle");

        match bundle {
            QuorumBundle::V1(v1::GenerateQuorumResponse { shardfile, .. }) => {
                assert_eq!(shardfile, "shards");
            }
        }
    }

    #[test]
    fn expired_pcr_sets_are_skipped_before_verification() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let policy = KeymakerPcrPolicy {
            allowed: vec![
                pcr_set(1, Some(SystemTime::UNIX_EPOCH + Duration::from_secs(9))),
                pcr_set(2, None),
            ],
        };
        let verifier = FakeVerifier {
            accepted_pcr0: vec![2],
            calls: Default::default(),
        };

        load_json_with_verifier(&sample_json(), &policy, now, &verifier).expect("verified bundle");

        assert_eq!(
            verifier.calls.lock().expect("unpoisoned").as_slice(),
            &[vec![2]]
        );
    }

    #[test]
    fn empty_necroproof_fails_closed() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let json = serde_json::json!({
            "data": {
                "version": "V1",
                "bundle_id": [9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9],
                "label": {},
                "keyring": [],
                "shardfile": "shards",
                "public_key": "public"
            },
            "necroproof": []
        })
        .to_string();
        let policy = KeymakerPcrPolicy {
            allowed: vec![pcr_set(1, None)],
        };

        assert!(matches!(
            load_json_with_verifier(&json, &policy, now, &FakeVerifier::default()),
            Err(LoadQuorumBundleError::EmptyNecroproof)
        ));
    }

    #[test]
    fn v1_web_authn_key_material_is_preserved_but_current_openpgp_accessors_reject_it() {
        let bundle = QuorumBundle::V1(v1::GenerateQuorumResponse {
            bundle_id: [3; 16],
            label: Default::default(),
            keyring: vec![v1::Key::WebAuthn {
                credential: vec!["credential-a".to_string()],
                cert: "cert-a".to_string(),
            }],
            shardfile: "shards".to_string(),
            public_key: "public".to_string(),
        });

        assert!(matches!(
            bundle.openpgp_keyring(),
            Err(BundleAccessorError::UnsupportedWebAuthnKey { index: 0 })
        ));
    }
}
