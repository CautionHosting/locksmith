use bootproof_sdk::format::{VerifiableSignedAttestationFormat as _, nitro::Nitro};
use coset::{CborSerializable as _, CoseSign1};
use keymaker_models::generate_quorum::{
    GenerateQuorumBundle, GenerateQuorumResponse, deterministic_bundle_hash,
    deterministic_necroproof_nonce, v1,
};
use serde::Deserialize as _;
use serde_cbor::Value as CborValue;
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

pub type QuorumBundle = GenerateQuorumBundle;

pub trait QuorumBundleExt {
    fn shardfile(&self) -> &str;
    fn public_key(&self) -> &str;
    fn openpgp_keyring(&self) -> Result<String, BundleAccessorError>;
}

impl QuorumBundleExt for GenerateQuorumBundle {
    fn shardfile(&self) -> &str {
        match self {
            Self::V1(bundle) => &bundle.shardfile,
        }
    }

    fn public_key(&self) -> &str {
        match self {
            Self::V1(bundle) => &bundle.public_key,
        }
    }

    fn openpgp_keyring(&self) -> Result<String, BundleAccessorError> {
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

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeymakerPcrPolicy {
    pub sets: Vec<KeymakerPcrSet>,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeymakerPcrSet {
    #[serde(deserialize_with = "deserialize_pcrs")]
    pub pcrs: HashMap<u8, Vec<u8>>,
    pub expires_at_unix_seconds: Option<u64>,
}

impl KeymakerPcrSet {
    fn is_valid_at(&self, at: SystemTime) -> bool {
        let Some(expires_at) = self.expires_at_unix_seconds else {
            return true;
        };
        at < SystemTime::UNIX_EPOCH + Duration::from_secs(expires_at)
    }
}

impl KeymakerPcrPolicy {
    pub fn from_json(input: &str) -> Result<Self, ParseKeymakerPcrPolicyError> {
        serde_json::from_str(input)
            .map_err(|source| ParseKeymakerPcrPolicyError::ParseJson { source })
    }

    fn verify_necroproof(
        &self,
        necroproof: &[u8],
        nonce: &[u8],
        expected_user_data: &[u8],
    ) -> Result<(), VerifyNecroproofError> {
        let at = necroproof_timestamp(necroproof)?;
        let mut attempts = 0;
        for pcr_set in self.sets.iter().filter(|set| set.is_valid_at(at)) {
            attempts += 1;
            if verify_necroproof_with_pcrs(necroproof, &pcr_set.pcrs, nonce, expected_user_data, at)
                .is_ok()
            {
                return Ok(());
            }
        }

        if attempts == 0 {
            return Err(VerifyNecroproofError::NoActivePcrSets);
        }
        Err(VerifyNecroproofError::NoMatchingPcrSet { attempts })
    }
}

fn deserialize_pcrs<'de, D>(deserializer: D) -> Result<HashMap<u8, Vec<u8>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let pcrs = HashMap::<u8, String>::deserialize(deserializer)?;
    pcrs.into_iter()
        .map(|(pcr_index, value)| {
            smex::decode_to_vec(&value)
                .map(|value| (pcr_index, value))
                .map_err(serde::de::Error::custom)
        })
        .collect()
}

#[derive(Debug, thiserror::Error)]
pub enum ParseKeymakerPcrPolicyError {
    #[error("could not parse Keymaker PCR policy JSON")]
    ParseJson {
        #[source]
        source: serde_json::Error,
    },
}

fn verify_necroproof_with_pcrs(
    necroproof: &[u8],
    pcrs: &HashMap<u8, Vec<u8>>,
    nonce: &[u8],
    expected_user_data: &[u8],
    at: SystemTime,
) -> Result<(), VerifyNecroproofError> {
    let at_since_epoch = at
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let attestation = Nitro::new(necroproof, pcrs.clone())
        .map_err(|source| VerifyNecroproofError::InvalidPcrs { source })?;
    let document = attestation
        .verify(at_since_epoch, &nonce)
        .map_err(|source| VerifyNecroproofError::RejectedByBootproof { source })?;
    let user_data = get_user_data(document)?;
    if user_data != expected_user_data {
        return Err(VerifyNecroproofError::UserDataMismatch);
    }
    Ok(())
}

fn necroproof_timestamp(necroproof: &[u8]) -> Result<SystemTime, VerifyNecroproofError> {
    let cose_signed_blob =
        CoseSign1::from_slice(necroproof).map_err(|source| VerifyNecroproofError::DecodeCose {
            source: Box::new(source),
        })?;
    let payload_bytes = cose_signed_blob
        .payload
        .as_ref()
        .ok_or(VerifyNecroproofError::MissingTimestamp)?;
    let payload: CborValue = serde_cbor::from_slice(payload_bytes)
        .map_err(|source| VerifyNecroproofError::DecodeDocument { source })?;
    let CborValue::Map(map) = payload else {
        return Err(VerifyNecroproofError::MissingTimestamp);
    };
    let timestamp_millis = match map.get(&CborValue::Text("timestamp".into())) {
        Some(CborValue::Integer(timestamp)) => {
            u64::try_from(*timestamp).map_err(|_| VerifyNecroproofError::InvalidTimestamp {
                timestamp: *timestamp,
            })?
        }
        _ => return Err(VerifyNecroproofError::MissingTimestamp),
    };
    Ok(SystemTime::UNIX_EPOCH + Duration::from_millis(timestamp_millis))
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

    #[error("could not decode keymaker necroproof COSE wrapper")]
    DecodeCose {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    #[error("keymaker necroproof document does not contain a timestamp")]
    MissingTimestamp,

    #[error("keymaker necroproof timestamp {timestamp} is invalid")]
    InvalidTimestamp { timestamp: i128 },

    #[error("could not decode keymaker necroproof document")]
    DecodeDocument {
        #[source]
        source: serde_cbor::Error,
    },

    #[error("keymaker PCR policy did not contain any PCR sets valid at the necroproof timestamp")]
    NoActivePcrSets,

    #[error("keymaker necroproof did not match any PCR set valid at the necroproof timestamp")]
    NoMatchingPcrSet { attempts: usize },
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

    #[error("could not verify keymaker quorum bundle necroproof")]
    VerifyNecroproof {
        #[source]
        source: VerifyNecroproofError,
    },
}

pub fn load_json(
    input: &str,
    policy: &KeymakerPcrPolicy,
) -> Result<GenerateQuorumBundle, LoadQuorumBundleError> {
    let response: GenerateQuorumResponse = serde_json::from_str(input)
        .map_err(|source| LoadQuorumBundleError::ParseJson { source })?;
    load_response(response, policy)
}

pub fn load_response(
    response: GenerateQuorumResponse,
    policy: &KeymakerPcrPolicy,
) -> Result<GenerateQuorumBundle, LoadQuorumBundleError> {
    if response.necroproof.is_empty() {
        return Err(LoadQuorumBundleError::EmptyNecroproof);
    }

    let bundle_hash = deterministic_bundle_hash(&response.data)
        .map_err(|source| LoadQuorumBundleError::HashBundle { source })?;
    let nonce = deterministic_necroproof_nonce(&bundle_hash)
        .map_err(|source| LoadQuorumBundleError::DeriveNonce { source })?;

    policy
        .verify_necroproof(&response.necroproof, &nonce, &bundle_hash)
        .map_err(|source| LoadQuorumBundleError::VerifyNecroproof { source })?;

    Ok(response.data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use coset::CoseSign1;
    use keymaker_models::generate_quorum::v1;
    use serde_cbor::Value;
    use std::collections::BTreeMap;
    use std::time::{Duration, SystemTime};

    fn sample_json(necroproof: Vec<u8>) -> String {
        serde_json::json!({
            "data": {
                "version": "V1",
                "bundle_id": [9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9],
                "label": {"name": "demo"},
                "keyring": [{"OpenPGP": {"cert": "cert-a"}}, {"OpenPGP": {"cert": "cert-b"}}],
                "shardfile": "shards",
                "public_key": "public"
            },
            "necroproof": necroproof
        })
        .to_string()
    }

    fn pcr_set(pcr0: u8, expires_at_unix_seconds: Option<u64>) -> KeymakerPcrSet {
        KeymakerPcrSet {
            pcrs: HashMap::from_iter([(0, vec![pcr0]), (1, vec![1]), (2, vec![2])]),
            expires_at_unix_seconds,
        }
    }

    fn cose_with_timestamp(timestamp_millis: i128) -> Vec<u8> {
        let mut map = BTreeMap::new();
        map.insert(
            Value::Text("timestamp".to_string()),
            Value::Integer(timestamp_millis),
        );
        CoseSign1 {
            payload: Some(serde_cbor::to_vec(&Value::Map(map)).expect("payload")),
            ..Default::default()
        }
        .to_vec()
        .expect("cose")
    }

    #[test]
    fn policy_json_loads_sets_with_hex_pcrs() {
        let policy = KeymakerPcrPolicy::from_json(
            r#"{
                "sets": [{
                    "pcrs": {"0": "0a", "1": "0b", "2": "0c"},
                    "expires_at_unix_seconds": null
                }]
            }"#,
        )
        .expect("policy");

        assert_eq!(policy.sets[0].pcrs.get(&0), Some(&vec![0x0a]));
        assert!(policy.sets[0].is_valid_at(SystemTime::UNIX_EPOCH + Duration::from_secs(10)));
    }

    #[test]
    fn pcr_set_expiry_is_evaluated_at_necroproof_timestamp() {
        let policy = KeymakerPcrPolicy {
            sets: vec![pcr_set(1, Some(10)), pcr_set(2, None)],
        };

        assert!(policy.sets[0].is_valid_at(SystemTime::UNIX_EPOCH + Duration::from_secs(9)));
        assert!(!policy.sets[0].is_valid_at(SystemTime::UNIX_EPOCH + Duration::from_secs(10)));
        assert!(policy.sets[1].is_valid_at(SystemTime::UNIX_EPOCH + Duration::from_secs(10)));
    }

    #[test]
    fn necroproof_timestamp_is_read_from_cose_payload() {
        let at = necroproof_timestamp(&cose_with_timestamp(1_234)).expect("timestamp");

        assert_eq!(
            at.duration_since(SystemTime::UNIX_EPOCH)
                .expect("after epoch"),
            Duration::from_millis(1_234)
        );
    }

    #[test]
    fn empty_necroproof_fails_closed() {
        let json = sample_json(vec![]);
        let policy = KeymakerPcrPolicy {
            sets: vec![pcr_set(1, None)],
        };

        assert!(matches!(
            load_json(&json, &policy),
            Err(LoadQuorumBundleError::EmptyNecroproof)
        ));
    }

    #[test]
    fn v1_web_authn_key_material_is_preserved_but_current_openpgp_accessors_reject_it() {
        let bundle = GenerateQuorumBundle::V1(v1::GenerateQuorumResponse {
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
