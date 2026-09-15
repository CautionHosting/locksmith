use bootproof_sdk::format::nitro::Nitro;
use keymaker_models::generate_quorum::{
    GenerateQuorumBundle, GenerateQuorumResponse, deterministic_bundle_hash,
    deterministic_necroproof_nonce,
};
use serde::Deserialize as _;
use serde_cbor::Value as CborValue;
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

pub type QuorumBundle = GenerateQuorumBundle;

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
    #[serde(default, deserialize_with = "deserialize_expiry")]
    pub expires_at_unix_seconds: Option<u64>,
}

impl KeymakerPcrSet {
    fn is_valid_at(&self, at: SystemTime) -> bool {
        let Some(expires_at) = self.expires_at_unix_seconds else {
            return true;
        };
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(expires_at))
            .is_some_and(|expiry| at < expiry)
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
        if self.sets.is_empty() {
            return Err(VerifyNecroproofError::NoPcrSets);
        }
        let mut errors = Vec::new();
        for (index, pcr_set) in self.sets.iter().enumerate() {
            match verify_necroproof_with_pcrs(necroproof, &pcr_set.pcrs, nonce, expected_user_data)
            {
                Ok(at) if pcr_set.is_valid_at(at) => return Ok(()),
                Ok(_) => errors.push((
                    index,
                    VerifyNecroproofError::PolicyExpired {
                        expires_at_unix_seconds: pcr_set
                            .expires_at_unix_seconds
                            .expect("only expiring PCR sets can be invalid at a timestamp"),
                    },
                )),
                Err(error) => errors.push((index, error)),
            }
        }
        Err(VerifyNecroproofError::NoMatchingPcrSet {
            attempts: errors.len(),
            errors,
        })
    }
}

fn deserialize_expiry<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let expiry = Option::<u64>::deserialize(deserializer)?;
    if expiry.is_some_and(|seconds| {
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds))
            .is_none()
    }) {
        return Err(serde::de::Error::custom(
            "expires_at_unix_seconds is outside the supported SystemTime range",
        ));
    }
    Ok(expiry)
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
) -> Result<SystemTime, VerifyNecroproofError> {
    let attestation = Nitro::new(necroproof, pcrs.clone())
        .map_err(|source| VerifyNecroproofError::InvalidPcrs { source })?;
    let document = attestation
        .verify_at_attestation_time(Some(&nonce))
        .map_err(|source| VerifyNecroproofError::RejectedByBootproof { source })?;
    let attestation_timestamp = get_timestamp(&document)?;
    let user_data = get_user_data(document)?;
    if user_data != expected_user_data {
        return Err(VerifyNecroproofError::UserDataMismatch);
    }
    Ok(attestation_timestamp)
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

    #[error("keymaker necroproof document does not contain a timestamp")]
    MissingTimestamp,

    #[error("keymaker necroproof timestamp {timestamp} is invalid")]
    InvalidTimestamp { timestamp: i128 },

    #[error("could not decode keymaker necroproof document")]
    DecodeDocument {
        #[source]
        source: serde_cbor::Error,
    },

    #[error("keymaker PCR policy did not contain any PCR sets")]
    NoPcrSets,

    #[error("PCR policy expired at Unix second {expires_at_unix_seconds}")]
    PolicyExpired { expires_at_unix_seconds: u64 },

    #[error("keymaker necroproof did not match any PCR set valid at the necroproof timestamp ({attempts} attempts): {details}", details = PcrFailures(.errors))]
    NoMatchingPcrSet {
        attempts: usize,
        errors: Vec<(usize, VerifyNecroproofError)>,
    },
}

// Error::source exposes one chain; show every attempted set without dumping proof data.
struct PcrFailures<'a>(&'a [(usize, VerifyNecroproofError)]);

impl std::fmt::Display for PcrFailures<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (position, (index, error)) in self.0.iter().enumerate() {
            if position != 0 {
                f.write_str("; ")?;
            }
            write!(f, "set {index}: {error}")?;
            let mut source = std::error::Error::source(error);
            while let Some(cause) = source {
                write!(f, ": {cause}")?;
                source = cause.source();
            }
        }
        Ok(())
    }
}

#[derive(Debug, serde::Deserialize)]
struct OpaqueContainsUserData {
    user_data: serde_bytes::ByteBuf,
}

fn get_timestamp(document: &CborValue) -> Result<SystemTime, VerifyNecroproofError> {
    let CborValue::Map(map) = document else {
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

    // This proof is only a deterministic test checksum, never Nitro evidence.
    #[cfg(feature = "unsafe-e2e")]
    if std::env::var("CAUTION_UNSAFE_KEY_SERVICE_E2E").as_deref() == Ok("1")
        && policy.sets.len() == 1
        && policy.sets[0].expires_at_unix_seconds.is_none()
        && policy.sets[0].pcrs.len() == 3
        && (0..=2).all(|index| {
            policy.sets[0]
                .pcrs
                .get(&index)
                .is_some_and(|pcr| pcr == &[0xab; 48])
        })
        && response.necroproof == nonce
    {
        tracing::warn!("accepting synthetic Keymaker proof in unsafe-e2e build");
        return Ok(response.data);
    }

    policy
        .verify_necroproof(&response.necroproof, &nonce, &bundle_hash)
        .map_err(|source| LoadQuorumBundleError::VerifyNecroproof { source })?;

    Ok(response.data)
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn policy_expiry_rejects_overflow_and_accepts_optional_values() {
        for expiry in [None, Some(serde_json::Value::Null), Some(10.into())] {
            let mut set = serde_json::json!({"pcrs": {"0": "0a"}});
            if let Some(expiry) = expiry {
                set["expires_at_unix_seconds"] = expiry;
            }
            let json = serde_json::json!({"sets": [set]}).to_string();
            KeymakerPcrPolicy::from_json(&json).unwrap();
        }
        let json = serde_json::json!({"sets": [{
            "pcrs": {"0": "0a"},
            "expires_at_unix_seconds": u64::MAX
        }]})
        .to_string();
        let error = KeymakerPcrPolicy::from_json(&json).unwrap_err();
        let ParseKeymakerPcrPolicyError::ParseJson { source } = error;
        assert!(source.to_string().contains("expires_at_unix_seconds"));
        assert!(!pcr_set(1, Some(u64::MAX)).is_valid_at(SystemTime::UNIX_EPOCH));
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
}

#[cfg(test)]
#[path = "bundle_verification_tests.rs"]
mod verification_tests;
