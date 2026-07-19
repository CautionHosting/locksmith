use keymaker_models::generate_quorum::{self, v0, v1};
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Key {
    OpenPGP {
        cert: String,
    },
    WebAuthn {
        credential: Vec<String>,
        cert: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumBundle {
    pub bundle_id: Option<[u8; 16]>,
    pub label: HashMap<String, String>,
    pub keyring: Vec<Key>,
    pub shardfile: String,
    pub public_key: String,
    pub legacy_keyring_hash: Option<Vec<u8>>,
    pub legacy_necroproof: Option<Vec<u8>>,
}

impl QuorumBundle {
    pub fn load_json(input: &str) -> Result<Self, LoadQuorumBundleError> {
        let value: serde_json::Value = serde_json::from_str(input)
            .map_err(|source| LoadQuorumBundleError::InvalidJson { source })?;

        match version_marker(&value)? {
            Some("V1") => load_v1(value),
            Some(version) => Err(LoadQuorumBundleError::UnsupportedVersion {
                version: version.to_owned(),
            }),
            None => load_v0(value),
        }
    }

    #[must_use]
    pub fn openpgp_keyring(&self) -> String {
        self.keyring
            .iter()
            .map(Key::cert)
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl Key {
    #[must_use]
    pub fn cert(&self) -> &str {
        match self {
            Key::OpenPGP { cert } | Key::WebAuthn { cert, .. } => cert,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LoadQuorumBundleError {
    #[error("failed to parse quorum bundle json")]
    InvalidJson {
        #[source]
        source: serde_json::Error,
    },

    #[error("quorum bundle version field must be a string")]
    InvalidVersionField,

    #[error("unsupported quorum bundle version {version}")]
    UnsupportedVersion { version: String },

    #[error("failed to load v1 quorum bundle: invalid {field}: {reason}")]
    InvalidV1Field {
        field: &'static str,
        reason: &'static str,
    },

    #[error("failed to load v1 quorum bundle")]
    LoadV1 {
        #[source]
        source: serde_json::Error,
    },

    #[error("failed to load legacy v0 quorum bundle")]
    LoadV0 {
        #[source]
        source: serde_json::Error,
    },
}

fn version_marker(value: &serde_json::Value) -> Result<Option<&str>, LoadQuorumBundleError> {
    let Some(version) = value.get("version") else {
        return Ok(None);
    };

    version
        .as_str()
        .map(Some)
        .ok_or(LoadQuorumBundleError::InvalidVersionField)
}

fn load_v1(value: serde_json::Value) -> Result<QuorumBundle, LoadQuorumBundleError> {
    validate_v1_shape(&value)?;
    let response: generate_quorum::GenerateQuorumResponse =
        serde_json::from_value(value).map_err(|source| LoadQuorumBundleError::LoadV1 { source })?;
    let response = response.to_latest();
    convert_v1(response)
}

fn validate_v1_shape(value: &serde_json::Value) -> Result<(), LoadQuorumBundleError> {
    let object = value
        .as_object()
        .ok_or(LoadQuorumBundleError::InvalidV1Field {
            field: "root",
            reason: "expected object",
        })?;

    let bundle_id = object
        .get("bundle_id")
        .ok_or(LoadQuorumBundleError::InvalidV1Field {
            field: "bundle_id",
            reason: "missing required field",
        })?;
    validate_bundle_id(bundle_id)?;

    ensure_field_object(object, "label")?;
    ensure_field_array(object, "keyring")?;
    ensure_field_string(object, "shardfile")?;
    ensure_field_string(object, "public_key")?;

    Ok(())
}

fn validate_bundle_id(value: &serde_json::Value) -> Result<(), LoadQuorumBundleError> {
    let bytes = value
        .as_array()
        .ok_or(LoadQuorumBundleError::InvalidV1Field {
            field: "bundle_id",
            reason: "expected 16-byte array",
        })?;
    if bytes.len() != 16 {
        return Err(LoadQuorumBundleError::InvalidV1Field {
            field: "bundle_id",
            reason: "expected 16-byte array",
        });
    }
    if bytes
        .iter()
        .any(|byte| byte.as_u64().is_none_or(|byte| byte > u64::from(u8::MAX)))
    {
        return Err(LoadQuorumBundleError::InvalidV1Field {
            field: "bundle_id",
            reason: "expected byte values",
        });
    }
    Ok(())
}

fn ensure_field_object(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &'static str,
) -> Result<(), LoadQuorumBundleError> {
    let value = object
        .get(field)
        .ok_or(LoadQuorumBundleError::InvalidV1Field {
            field,
            reason: "missing required field",
        })?;
    if !value.is_object() {
        return Err(LoadQuorumBundleError::InvalidV1Field {
            field,
            reason: "expected object",
        });
    }
    Ok(())
}

fn ensure_field_array(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &'static str,
) -> Result<(), LoadQuorumBundleError> {
    let value = object
        .get(field)
        .ok_or(LoadQuorumBundleError::InvalidV1Field {
            field,
            reason: "missing required field",
        })?;
    if !value.is_array() {
        return Err(LoadQuorumBundleError::InvalidV1Field {
            field,
            reason: "expected array",
        });
    }
    Ok(())
}

fn ensure_field_string(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &'static str,
) -> Result<(), LoadQuorumBundleError> {
    let value = object
        .get(field)
        .ok_or(LoadQuorumBundleError::InvalidV1Field {
            field,
            reason: "missing required field",
        })?;
    match value.as_str() {
        Some(value) if !value.is_empty() => Ok(()),
        Some(_) => Err(LoadQuorumBundleError::InvalidV1Field {
            field,
            reason: "must not be empty",
        }),
        None => Err(LoadQuorumBundleError::InvalidV1Field {
            field,
            reason: "expected string",
        }),
    }
}

fn convert_v1(response: v1::GenerateQuorumResponse) -> Result<QuorumBundle, LoadQuorumBundleError> {
    let keyring = response
        .keyring
        .into_iter()
        .map(convert_v1_key)
        .collect::<Result<Vec<_>, _>>()?;

    if keyring.is_empty() {
        return Err(LoadQuorumBundleError::InvalidV1Field {
            field: "keyring",
            reason: "must contain at least one key",
        });
    }

    Ok(QuorumBundle {
        bundle_id: Some(response.bundle_id),
        label: response.label,
        keyring,
        shardfile: response.shardfile,
        public_key: response.public_key,
        legacy_keyring_hash: None,
        legacy_necroproof: None,
    })
}

fn convert_v1_key(key: v1::Key) -> Result<Key, LoadQuorumBundleError> {
    match key {
        v1::Key::OpenPGP { cert } => {
            if cert.is_empty() {
                return Err(LoadQuorumBundleError::InvalidV1Field {
                    field: "keyring",
                    reason: "OpenPGP cert must not be empty",
                });
            }
            Ok(Key::OpenPGP { cert })
        }
        v1::Key::WebAuthn { credential, cert } => {
            if credential.is_empty() {
                return Err(LoadQuorumBundleError::InvalidV1Field {
                    field: "keyring",
                    reason: "WebAuthn credential list must not be empty",
                });
            }
            if credential.iter().any(String::is_empty) {
                return Err(LoadQuorumBundleError::InvalidV1Field {
                    field: "keyring",
                    reason: "WebAuthn credentials must not be empty",
                });
            }
            if cert.is_empty() {
                return Err(LoadQuorumBundleError::InvalidV1Field {
                    field: "keyring",
                    reason: "WebAuthn cert must not be empty",
                });
            }
            Ok(Key::WebAuthn { credential, cert })
        }
    }
}

fn load_v0(value: serde_json::Value) -> Result<QuorumBundle, LoadQuorumBundleError> {
    let response: v0::GenerateQuorumResponse =
        serde_json::from_value(value).map_err(|source| LoadQuorumBundleError::LoadV0 { source })?;
    Ok(QuorumBundle {
        bundle_id: None,
        label: response.label,
        keyring: vec![Key::OpenPGP {
            cert: response.keyring,
        }],
        shardfile: response.shardfile,
        public_key: response.public_key,
        legacy_keyring_hash: Some(response.keyring_hash),
        legacy_necroproof: Some(response.necroproof),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v0_bundle_json() -> String {
        serde_json::json!({
            "label": {"name": "legacy"},
            "keyring": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nlegacy\n-----END PGP PUBLIC KEY BLOCK-----\n",
            "keyring_hash": [1, 2, 3, 4],
            "shardfile": "legacy shardfile",
            "public_key": "legacy public key",
            "necroproof": [5, 6, 7, 8]
        })
        .to_string()
    }

    fn v1_bundle_json() -> String {
        serde_json::json!({
            "version": "V1",
            "bundle_id": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            "label": {"name": "structured"},
            "keyring": [
                {"OpenPGP": {"cert": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nopenpgp\n-----END PGP PUBLIC KEY BLOCK-----\n"}},
                {"WebAuthn": {"credential": ["credential-a", "credential-b"], "cert": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nwebauthn\n-----END PGP PUBLIC KEY BLOCK-----\n"}}
            ],
            "shardfile": "v1 shardfile",
            "public_key": "v1 public key"
        })
        .to_string()
    }

    #[test]
    fn loads_legacy_v0_bundle_and_upgrades_to_latest_shape() {
        let bundle = QuorumBundle::load_json(&v0_bundle_json()).expect("valid v0 bundle loads");

        assert_eq!(bundle.bundle_id, None);
        assert_eq!(bundle.label.get("name").map(String::as_str), Some("legacy"));
        assert_eq!(
            bundle.legacy_keyring_hash.as_deref(),
            Some(&[1, 2, 3, 4][..])
        );
        assert_eq!(bundle.legacy_necroproof.as_deref(), Some(&[5, 6, 7, 8][..]));
        assert_eq!(
            bundle.keyring,
            vec![Key::OpenPGP {
                cert: "-----BEGIN PGP PUBLIC KEY BLOCK-----\nlegacy\n-----END PGP PUBLIC KEY BLOCK-----\n".into()
            }]
        );
    }

    #[test]
    fn loads_v1_bundle_and_preserves_structured_webauthn_associations() {
        let bundle = QuorumBundle::load_json(&v1_bundle_json()).expect("valid v1 bundle loads");

        assert_eq!(
            bundle.bundle_id,
            Some([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
        );
        assert_eq!(
            bundle.label.get("name").map(String::as_str),
            Some("structured")
        );
        assert_eq!(bundle.legacy_keyring_hash, None);
        assert_eq!(bundle.legacy_necroproof, None);
        assert_eq!(
            bundle.keyring,
            vec![
                Key::OpenPGP {
                    cert: "-----BEGIN PGP PUBLIC KEY BLOCK-----\nopenpgp\n-----END PGP PUBLIC KEY BLOCK-----\n".into()
                },
                Key::WebAuthn {
                    credential: vec!["credential-a".into(), "credential-b".into()],
                    cert: "-----BEGIN PGP PUBLIC KEY BLOCK-----\nwebauthn\n-----END PGP PUBLIC KEY BLOCK-----\n".into()
                },
            ]
        );
    }

    #[test]
    fn rejects_malformed_v1_without_falling_back_to_v0() {
        let mut value: serde_json::Value = serde_json::from_str(&v1_bundle_json()).unwrap();
        value.as_object_mut().unwrap().remove("public_key");
        value
            .as_object_mut()
            .unwrap()
            .insert("keyring_hash".into(), serde_json::json!([9, 9, 9]));
        value
            .as_object_mut()
            .unwrap()
            .insert("necroproof".into(), serde_json::json!([8, 8, 8]));

        let error = QuorumBundle::load_json(&value.to_string()).expect_err("malformed v1 fails");

        assert!(error.to_string().contains("v1 quorum bundle"));
        assert!(error.to_string().contains("public_key"));
    }

    #[test]
    fn rejects_unsupported_version_without_v0_fallback() {
        let mut value: serde_json::Value = serde_json::from_str(&v1_bundle_json()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("version".into(), serde_json::json!("V2"));

        let error = QuorumBundle::load_json(&value.to_string()).expect_err("future version fails");

        assert!(
            error
                .to_string()
                .contains("unsupported quorum bundle version V2")
        );
    }

    #[test]
    fn v1_openpgp_keyring_includes_all_certificates_without_flattening_stored_keys() {
        let bundle = QuorumBundle::load_json(&v1_bundle_json()).expect("valid v1 bundle loads");

        assert!(bundle.openpgp_keyring().contains("openpgp"));
        assert!(bundle.openpgp_keyring().contains("webauthn"));
        assert!(matches!(bundle.keyring[1], Key::WebAuthn { .. }));
    }

    #[test]
    fn rejects_wrong_typed_v1_bundle_id() {
        let mut value: serde_json::Value = serde_json::from_str(&v1_bundle_json()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("bundle_id".into(), serde_json::json!([1, 2, 3]));

        let error = QuorumBundle::load_json(&value.to_string()).expect_err("bad bundle id fails");

        assert!(error.to_string().contains("v1 quorum bundle"));
        assert!(error.to_string().contains("bundle_id"));
    }
}
