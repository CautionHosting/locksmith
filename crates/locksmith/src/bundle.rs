use keymaker_models::generate_quorum::{self, v1};

pub fn load_json(
    input: &str,
) -> Result<generate_quorum::GenerateQuorumResponse, LoadQuorumBundleError> {
    serde_json::from_str(input).map_err(|source| LoadQuorumBundleError::InvalidJson { source })
}

#[must_use]
pub fn openpgp_keyring(bundle: &generate_quorum::GenerateQuorumResponse) -> String {
    match bundle {
        generate_quorum::GenerateQuorumResponse::V1(bundle) => bundle
            .keyring
            .iter()
            .map(key_cert)
            .collect::<Vec<_>>()
            .join("\n"),
    }
}

#[must_use]
pub fn shardfile(bundle: &generate_quorum::GenerateQuorumResponse) -> &str {
    match bundle {
        generate_quorum::GenerateQuorumResponse::V1(bundle) => &bundle.shardfile,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LoadQuorumBundleError {
    #[error("failed to parse quorum bundle json")]
    InvalidJson {
        #[source]
        source: serde_json::Error,
    },
}

fn key_cert(key: &v1::Key) -> &str {
    match key {
        v1::Key::OpenPGP { cert } | v1::Key::WebAuthn { cert, .. } => cert,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn loads_v1_bundle_and_preserves_model_shape() {
        let bundle = load_json(&v1_bundle_json()).expect("valid v1 bundle loads");

        match bundle {
            generate_quorum::GenerateQuorumResponse::V1(bundle) => {
                assert_eq!(
                    bundle.bundle_id,
                    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
                );
                assert_eq!(
                    bundle.label.get("name").map(String::as_str),
                    Some("structured")
                );
                assert_eq!(bundle.shardfile, "v1 shardfile");
                assert_eq!(bundle.keyring.len(), 2);
                assert!(matches!(
                    bundle.keyring[1],
                    v1::Key::WebAuthn { ref credential, .. }
                        if credential == &vec!["credential-a".to_owned(), "credential-b".to_owned()]
                ));
            }
        }
    }

    #[test]
    fn rejects_legacy_v0_bundle() {
        let legacy = serde_json::json!({
            "label": {"name": "legacy"},
            "keyring": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nlegacy\n-----END PGP PUBLIC KEY BLOCK-----\n",
            "keyring_hash": [1, 2, 3, 4],
            "shardfile": "legacy shardfile",
            "public_key": "legacy public key",
            "necroproof": [5, 6, 7, 8]
        })
        .to_string();

        let error = load_json(&legacy).expect_err("legacy v0 bundle is no longer supported");

        assert!(error.to_string().contains("quorum bundle json"));
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut value: serde_json::Value = serde_json::from_str(&v1_bundle_json()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("version".into(), serde_json::json!("V2"));

        let error = load_json(&value.to_string()).expect_err("future version fails");

        assert!(error.to_string().contains("quorum bundle json"));
    }

    #[test]
    fn openpgp_keyring_includes_all_certificates_without_flattening_stored_model() {
        let bundle = load_json(&v1_bundle_json()).expect("valid v1 bundle loads");

        assert!(openpgp_keyring(&bundle).contains("openpgp"));
        assert!(openpgp_keyring(&bundle).contains("webauthn"));
        match bundle {
            generate_quorum::GenerateQuorumResponse::V1(bundle) => {
                assert!(matches!(bundle.keyring[1], v1::Key::WebAuthn { .. }));
            }
        }
    }
}
