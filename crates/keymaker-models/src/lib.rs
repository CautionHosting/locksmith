#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proofed<T> {
    pub data: T,
    pub necroproof: Vec<u8>,
}

pub mod generate_quorum {
    use sha2::{Digest as _, Sha256};
    use std::collections::HashMap;

    pub mod v0 {
        use super::HashMap;

        #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
        pub struct GenerateQuorumRequest {
            pub label: HashMap<String, String>,
            pub threshold: u8,
            pub max: u8,
            pub keyring: String,
        }

        #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
        pub struct GenerateQuorumResponse {
            pub label: HashMap<String, String>,
            pub keyring: String,
            pub keyring_hash: Vec<u8>,
            pub shardfile: String,
            pub public_key: String,
            // NOTE: Unused.
            pub necroproof: Vec<u8>,
        }
    }

    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    #[serde(tag = "version")]
    pub enum GenerateQuorumRequest {
        V1(v1::GenerateQuorumRequest),
    }

    impl GenerateQuorumRequest {
        #[must_use]
        pub fn to_latest(self) -> v1::GenerateQuorumRequest {
            match self {
                GenerateQuorumRequest::V1(generate_quorum_request) => generate_quorum_request,
            }
        }
    }

    pub type GenerateQuorumResponse = crate::Proofed<GenerateQuorumBundle>;

    #[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(tag = "version")]
    pub enum GenerateQuorumBundle {
        V1(v1::GenerateQuorumResponse),
    }

    impl GenerateQuorumBundle {
        #[must_use]
        pub fn to_latest(self) -> v1::GenerateQuorumResponse {
            match self {
                GenerateQuorumBundle::V1(generate_quorum_response) => generate_quorum_response,
            }
        }
    }

    #[derive(Debug, thiserror::Error)]
    #[error("failed to hash generate quorum bundle")]
    pub struct DeterministicBundleHashError {
        #[source]
        source: serde_cbor::Error,
    }

    pub fn deterministic_bundle_hash(
        bundle: &GenerateQuorumBundle,
    ) -> Result<Vec<u8>, DeterministicBundleHashError> {
        let canonical_value = serde_cbor::value::to_value(bundle)
            .map_err(|source| DeterministicBundleHashError { source })?;
        let encoded = serde_cbor::to_vec(&canonical_value)
            .map_err(|source| DeterministicBundleHashError { source })?;
        let mut hash = Sha256::new();
        hash.update(encoded);
        Ok(hash.finalize().to_vec())
    }

    pub fn deterministic_necroproof_nonce(
        bundle_hash: &[u8],
    ) -> Result<Vec<u8>, DeterministicBundleHashError> {
        let encoded =
            serde_cbor::to_vec(&("keymaker-generate-quorum-necroproof-nonce-v1", bundle_hash))
                .map_err(|source| DeterministicBundleHashError { source })?;
        let mut hash = Sha256::new();
        hash.update(encoded);
        Ok(hash.finalize().to_vec())
    }

    pub mod v1 {
        use super::HashMap;

        /// A key used either for directly decrypting the shard, or authorizing a third party to
        /// decrypt the shard. Every key must containing a signing component and an encryption
        /// component.
        #[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
        pub enum Key {
            /// An OpenPGP certificate used for decrypting the shard and signing the encrypted
            /// payload.
            OpenPGP {
                /// The ASCII Armored OpenPGP certificate.
                cert: String,
            },

            /// A set of WebAuthn credentials used for authorizing decryption of the shard and
            /// signing the encrypted payload, and an OpenPGP certificate for the Caution Shard
            /// Recryption service to derive a matching private key and decrypt the shard.
            WebAuthn {
                /// The WebAuthn credentials.
                credential: Vec<String>,

                /// The ASCII Armored OpenPGP certificate.
                cert: String,
            },
        }

        #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct GenerateQuorumRequest {
            /// A randomly-generated bundle UUID.
            pub bundle_id: [u8; 16],

            /// Any user-readable labels associated with the bundle.
            pub label: HashMap<String, String>,

            /// The threshold of keys used to reconstitute the quorum.
            pub threshold: u8,

            /// The maximum amount of keys - this is equivalent to `self.keyring.len()`.
            pub max: u8,

            /// The public component of keys used to decrypt the shards.
            pub keyring: Vec<Key>,
        }

        #[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct GenerateQuorumResponse {
            /// The provided bundle UUID.
            pub bundle_id: [u8; 16],

            /// The provided labels.
            pub label: HashMap<String, String>,

            /// The provided public keys.
            pub keyring: Vec<Key>,

            /// The v1 Shardfile.
            pub shardfile: String,

            /// The default OpenPGP Certificate of the generated quorum.
            pub public_key: String,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Proofed;
    use super::generate_quorum::{
        GenerateQuorumBundle, GenerateQuorumResponse, deterministic_bundle_hash, v1,
    };
    use std::collections::HashMap;

    fn sample_bundle(label: impl Into<HashMap<String, String>>) -> GenerateQuorumBundle {
        GenerateQuorumBundle::V1(v1::GenerateQuorumResponse {
            bundle_id: [7; 16],
            label: label.into(),
            keyring: vec![v1::Key::OpenPGP {
                cert: "-----BEGIN PGP PUBLIC KEY BLOCK-----\n-----END PGP PUBLIC KEY BLOCK-----"
                    .to_string(),
            }],
            shardfile: "-----BEGIN PGP MESSAGE-----\n-----END PGP MESSAGE-----".to_string(),
            public_key: "-----BEGIN PGP PUBLIC KEY BLOCK-----\n-----END PGP PUBLIC KEY BLOCK-----"
                .to_string(),
        })
    }

    #[test]
    fn proofed_generate_quorum_response_deserializes_tagged_v1_data() {
        let json = r#"
        {
          "data": {
            "version": "V1",
            "bundle_id": [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
            "label": {"name": "demo"},
            "keyring": [{"OpenPGP": {"cert": "cert"}}],
            "shardfile": "shards",
            "public_key": "public"
          },
          "necroproof": [2, 3, 5]
        }
        "#;

        let response: GenerateQuorumResponse = serde_json::from_str(json).expect("valid v1 bundle");

        assert_eq!(response.necroproof, vec![2, 3, 5]);
        assert!(matches!(response.data, GenerateQuorumBundle::V1(_)));
    }

    #[test]
    fn legacy_v0_response_is_not_a_versioned_proofed_bundle() {
        let legacy = r#"
        {
          "label": {},
          "keyring": "cert",
          "keyring_hash": [1, 2, 3],
          "shardfile": "shards",
          "public_key": "public",
          "necroproof": []
        }
        "#;

        assert!(serde_json::from_str::<GenerateQuorumResponse>(legacy).is_err());
    }

    #[test]
    fn deterministic_bundle_hash_is_stable_across_label_order_and_json_roundtrip() {
        let first = sample_bundle(HashMap::from_iter([
            ("name".to_string(), "demo".to_string()),
            ("environment".to_string(), "test".to_string()),
            ("owner".to_string(), "caution".to_string()),
        ]));
        let second = sample_bundle(HashMap::from_iter([
            ("owner".to_string(), "caution".to_string()),
            ("environment".to_string(), "test".to_string()),
            ("name".to_string(), "demo".to_string()),
        ]));
        let roundtripped: GenerateQuorumBundle =
            serde_json::from_str(&serde_json::to_string(&first).expect("serialize bundle"))
                .expect("deserialize bundle");

        let first_hash = deterministic_bundle_hash(&first).expect("hash first");
        assert_eq!(
            first_hash,
            deterministic_bundle_hash(&second).expect("hash second")
        );
        assert_eq!(
            first_hash,
            deterministic_bundle_hash(&roundtripped).expect("hash roundtripped")
        );
    }

    #[test]
    fn deterministic_bundle_hash_covers_data_but_not_necroproof() {
        let data = sample_bundle(HashMap::from_iter([(
            "name".to_string(),
            "demo".to_string(),
        )]));
        let first = Proofed {
            data: data.clone(),
            necroproof: vec![1],
        };
        let second = Proofed {
            data: data.clone(),
            necroproof: vec![2],
        };

        assert_eq!(
            deterministic_bundle_hash(&first.data).expect("hash first"),
            deterministic_bundle_hash(&second.data).expect("hash second")
        );

        let different_data = sample_bundle(HashMap::from_iter([(
            "name".to_string(),
            "other".to_string(),
        )]));
        assert_ne!(
            deterministic_bundle_hash(&data).expect("hash original"),
            deterministic_bundle_hash(&different_data).expect("hash changed")
        );
    }
}
