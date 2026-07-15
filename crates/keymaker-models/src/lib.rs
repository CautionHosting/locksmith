#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Proofed<T> {
    data: T,
    necroproof: Vec<u8>,
}

pub mod generate_quorum {
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

    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    pub enum GenerateQuorumResponse {
        V1(v1::GenerateQuorumResponse),
    }

    impl GenerateQuorumResponse {
        #[must_use]
        pub fn to_latest(self) -> v1::GenerateQuorumResponse {
            match self {
                GenerateQuorumResponse::V1(generate_quorum_response) => generate_quorum_response,
            }
        }
    }

    pub mod v1 {
        use super::HashMap;

        /// A key used either for directly decrypting the shard, or authorizing a third party to
        /// decrypt the shard. Every key must containing a signing component and an encryption
        /// component.
        #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
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
        pub struct GenerateQuorumRequest {
            /// A randomly-generated bundle UUID.
            pub bundle_id: [u8; 32],

            /// Any user-readable labels associated with the bundle.
            pub label: HashMap<String, String>,

            /// The threshold of keys used to reconstitute the quorum.
            pub threshold: u8,

            /// The maximum amount of keys - this is equivalent to `self.keyring.len()`.
            pub max: u8,

            /// The public component of keys used to decrypt the shards.
            pub keyring: Vec<Key>,
        }

        #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
        pub struct GenerateQuorumResponse {
            /// The provided bundle UUID.
            pub bundle_id: [u8; 32],

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
