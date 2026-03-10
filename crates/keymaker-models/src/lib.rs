pub mod generate_quorum {
    use std::collections::HashMap;

    #[derive(serde::Serialize, serde::Deserialize)]
    pub struct GenerateQuorumRequest {
        pub label: HashMap<String, String>,
        pub threshold: u8,
        pub max: u8,
        pub keyring: String,
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    pub struct GenerateQuorumResponse {
        pub label: HashMap<String, String>,
        pub keyring: String,
        pub keyring_hash: Vec<u8>,
        pub shardfile: String,
        pub public_key: String,
        pub necroproof: Vec<u8>,
    }
}
