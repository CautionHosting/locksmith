use keymaker_client::{
    KeymakerClient,
    models::generate_quorum::{GenerateQuorumRequest, v1},
};

#[tokio::main]
async fn main() {
    let keyring =
        std::fs::read_to_string("keyring.asc").expect("should be able to find static keyring");
    let keys = split_ascii_armored_openpgp_keys(&keyring);
    let max = u8::try_from(keys.len()).expect("keyring length fits in u8");
    let client = KeymakerClient::new(Default::default(), "http://localhost:8080".parse().unwrap());
    let request = GenerateQuorumRequest::V1(v1::GenerateQuorumRequest {
        bundle_id: [0; 16],
        label: Default::default(),
        threshold: 2,
        max,
        keyring: keys
            .into_iter()
            .map(|cert| v1::Key::OpenPGP { cert })
            .collect(),
    });

    let response = client.generate_quorum(request).await.unwrap();
    let encoded = serde_json::to_string(&response).expect("could serialize json");
    std::fs::write("new-bundle.json", encoded).expect("could write bundle");
}

fn split_ascii_armored_openpgp_keys(keyring: &str) -> Vec<String> {
    const BEGIN: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
    const END: &str = "-----END PGP PUBLIC KEY BLOCK-----";

    let mut keys = Vec::new();
    let mut current = Vec::new();
    for line in keyring.lines() {
        if line == BEGIN {
            current.clear();
        }
        if !current.is_empty() || line == BEGIN {
            current.push(line);
        }
        if line == END && !current.is_empty() {
            keys.push(format!("{}\n", current.join("\n")));
            current.clear();
        }
    }

    keys
}
