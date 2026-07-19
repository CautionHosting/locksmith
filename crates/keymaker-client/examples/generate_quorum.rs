use keymaker_client::{
    KeymakerClient,
    models::generate_quorum::{GenerateQuorumRequest, v1},
};

#[tokio::main]
async fn main() {
    let client = KeymakerClient::new(Default::default(), "http://localhost:8080".parse().unwrap());
    let request = GenerateQuorumRequest::V1(v1::GenerateQuorumRequest {
        bundle_id: [0; 16],
        label: Default::default(),
        threshold: 2,
        max: 4,
        keyring: vec![v1::Key::OpenPGP {
            cert: std::fs::read_to_string("keyring.asc")
                .expect("should be able to find static keyring"),
        }],
    });

    let response = client.generate_quorum(request).await.unwrap();
    let encoded = serde_json::to_string(&response).expect("could serialize json");
    std::fs::write("new-bundle.json", encoded).expect("could write bundle");
}
