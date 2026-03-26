use keymaker_client::{KeymakerClient, models::generate_quorum::GenerateQuorumRequest};

#[tokio::main]
async fn main() {
    let client = KeymakerClient::new(Default::default(), "http://localhost:8080".parse().unwrap());
    let request = GenerateQuorumRequest {
        label: Default::default(),
        threshold: 1,
        max: 1,
        keyring: std::fs::read_to_string("keyring.asc")
            .expect("should be able to find static keyring"),
    };

    let response = client.generate_quorum(request).await.unwrap();
    let encoded = serde_json::to_string(&response).expect("could serialize json");
    std::fs::write("bundle.json", encoded).expect("could write bundle");
}
