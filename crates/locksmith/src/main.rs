use keymaker_models::generate_quorum::GenerateQuorumResponse;

#[tokio::main]
async fn main() {
    let bundle_text = std::fs::read_to_string("bundle.json").expect("has bundle");
    let bundle: GenerateQuorumResponse = serde_json::from_str(&bundle_text).expect("valid json");
    locksmith::client::send_shard(
        "100.22.213.34:8080".parse().expect("valid address"),
        Default::default(),
        &bundle,
    ).await.expect("could send shard");
}
