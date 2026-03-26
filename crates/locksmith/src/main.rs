use keymaker_models::generate_quorum::GenerateQuorumResponse;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let bundle_text = std::fs::read_to_string("bundle.json").expect("has bundle");
    let bundle: GenerateQuorumResponse = serde_json::from_str(&bundle_text).expect("valid json");
    let status = locksmith::client::send_shard(
        "44.224.133.10:8080".parse().expect("valid address"),
        std::collections::HashMap::from_iter([
            (0, smex::decode_to_vec("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").expect("valid hex")),
            (1, smex::decode_to_vec("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").expect("valid hex")),
            (2, smex::decode_to_vec("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").expect("valid hex")),
        ]),
        &bundle,
    ).await.expect("could send shard");
    dbg!(status);
}
