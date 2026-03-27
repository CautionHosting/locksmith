use keymaker_models::generate_quorum::GenerateQuorumResponse;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let bundle_text = std::fs::read_to_string("/bundle.json").expect("has bundle");
    let bundle: GenerateQuorumResponse = serde_json::from_str(&bundle_text).expect("valid json");

    let reconstituted_secret = locksmith::server::receive_shards(
        "0.0.0.0:8080".parse().expect("known address can be parsed"),
        &bundle,
    )
    .await
    .expect("can get shards");
    // /usr/bin/locksmith-oneshot /etc/caution
}
