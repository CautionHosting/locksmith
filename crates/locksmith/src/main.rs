use keymaker_models::generate_quorum::GenerateQuorumResponse;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let mut args = std::env::args().skip(1);
    let address = args.next().expect("pass in socket address please");
    let bundlefile = args.next().unwrap_or_else(|| "bundle.json".into());

    let bundle_text = std::fs::read_to_string(bundlefile).expect("has bundle");
    let bundle: GenerateQuorumResponse = serde_json::from_str(&bundle_text).expect("valid json");
    let status = locksmith::client::send_shard(
        address.parse().expect("should pass IP:port, probably port 49504"),
        std::collections::HashMap::from_iter([
            (0, smex::decode_to_vec("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").expect("valid hex")),
            (1, smex::decode_to_vec("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").expect("valid hex")),
            (2, smex::decode_to_vec("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").expect("valid hex")),
        ]),
        &bundle,
    ).await.expect("could send shard");

    match status {
        locksmith::models::SendSignedEncryptedShardResponse::Accepted { remaining } => {
            eprintln!("Shard accepted, {remaining} remaining shards until reconstitution");
        }
        locksmith::models::SendSignedEncryptedShardResponse::Rejected { reason } => {
            eprintln!("Unable to send shard: {reason}");
            std::process::exit(1);
        }
    }
}
