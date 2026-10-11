mod main_args;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let args = match main_args::parse(
        std::env::args().skip(1),
        std::env::var("KEYMAKER_PCR_POLICY_JSON").ok(),
    ) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("{error}\n{}", main_args::USAGE);
            std::process::exit(2);
        }
    };
    let main_args::Args {
        address,
        bundlefile,
        policyfile,
    } = args;

    let policy_text = std::fs::read_to_string(policyfile).expect("has Keymaker PCR policy");
    let policy = locksmith::bundle::KeymakerPcrPolicy::from_json(&policy_text)
        .expect("valid Keymaker PCR policy JSON");
    let bundle_text = std::fs::read_to_string(bundlefile).expect("has bundle");
    let bundle =
        locksmith::bundle::load_json(&bundle_text, &policy).expect("valid verified bundle json");
    let status = locksmith::client::send_shard(
        address.parse().expect("should pass IP:port, probably port 49504"),
        std::collections::HashMap::from_iter([
            (0, smex::decode_to_vec("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").expect("valid hex")),
            (1, smex::decode_to_vec("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").expect("valid hex")),
            (2, smex::decode_to_vec("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").expect("valid hex")),
        ]),
        &bundle,
        None,
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
