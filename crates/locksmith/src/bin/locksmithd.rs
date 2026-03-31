use keymaker_models::generate_quorum::GenerateQuorumResponse;
use keyfork_mnemonic::Mnemonic;

#[tokio::main]
async fn get_shards() -> Vec<u8> {
    let bundle_text = std::fs::read_to_string("/etc/caution/bundle.json").expect("has bundle");
    let bundle: GenerateQuorumResponse = serde_json::from_str(&bundle_text).expect("valid json");

    let reconstituted_secret = locksmith::server::receive_shards(
        "0.0.0.0:8084".parse().expect("known address can be parsed"),
        &bundle,
    )
    .await
    .expect("can get shards");

    reconstituted_secret
}

#[tokio::main]
async fn get_shards_test_util() -> Vec<u8> {
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    vec![0u8; 32]
}

#[tokio::main]
async fn run_server(mnemonic: Mnemonic) {
    keyforkd::start_and_run_server(mnemonic).await.expect("could start keyforkd");
}

fn main() {
    // NOTE: tracing_subscriber might not be thread safe
    // tracing_subscriber::fmt::init();

    // SAFETY: Before daemonizing, all threads should be joined. This will be done by the time
    // tokio::main returns.
    // testing value:
    // let secret = get_shards_test_util();
    let secret = get_shards();

    daemonize::Daemonize::new().start().expect("could not fork to background");

    let mnemonic = Mnemonic::try_from_slice(&secret)
        .expect("reconstituted secret was of valid length");
    run_server(mnemonic);
}
