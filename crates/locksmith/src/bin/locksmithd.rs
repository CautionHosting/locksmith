#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    locksmith::server::receive_shards(
        "127.0.0.1:8080"
            .parse()
            .expect("known address can be parsed"),
    )
    .await
    .expect("can get shards");
}
