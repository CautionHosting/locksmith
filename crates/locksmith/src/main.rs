use keymaker_models::generate_quorum::GenerateQuorumResponse;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let bundle_text = std::fs::read_to_string("bundle.json").expect("has bundle");
    let bundle: GenerateQuorumResponse = serde_json::from_str(&bundle_text).expect("valid json");
    let status = locksmith::client::send_shard(
        "184.32.255.23:8080".parse().expect("valid address"),
        std::collections::HashMap::from_iter([
            (0, smex::decode_to_vec("29bb516eb83182de0bb2f155e2666927ec67a67eb387eb6294be5df9a926521f39dff725c68264960fca987ecc9ebe55").expect("valid hex")),
            (1, smex::decode_to_vec("29bb516eb83182de0bb2f155e2666927ec67a67eb387eb6294be5df9a926521f39dff725c68264960fca987ecc9ebe55").expect("valid hex")),
            (2, smex::decode_to_vec("21b9efbc184807662e966d34f390821309eeac6802309798826296bf3e8bec7c10edb30948c90ba67310f7b964fc500a").expect("valid hex")),
        ]),
        &bundle,
    ).await.expect("could send shard");
    dbg!(status);
}
