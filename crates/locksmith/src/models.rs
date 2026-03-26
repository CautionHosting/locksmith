#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct GeneratePublicKeyRequest {
    pub nonce: String,
}

// NOTE: Do not include the nonce. The client should store it locally and compare the nonce within
// the attested document for comparison.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct GeneratePublicKeyResponse {
    // NOTE: The hilarious inefficiencies of using Vec<u8> on a JSON serialized object is not
    // lost upon me.
    pub attestation: Vec<u8>,
}
