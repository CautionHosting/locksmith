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

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SendSignedEncryptedShardRequest {
    // The payload is a string containing a JSON encoded SendEncryptedShardRequest
    pub signed_payload: String,
    // The signature is an ASCII Armored OpenPGP detached signature over the signed payload.
    pub signature: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SendEncryptedShardRequest {
    // The payload is a hex-encoded AES-256-GCM encrypted JSON-serialized SendShardRequest
    pub encrypted_payload: String,
    pub public_key: [u8; 32],
}

// This type is serialized using JSON, then encrypted using AES-256-GCM.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SendShardRequest {
    pub shard: Vec<u8>,
    pub threshold: u8,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum SendSignedEncryptedShardResponse {
    Accepted {
        remaining: u8,
    },
    Rejected {
        reason: String,
    }
}
