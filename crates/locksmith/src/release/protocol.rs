//! Versioned, attested share-release protocol. No private key or plaintext share is a wire value.
use keymaker_models::generate_quorum::GenerateQuorumResponse;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Version {
    V1,
}
/// Exact PCR0/1/2 measurements approved by the holder. Hex, not an endpoint-provided trust anchor.
pub type Measurements = BTreeMap<u8, String>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeginRequest {
    pub version: Version,
    pub bundle: GenerateQuorumResponse,
    pub holder: String,
    pub destination_policy: Measurements,
    pub client_nonce: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub version: Version,
    pub bundle_hash: String,
    pub bundle_id: [u8; 16],
    pub organization_id: [u8; 16],
    pub holder: String,
    pub holder_position: u8,
    pub certificate_index: u8,
    pub destination_policy: Measurements,
    pub transport_nonce: String,
    pub expires_at_unix_seconds: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Begun {
    pub request_hash: String,
    pub session_id: String,
    pub context: Context,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareRequest {
    pub version: Version,
    pub session_id: String,
    pub destination_attestation: Vec<u8>,
    pub client_nonce: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prepared {
    pub request_hash: String,
    pub session_id: String,
    pub context: Context,
    pub destination_attestation_hash: String,
    pub destination_key: [u8; 32],
    pub options: webauthn_rs::prelude::RequestChallengeResponse,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompleteRequest {
    pub version: Version,
    pub session_id: String,
    pub assertion: webauthn_rs::prelude::PublicKeyCredential,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attested<T> {
    pub data: T,
    pub attestation: Vec<u8>,
}
