use bootproof_sdk::format::{VerifiableSignedAttestationFormat, nitro::Nitro};
use dterror::*;
use keyfork_shard::{Format, openpgp::OpenPGP};
use rand::Rng;
use std::panic::Location;
use std::time::SystemTime;
use structstruck::strike;
use tokio::io::AsyncWriteExt;

// NOTE: We need to inline the keyfork-shard reconstitution system here. We don't have a way to
// detect malicious users, so we need to be able to send _any_ public key and accept arbitrary,
// verifiable payloads. There's also no way to accept multiple payloads at once with the existing
// Keyfork receiver.

strike! {
    #[structstruck::each[derive(Debug)]]
    #[derive(thiserror::Error)]
    #[error("Could not send shard ({kind:?}) [{location}]")]
    pub struct SendShardError {
        kind: pub enum SendShardErrorKind {
            ConnectToRemote,
            ParseShardfile,
            DecryptShard,
            SendFirstPayload,
            ReceiveSecondPayload,
            DeserializeSecondPayload,
            InvalidPCRs,
            VerifyAttestation,
        },
        location: &'static Location<'static>,
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    }
}

impl FromContexts for SendShardError {
    type LongLivedContext = ();
    type ShortLivedContext = SendShardErrorKind;

    fn from_contexts(
        _long_lived_ctx: Self::LongLivedContext,
        short_lived_ctx: Self::ShortLivedContext,
        location: &'static std::panic::Location<'static>,
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    ) -> Self {
        Self {
            kind: short_lived_ctx,
            location,
            source,
        }
    }
}

#[tracing::instrument(skip_all)]
pub async fn send_shard(
    address: std::net::SocketAddr,
    pcrs: std::collections::HashMap<u8, Vec<u8>>,
    bundle: &keymaker_models::generate_quorum::GenerateQuorumResponse,
) -> Result<(), SendShardError> {
    use SendShardErrorKind as ErrorKind;

    // Establish a connection with the server
    let mut connection = tokio::net::TcpStream::connect(address)
        .await
        .with_contexts((), ErrorKind::ConnectToRemote)?;

    // Generate a nonce for attestation purposes
    let mut rng = rand::rngs::OsRng;
    let nonce = {
        let mut nonce = [0u8; 12];
        rng.fill(&mut nonce);
        nonce
    };
    let nonce_hex = smex::encode_to_string(nonce);

    // Send our nonce and receive the server's public key
    let request = crate::models::GeneratePublicKeyRequest {
        nonce: nonce_hex.clone(),
    };
    let request_string = serde_json::to_string(&request).expect("request is serializable");
    let framed_request =
        keyfork_frame::try_encode(request_string.as_bytes()).expect("nonce is < u32::MAX bytes");
    connection
        .write_all(&framed_request)
        .await
        .with_contexts((), ErrorKind::SendFirstPayload)?;

    // Receive the attested nonce and public key
    let response_bytes = keyfork_frame::asyncext::try_decode_from(&mut connection)
        .await
        .with_contexts((), ErrorKind::ReceiveSecondPayload)?;
    let response: crate::models::GeneratePublicKeyResponse =
        serde_json::from_slice(&response_bytes)
            .with_contexts((), ErrorKind::DeserializeSecondPayload)?;
    let attestation = Nitro::new(response.attestation, pcrs)
        .with_contexts((), ErrorKind::InvalidPCRs)?;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("time is linear");
    let document = attestation
        .verify(duration, &nonce_hex)
        .with_contexts((), ErrorKind::VerifyAttestation)?;

    // NOTE: Sin will be committed here.
    // We can't make use of the builtin Keyfork encryption mechanism. It relies on the Transfer
    // trait which is not actually usable when it comes to asynchronous enclaves.
    //
    // The actual cryptography behind it is the same. The only thing we need to do is ensure that
    // the enclave attests the first primary key alongside the nonce generated before, and the
    // server needs to verify incoming shards _before_ reconstituting, which means the server needs
    // to be aware of the keyring.
    let temp_ph = std::rc::Rc::new(std::sync::Mutex::new(
        keyfork_prompt::default_handler().expect("please give us a handler"),
    ));
    let messages = OpenPGP
        .parse_shard_file(bundle.shardfile.as_bytes())
        .with_contexts((), ErrorKind::ParseShardfile)?;
    let shard = OpenPGP
        .decrypt_one_shard(None, &messages, temp_ph)
        .with_contexts((), ErrorKind::DecryptShard)?;

    todo!("we have a shard, need to send it");

    todo!()
}
