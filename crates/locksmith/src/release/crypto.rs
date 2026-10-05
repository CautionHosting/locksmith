//! Software-only key-service operation. The caller must invoke this only after enclave authorization.
use super::{Context, Error};
use crate::models::*;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use dterror::{FromContexts, ResultExt};
use hkdf::Hkdf;
use keymaker_models::generate_quorum::v1;
use sequoia_openpgp::{
    self as pgp, Cert, Packet, PacketPile,
    parse::{Parse, stream::*},
    policy::{NullPolicy, StandardPolicy},
    serialize::stream::*,
};
use sha2::Sha256;
use std::io::Write;
use x25519_dalek::{EphemeralSecret, PublicKey};

fn pgp_error(source: anyhow::Error) -> Error {
    Error::from_contexts(
        (),
        "OpenPGP key-service operation",
        std::panic::Location::caller(),
        source.into(),
    )
}
struct Decryptor {
    private: Cert,
    signer: Cert,
    signed: bool,
}
impl VerificationHelper for Decryptor {
    fn get_certs(&mut self, _: &[pgp::KeyHandle]) -> pgp::Result<Vec<Cert>> {
        Ok(vec![self.signer.clone()])
    }
    fn check(&mut self, structure: MessageStructure) -> pgp::Result<()> {
        let mut signatures = 0;
        for layer in structure {
            if let MessageLayer::SignatureGroup { results } = layer {
                for result in results {
                    result.map_err(|_| anyhow::anyhow!("invalid quorum signature"))?;
                    signatures += 1;
                }
            }
        }
        if signatures != usize::from(self.signed) {
            anyhow::bail!("unexpected quorum signature count");
        }
        Ok(())
    }
}
impl DecryptionHelper for Decryptor {
    fn decrypt<D>(
        &mut self,
        pkesks: &[pgp::packet::PKESK],
        _: &[pgp::packet::SKESK],
        algorithm: Option<pgp::types::SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> pgp::Result<Option<pgp::Fingerprint>>
    where
        D: FnMut(pgp::types::SymmetricAlgorithm, &pgp::crypto::SessionKey) -> bool,
    {
        for key in self
            .private
            .keys()
            .with_policy(&NullPolicy::new(), None)
            .for_storage_encryption()
            .secret()
        {
            let mut pair = key.key().clone().into_keypair()?;
            for packet in pkesks {
                if packet
                    .decrypt(&mut pair, algorithm)
                    .is_some_and(|(a, s)| decrypt(a, &s))
                {
                    return Ok(Some(self.private.fingerprint()));
                }
            }
        }
        anyhow::bail!("selected key cannot decrypt share")
    }
}
/// Decrypt just the selected encrypted message, checking the proof-bound metadata and coordinate.
pub fn recrypt(
    context: &Context,
    bundle: &v1::GenerateQuorumResponse,
    destination: [u8; 32],
    private: Cert,
) -> Result<SendSignedEncryptedShardRequest, Error> {
    if private.fingerprint().to_string() != context.holder {
        return Err(Error::invalid("derived private key fingerprint"));
    }
    // The proof authenticates the complete encrypted shardfile, including its
    // metadata signer. Keyfork derives that signer directly from entropy;
    // bundle.public_key is separately derived from the mnemonic seed.
    let root = private.clone();
    let mut pkesks = Vec::new();
    let mut messages = Vec::new();
    for packet in PacketPile::from_bytes(bundle.shardfile.as_bytes())
        .map_err(pgp_error)?
        .into_children()
    {
        match packet {
            Packet::PKESK(p) => pkesks.push(p),
            Packet::SEIP(s) if !pkesks.is_empty() => messages.push(
                keyfork_shard::openpgp::EncryptedMessage::new(&mut pkesks, s),
            ),
            _ => return Err(Error::invalid("invalid shardfile packet")),
        }
    }
    if !pkesks.is_empty() || messages.len() != bundle.keyring.len() + 1 {
        return Err(Error::invalid("shardfile message count"));
    }
    let helper = |signed| Decryptor {
        private: private.clone(),
        signer: root.clone(),
        signed,
    };
    let metadata = messages[0]
        .decrypt_with(&NullPolicy::new(), helper(false))
        .with_contexts((), "decrypt share metadata")?;
    if metadata.len() < 2 || metadata[0] != 1 || metadata[1] != bundle.threshold {
        return Err(Error::invalid("share metadata version/threshold"));
    }
    let certs = pgp::cert::CertParser::from_bytes(&metadata[2..])
        .map_err(pgp_error)?
        .collect::<pgp::Result<Vec<_>>>()
        .map_err(pgp_error)?;
    if certs.len() != bundle.keyring.len() + 1 {
        return Err(Error::invalid("share metadata keyring"));
    }
    for (cert, key) in certs[1..].iter().zip(&bundle.keyring) {
        let (v1::Key::OpenPGP { cert: expected } | v1::Key::WebAuthn { cert: expected, .. }) = key;
        if cert.fingerprint()
            != Cert::from_bytes(expected.as_bytes())
                .map_err(pgp_error)?
                .fingerprint()
        {
            return Err(Error::invalid("share metadata holder order"));
        }
    }
    let position = usize::from(context.holder_position);
    let message = messages
        .get(position + 1)
        .ok_or_else(|| Error::invalid("holder position"))?;
    let shard = message
        .decrypt_with(
            &NullPolicy::new(),
            Decryptor {
                private: private.clone(),
                signer: certs[0].clone(),
                signed: true,
            },
        )
        .with_contexts((), "decrypt selected share")?;
    if shard.len() != 33 || shard[0] != context.holder_position + 1 {
        return Err(Error::invalid("share coordinate"));
    }
    let request = SendShardRequest {
        shard,
        threshold: bundle.threshold,
        bundle_hash: Some(context.bundle_hash.clone()),
    };
    let secret = EphemeralSecret::random();
    let public_key = PublicKey::from(&secret).to_bytes();
    let shared = secret.diffie_hellman(&PublicKey::from(destination));
    if !shared.was_contributory() {
        return Err(Error::invalid("noncontributory destination key"));
    }
    let hkdf = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    hkdf.expand(b"key", &mut key)
        .with_contexts((), "transport key")?;
    hkdf.expand(b"nonce", &mut nonce)
        .with_contexts((), "transport nonce")?;
    let bytes = serde_json::to_vec(&request).with_contexts((), "share serialization")?;
    let encrypted = Aes256Gcm::new_from_slice(&key)
        .expect("fixed key size")
        .encrypt(Nonce::from_slice(&nonce), bytes.as_slice())
        .with_contexts((), "encrypt share")?;
    let signed_payload = serde_json::to_string(&SendEncryptedShardRequest {
        encrypted_payload: smex::encode_to_string(encrypted),
        public_key,
    })
    .with_contexts((), "transport serialization")?;
    let mut policy = StandardPolicy::new();
    policy.good_critical_notations(&[super::ORG, super::BUNDLE]);
    let signing = private
        .keys()
        .with_policy(&policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_signing()
        .secret()
        .next()
        .ok_or_else(|| Error::invalid("derived signing key"))?;
    let pair = signing.key().clone().into_keypair().map_err(pgp_error)?;
    let mut output = Vec::new();
    let message = Message::new(&mut output);
    let message = Armorer::new(message)
        .kind(pgp::armor::Kind::Signature)
        .build()
        .map_err(pgp_error)?;
    let mut signer = Signer::new(message, pair)
        .detached()
        .build()
        .map_err(pgp_error)?;
    signer
        .write_all(signed_payload.as_bytes())
        .with_contexts((), "sign encrypted share")?;
    signer.finalize().map_err(pgp_error)?;
    let signature = String::from_utf8(output).with_contexts((), "signature armor")?;
    Ok(SendSignedEncryptedShardRequest {
        signed_payload,
        signature,
    })
}

/// The CLI checks the selected holder's signature before forwarding ciphertext.
pub fn verify_request(cert: &str, request: &SendSignedEncryptedShardRequest, at: std::time::SystemTime) -> Result<(), Error> {
    crate::custody::verify_holder_signature(cert, &request.signed_payload, &request.signature, at)
}

/// A single destination connection: attestation and shard submission cannot switch sessions.
pub struct Destination {
    connection: tokio::net::TcpStream,
    pub attestation: Vec<u8>,
}
impl Destination {
    pub async fn connect(address: std::net::SocketAddr, nonce: String) -> Result<Self, Error> {
        let mut connection = tokio::net::TcpStream::connect(address)
            .await
            .with_contexts((), "connect destination")?;
        let response: GeneratePublicKeyResponse =
            crate::send_and_receive(&mut connection, GeneratePublicKeyRequest { nonce })
                .await
                .with_contexts((), "destination attestation")?;
        Ok(Self {
            connection,
            attestation: response.attestation,
        })
    }
    pub async fn send(
        mut self,
        request: SendSignedEncryptedShardRequest,
    ) -> Result<SendSignedEncryptedShardResponse, Error> {
        crate::send_and_receive(&mut self.connection, request)
            .await
            .with_contexts((), "submit recrypted share")
    }
    pub async fn disconnected(&self) {
        let mut byte = [0u8; 1];
        // There should be no unsolicited data before submission; EOF or data aborts approval.
        let _ = self.connection.peek(&mut byte).await;
    }
}
