use dterror::ResultExt as _;
use keyfork_derive_openpgp::derive_util as derive;
use keyfork_shard::{
    Format,
    openpgp::{OpenPGP, openpgp},
};
use openpgp::{
    cert::Cert,
    packet::UserID,
    serialize::Serialize as _,
    types::KeyFlags,
};
use sha2::{Digest, Sha256};
use tracing::{debug, warn};

use crate::certs::parse_certs;
use crate::error::{GenerateQuorumError, GenerateQuorumErrorKind};
use keymaker_models::generate_quorum::{GenerateQuorumRequest, GenerateQuorumResponse};

fn hash_keyring(keyring: &[u8]) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(keyring);
    hash.finalize().to_vec()
}

/// Deterministically derive an OpenPGP cert (account 0) from 32 bytes of entropy.
pub fn derive_openpgp_cert_from_entropy(entropy: &[u8; 32]) -> Result<Cert, GenerateQuorumError> {
    use GenerateQuorumErrorKind as ErrorKind;

    let userid = UserID::from("Keymaker-generated key");
    let mnemonic = keyfork_mnemonic::Mnemonic::from_array(*entropy);
    let seed = mnemonic.generate_seed(None);
    let xprv =
        keyfork_derive_openpgp::XPrv::new(seed).expect("const length Ed25519 key is always valid");
    let index = derive::DerivationIndex::new(0, true).expect("account 0 is always valid");
    let path = keyfork_derive_path_data::paths::OPENPGP
        .clone()
        .chain_push(index);

    let subkeys = [
        KeyFlags::empty().set_certification(),
        KeyFlags::empty().set_signing(),
        KeyFlags::empty()
            .set_transport_encryption()
            .set_storage_encryption(),
        KeyFlags::empty().set_authentication(),
    ];

    keyfork_derive_openpgp::derive(
        &xprv
            .derive_path(&path)
            .with_contexts((), ErrorKind::DeriveOpenPGPCert)?,
        &subkeys,
        &userid,
    )
    .with_contexts((), ErrorKind::DeriveOpenPGPCert)
}

/// Shamir-shard `entropy` across `certs` and OpenPGP-encrypt each share. Returns the armored shardfile.
pub fn shard_entropy(
    threshold: u8,
    max: u8,
    entropy: &[u8; 32],
    certs: &[Cert],
) -> Result<String, GenerateQuorumError> {
    let opgp = OpenPGP;
    let mut shardfile_bytes = vec![];
    opgp.shard_and_encrypt(threshold, max, entropy, certs, &mut shardfile_bytes)
        .map_err(|source| {
            warn!("untraceable shard error: {source}");
            GenerateQuorumError::new(GenerateQuorumErrorKind::Shard, None)
        })?;
    Ok(String::try_from(shardfile_bytes).expect("should always get utf8 encoded bytes"))
}

/// Generate quorum material: fresh entropy, sharded to the request's keyring, plus a derived
/// public cert. Returns the bundle. No secret material is retained after return.
pub fn generate_quorum(
    req: GenerateQuorumRequest,
) -> Result<GenerateQuorumResponse, GenerateQuorumError> {
    use GenerateQuorumErrorKind as ErrorKind;
    let GenerateQuorumRequest {
        label,
        threshold,
        max,
        keyring,
    } = req;

    let keyring_hash = hash_keyring(keyring.as_bytes());
    debug!(?label, ?threshold, ?max, ?keyring_hash);
    keyfork_entropy::ensure_safe();

    let certs = parse_certs(&keyring)
        .map_err(|e| GenerateQuorumError::new(ErrorKind::ParseCerts, Some(Box::new(e))))?;

    let entropy: [u8; 32] =
        keyfork_entropy::generate_entropy_of_const_size().with_contexts((), ErrorKind::Entropy)?;

    let shardfile = shard_entropy(threshold, max, &entropy, &certs)?;
    let cert = derive_openpgp_cert_from_entropy(&entropy)?;

    let mut public_key_bytes = vec![];
    let mut armored = openpgp::armor::Writer::new(
        &mut public_key_bytes,
        openpgp::armor::Kind::PublicKey,
    )
    .with_contexts((), ErrorKind::SerializeOpenPGPCert)?;
    cert.serialize(&mut armored)
        .map_err(|source| {
            GenerateQuorumError::new(
                ErrorKind::SerializeOpenPGPCert,
                Some(source.into_boxed_dyn_error()),
            )
        })?;
    armored
        .finalize()
        .with_contexts((), ErrorKind::SerializeOpenPGPCert)?;

    let public_key =
        String::try_from(public_key_bytes).expect("should always get valid utf8 from armor");

    Ok(GenerateQuorumResponse {
        label,
        keyring,
        keyring_hash,
        shardfile,
        public_key,
        necroproof: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyfork_shard::{Format, openpgp::OpenPGP};
    use sequoia_openpgp::cert::CertBuilder;
    use sequoia_openpgp::serialize::SerializeInto;

    const ENTROPY: [u8; 32] = [7u8; 32];

    /// A test TSK (with secret material) that has both auth and storage-enc subkeys.
    fn test_member() -> sequoia_openpgp::cert::Cert {
        CertBuilder::new()
            .add_userid("member")
            .add_authentication_subkey()
            .add_storage_encryption_subkey()
            .generate()
            .unwrap()
            .0
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = derive_openpgp_cert_from_entropy(&ENTROPY).unwrap();
        let b = derive_openpgp_cert_from_entropy(&ENTROPY).unwrap();
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn shards_round_trip_to_the_original_entropy() {
        let members: Vec<_> = (0..3).map(|_| test_member()).collect();
        let shardfile = shard_entropy(2, 3, &ENTROPY, &members).unwrap();

        let recovered = OpenPGP
            .decrypt_all_shards_to_secret(
                Some(&members[..]),
                std::io::Cursor::new(shardfile.as_bytes()),
                Box::new(keyfork_prompt::headless::Headless::new()),
            )
            .expect("recover secret from a quorum of shards");

        assert_eq!(recovered, ENTROPY.to_vec());
    }

    #[test]
    fn generate_quorum_returns_a_valid_bundle() {
        // `keyfork_entropy::ensure_safe()` is an airgap guard: it aborts unless every non-`lo`
        // network interface is down (only true inside a real Nitro enclave, which is vsock-only)
        // or one of keyfork's documented bypass vars is set. Set the bypass so this test can
        // exercise the full `generate_quorum` path on an ordinary networked CI/dev host. Setting
        // it process-wide is safe here: it only *relaxes* the guard, and no test asserts the guard
        // is active.
        unsafe { std::env::set_var("SHOOT_SELF_IN_FOOT", "1") };

        use sequoia_openpgp::cert::Cert;
        use sequoia_openpgp::parse::Parse;
        use std::collections::HashMap;

        let members: Vec<_> = (0..3).map(|_| test_member()).collect();
        let keyring: String = members
            .iter()
            .map(|c| String::from_utf8(c.armored().to_vec().unwrap()).unwrap())
            .collect();

        let req = keymaker_models::generate_quorum::GenerateQuorumRequest {
            label: HashMap::new(),
            threshold: 2,
            max: 3,
            keyring: keyring.clone(),
        };
        let resp = generate_quorum(req).unwrap();

        // public_key parses as a valid OpenPGP cert
        Cert::from_bytes(resp.public_key.as_bytes()).expect("public_key is a valid cert");
        // keyring is echoed back and hashed with SHA-256
        assert_eq!(resp.keyring, keyring);
        assert_eq!(resp.keyring_hash.len(), 32);
        assert!(!resp.shardfile.is_empty());
    }
}
