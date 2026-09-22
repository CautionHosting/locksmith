//! Explicit, proofless import of historical PGP bundles. Never a V1 verification fallback.
use crate::bundle::{RecoverySource, RecoveryView};
use dterror::{FromContexts, ResultExt};
use keyfork_shard::openpgp::EncryptedMessage;
use keymaker_models::generate_quorum::v1::Key;
use sequoia_openpgp::{
    self as pgp, Cert, Packet, PacketPile, cert::CertParser, parse::Parse, policy::NullPolicy,
    serialize::SerializeInto,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    path::Path,
    rc::Rc,
    sync::Mutex,
};

pub type Prompt = Rc<Mutex<Box<dyn keyfork_prompt::PromptHandler>>>;

#[derive(Debug, thiserror::Error)]
#[error("legacy bundle: {message} [{location}]")]
pub struct Error {
    message: &'static str,
    location: &'static std::panic::Location<'static>,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}
impl FromContexts for Error {
    type LongLivedContext = ();
    type ShortLivedContext = &'static str;
    fn from_contexts(
        _: (),
        message: &'static str,
        location: &'static std::panic::Location<'static>,
        source: Box<dyn std::error::Error + Send + Sync>,
    ) -> Self {
        Self {
            message,
            location,
            source: Some(source),
        }
    }
}
impl Error {
    #[track_caller]
    pub(crate) fn invalid(message: &'static str) -> Self {
        Self {
            message,
            location: std::panic::Location::caller(),
            source: None,
        }
    }
}
#[track_caller]
pub(crate) fn pgp_error(source: anyhow::Error) -> Error {
    Error::from_contexts(
        (),
        "OpenPGP operation failed",
        std::panic::Location::caller(),
        source.into(),
    )
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginalV0 {
    label: HashMap<String, String>,
    keyring: String,
    keyring_hash: Vec<u8>,
    shardfile: String,
    public_key: String,
    necroproof: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
enum Format {
    ImportedV0,
}

/// Contains public data only. This tag is NOT evidence of origin or approval.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportedV0 {
    format: Format,
    original: OriginalV0,
    threshold: u8,
    keyring: Vec<Key>,
}
impl RecoverySource for ImportedV0 {
    fn recovery(&self) -> RecoveryView<'_> {
        RecoveryView {
            label: &self.original.label,
            threshold: self.threshold,
            max: self.keyring.len() as u8,
            keyring: &self.keyring,
            shardfile: &self.original.shardfile,
            public_key: &self.original.public_key,
            legacy: true,
        }
    }
}

/// Reject unknown format markers instead of trying V1 and falling back on error.
pub fn is_imported_json(text: &str) -> Result<bool, Error> {
    let value: serde_json::Value =
        serde_json::from_str(text).with_contexts((), "invalid bundle JSON")?;
    match value.get("format") {
        None => Ok(false),
        Some(tag) if tag == "ImportedV0" => Ok(true),
        _ => Err(Error::invalid("unsupported bundle format")),
    }
}

pub(crate) fn certificates(text: &[u8]) -> Result<Vec<Cert>, Error> {
    let certs = CertParser::from_bytes(text)
        .map_err(pgp_error)?
        .collect::<pgp::Result<Vec<_>>>()
        .map_err(pgp_error)?;
    if certs.is_empty() || certs.iter().any(Cert::is_tsk) {
        return Err(Error::invalid(
            "expected public certificates without secret packets",
        ));
    }
    Ok(certs)
}

/// Unlike keyfork's historical parser, malformed packets are errors, not panics.
pub(crate) fn messages(text: &str) -> Result<Vec<EncryptedMessage>, Error> {
    let mut recipients = Vec::new();
    let mut messages = Vec::new();
    for packet in PacketPile::from_bytes(text.as_bytes())
        .map_err(pgp_error)?
        .into_children()
    {
        match packet {
            Packet::PKESK(p) => recipients.push(p),
            Packet::SEIP(s) if !recipients.is_empty() => {
                messages.push(EncryptedMessage::new(&mut recipients, s))
            }
            _ => return Err(Error::invalid("invalid shardfile packet structure")),
        }
    }
    if !recipients.is_empty() || !(2..=255).contains(&messages.len()) {
        return Err(Error::invalid("invalid shardfile message count"));
    }
    Ok(messages)
}
impl OriginalV0 {
    fn validate(&self) -> Result<(Vec<Cert>, Vec<EncryptedMessage>), Error> {
        if !self.necroproof.is_empty() {
            return Err(Error::invalid(
                "expected historical V0 with an empty necroproof",
            ));
        }
        if self.keyring_hash.as_slice() != Sha256::digest(self.keyring.as_bytes()).as_slice() {
            return Err(Error::invalid(
                "keyring checksum mismatch; restore the original bundle (no repair override)",
            ));
        }
        let certs = certificates(self.keyring.as_bytes())?;
        let public = certificates(self.public_key.as_bytes())?;
        if public.len() != 1 {
            return Err(Error::invalid("expected one quorum public certificate"));
        }
        Ok((certs, messages(&self.shardfile)?))
    }
}

fn validate_holders(certs: &[Cert], threshold: u8, message_count: usize) -> Result<(), Error> {
    if threshold == 0
        || usize::from(threshold) > certs.len()
        || certs.len() > 254
        || message_count != certs.len() + 1
    {
        return Err(Error::invalid(
            "threshold, holder count or shard count is inconsistent",
        ));
    }
    let mut identities = HashSet::new();
    let mut material = HashMap::new();
    let policy = NullPolicy::new();
    for (index, cert) in certs.iter().enumerate() {
        if cert.is_tsk() || !identities.insert(cert.fingerprint()) {
            return Err(Error::invalid("duplicate holder or private certificate"));
        }
        // Loading checks historical structure, not every holder’s present authorization.
        // The sender and receiver authorize the actual contribution separately.
        let signing: Vec<_> = cert
            .keys()
            .with_policy(&policy, None)
            .supported()
            .for_signing()
            .collect();
        let encryption: Vec<_> = cert
            .keys()
            .with_policy(&policy, None)
            .for_storage_encryption()
            .collect();
        if signing.is_empty() || encryption.is_empty() {
            return Err(Error::invalid(
                "holder needs structurally valid signing and storage decryption keys",
            ));
        }
        for key in signing
            .iter()
            .map(|k| k.key())
            .chain(encryption.iter().map(|k| k.key()))
        {
            // Key material, not fingerprint: creation timestamps may differ for the same key.
            let mut identity = key.mpis().clone();
            if let pgp::crypto::mpi::PublicKey::ECDH { hash, sym, .. } = &mut identity {
                *hash = pgp::types::HashAlgorithm::SHA256;
                *sym = pgp::types::SymmetricAlgorithm::AES256;
            }
            if material
                .insert(identity, index)
                .is_some_and(|previous| previous != index)
            {
                return Err(Error::invalid(
                    "holders must not share signing or encryption key material",
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn metadata(bytes: &[u8]) -> Result<(u8, Cert, Vec<Cert>), Error> {
    if bytes.len() < 2 || bytes[0] != 1 {
        return Err(Error::invalid("unsupported or truncated shard metadata"));
    }
    let mut certs = certificates(&bytes[2..])?.into_iter();
    let signer = certs
        .next()
        .ok_or_else(|| Error::invalid("missing metadata signing certificate"))?;
    Ok((bytes[1], signer, certs.collect()))
}

impl ImportedV0 {
    pub fn from_json(text: &str) -> Result<Self, Error> {
        let bundle: Self =
            serde_json::from_str(text).with_contexts((), "invalid ImportedV0 artifact")?;
        bundle.validate()?;
        Ok(bundle)
    }
    /// Structural validation only: servers without holder keys cannot check encrypted metadata.
    pub fn validate(&self) -> Result<(), Error> {
        let (original, messages) = self.original.validate()?;
        let mut holders = Vec::new();
        for key in &self.keyring {
            let Key::OpenPGP { cert } = key else {
                return Err(Error::invalid(
                    "ImportedV0 supports only external PGP holders",
                ));
            };
            let parsed = certificates(cert.as_bytes())?;
            if parsed.len() != 1 {
                return Err(Error::invalid("expected one certificate per holder"));
            }
            let cert = parsed.into_iter().next().expect("one certificate checked");
            if !original.iter().any(|candidate| candidate == &cert) {
                return Err(Error::invalid(
                    "imported holder differs from the original keyring",
                ));
            }
            holders.push(cert);
        }
        validate_holders(&holders, self.threshold, messages.len())
    }
    pub fn content_hash(&self) -> Result<String, Error> {
        let value =
            serde_cbor::value::to_value(self).with_contexts((), "canonical legacy artifact")?;
        let bytes = serde_cbor::to_vec(&("caution-imported-v0", value))
            .with_contexts((), "encode legacy artifact")?;
        Ok(smex::encode_to_string(Sha256::digest(bytes)))
    }
}

/// Decrypt only the metadata header. No share or quorum secret is reconstructed.
pub fn import(
    text: &str,
    private_path: Option<&Path>,
    holder: Option<&str>,
    prompt: Prompt,
) -> Result<ImportedV0, Error> {
    let original: OriginalV0 = serde_json::from_str(text)
        .with_contexts((), "expected the original unversioned V0 bundle")?;
    let (certs, messages) = original.validate()?;
    let (bytes, selected) = if let Some(path) = private_path {
        let private = std::fs::read(path).with_contexts((), "read holder private keyring")?;
        let keys = CertParser::from_bytes(&private)
            .map_err(pgp_error)?
            .collect::<pgp::Result<Vec<_>>>()
            .map_err(pgp_error)?;
        let matching: Vec<_> = certs
            .iter()
            .filter(|c| holder.is_none_or(|h| c.fingerprint().to_string().eq_ignore_ascii_case(h)))
            .filter_map(|c| {
                keys.iter()
                    .find(|k| k.is_tsk() && k.fingerprint() == c.fingerprint())
            })
            .collect();
        let [private] = matching.as_slice() else {
            return Err(Error::invalid(
                "select exactly one matching holder with --holder",
            ));
        };
        (
            crate::openpgp::legacy_decrypt::decrypt(&messages[0], private, None, prompt)?,
            private.fingerprint(),
        )
    } else {
        #[cfg(feature = "rpgpie")]
        {
            let selected: Vec<_> = certs
                .iter()
                .filter(|c| {
                    holder.is_none_or(|h| c.fingerprint().to_string().eq_ignore_ascii_case(h))
                })
                .collect();
            let [selected] = selected.as_slice() else {
                return Err(Error::invalid("select one smartcard holder with --holder"));
            };
            let bytes =
                crate::openpgp::selected_card::import_metadata(selected, &messages[0], prompt)
                    .with_contexts((), "decrypt metadata with selected card")?;
            (bytes, selected.fingerprint())
        }
        #[cfg(not(feature = "rpgpie"))]
        {
            return Err(Error::invalid(
                "smartcard support is not compiled in; use --keyring",
            ));
        }
    };
    let (threshold, _, holders) = metadata(&bytes)?;
    if !holders.iter().any(|c| c.fingerprint() == selected) {
        return Err(Error::invalid(
            "selected holder is absent from encrypted metadata",
        ));
    }
    let keyring = holders
        .iter()
        .map(|cert| {
            Ok(Key::OpenPGP {
                cert: String::from_utf8(cert.armored().to_vec().map_err(pgp_error)?)
                    .with_contexts((), "encode public certificate")?,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let imported = ImportedV0 {
        format: Format::ImportedV0,
        original,
        threshold,
        keyring,
    };
    imported.validate()?;
    Ok(imported)
}

/// Safe software release for imported artifacts; recheck the holder-approved metadata before sending a share.
pub(crate) fn decrypt_share(
    view: RecoveryView<'_>,
    private: &Cert,
    index: usize,
    prompt: Prompt,
) -> Result<(Vec<u8>, u8), Error> {
    let messages = messages(view.shardfile)?;
    let bytes =
        crate::openpgp::legacy_decrypt::decrypt(&messages[0], private, None, prompt.clone())?;
    let (threshold, signer, certs) = metadata(&bytes)?;
    if threshold != view.threshold
        || certs.len() != view.keyring.len()
        || messages.len() != certs.len() + 1
    {
        return Err(Error::invalid(
            "imported quorum differs from encrypted metadata",
        ));
    }
    for (cert, key) in certs.iter().zip(view.keyring) {
        let Key::OpenPGP { cert: expected } = key else {
            return Err(Error::invalid("legacy custody must be PGP"));
        };
        if cert != &Cert::from_bytes(expected).map_err(pgp_error)? {
            return Err(Error::invalid(
                "imported holder order differs from encrypted metadata",
            ));
        }
    }
    let share = messages
        .get(index + 1)
        .ok_or_else(|| Error::invalid("unknown holder coordinate"))?;
    let bytes = crate::openpgp::legacy_decrypt::decrypt(share, private, Some(&signer), prompt)?;
    if bytes.len() != 33 || usize::from(bytes[0]) != index + 1 {
        return Err(Error::invalid("share coordinate mismatch"));
    }
    Ok((bytes, threshold))
}

pub fn import_candidates(text: &str) -> Result<Vec<Key>, Error> {
    let original: OriginalV0 =
        serde_json::from_str(text).with_contexts((), "expected original unversioned V0 bundle")?;
    let (certs, _) = original.validate()?;
    certs
        .iter()
        .map(|cert| {
            Ok(Key::OpenPGP {
                cert: String::from_utf8(cert.armored().to_vec().map_err(pgp_error)?)
                    .with_contexts((), "encode public certificate")?,
            })
        })
        .collect()
}
pub fn import_with_default_prompt(
    text: &str,
    private_path: Option<&Path>,
    holder: &str,
) -> Result<ImportedV0, Error> {
    let prompt = keyfork_prompt::default_handler().with_contexts((), "create holder prompt")?;
    import(
        text,
        private_path,
        Some(holder),
        Rc::new(Mutex::new(prompt)),
    )
}

#[cfg(test)]
#[path = "legacy_tests.rs"]
pub(crate) mod tests;
