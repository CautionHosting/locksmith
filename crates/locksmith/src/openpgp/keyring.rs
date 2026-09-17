use dterror::*;
use keymaker_models::generate_quorum::v1::Key;
use sequoia_openpgp::{armor, cert::CertParser, parse::Parse, serialize::Serialize};
use std::panic::Location;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReconstructKeyringErrorKind {
    EmptyKeyring,
    EmptyEntry(usize),
    ParseEntry(usize),
    Serialize,
}

#[derive(Debug, thiserror::Error)]
#[error("could not reconstruct OpenPGP keyring ({kind:?}) [{location}]")]
pub(crate) struct ReconstructKeyringError {
    kind: ReconstructKeyringErrorKind,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    location: &'static Location<'static>,
}

impl FromContexts for ReconstructKeyringError {
    type LongLivedContext = ();
    type ShortLivedContext = ReconstructKeyringErrorKind;

    fn from_contexts(
        (): (),
        kind: Self::ShortLivedContext,
        location: &'static Location<'static>,
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    ) -> Self {
        Self {
            kind,
            source: Some(source),
            location,
        }
    }
}

impl ReconstructKeyringError {
    #[track_caller]
    fn without_source(kind: ReconstructKeyringErrorKind) -> Self {
        Self {
            kind,
            source: None,
            location: Location::caller(),
        }
    }
}

/// Build a transient, single armor block for parsers that stop at the first block.
/// The original certificate strings remain part of the unchanged proofed bundle.
pub(crate) fn reconstruct_keyring(keys: &[Key]) -> Result<String, ReconstructKeyringError> {
    use ReconstructKeyringErrorKind as Kind;

    if keys.is_empty() {
        return Err(ReconstructKeyringError::without_source(Kind::EmptyKeyring));
    }
    let mut output = armor::Writer::new(Vec::new(), armor::Kind::PublicKey)
        .with_contexts((), Kind::Serialize)?;
    for (index, key) in keys.iter().enumerate() {
        // Both custody choices authenticate the existing receiver request with
        // this holder certificate. WebAuthn authorization stays in the custody enclave.
        let (Key::OpenPGP { cert } | Key::WebAuthn { cert, .. }) = key;
        if cert.trim().is_empty() {
            return Err(ReconstructKeyringError::without_source(Kind::EmptyEntry(
                index,
            )));
        }
        // dterror 0.1 requires Error, which Sequoia's anyhow::Error does not implement.
        let parser = CertParser::from_bytes(cert).map_err(|source| {
            ReconstructKeyringError::from_contexts(
                (),
                Kind::ParseEntry(index),
                Location::caller(),
                source.into(),
            )
        })?;
        let mut count = 0;
        for certificate in parser {
            let certificate = certificate.map_err(|source| {
                ReconstructKeyringError::from_contexts(
                    (),
                    Kind::ParseEntry(index),
                    Location::caller(),
                    source.into(),
                )
            })?;
            certificate.serialize(&mut output).map_err(|source| {
                ReconstructKeyringError::from_contexts(
                    (),
                    Kind::Serialize,
                    Location::caller(),
                    source.into(),
                )
            })?;
            count += 1;
        }
        if count == 0 {
            return Err(ReconstructKeyringError::without_source(Kind::EmptyEntry(
                index,
            )));
        }
    }
    let output = output.finalize().with_contexts((), Kind::Serialize)?;
    Ok(String::from_utf8(output).expect("ASCII armor is UTF-8"))
}

#[cfg(all(test, feature = "rpgpie"))]
#[path = "keyring_tests.rs"]
mod tests;
