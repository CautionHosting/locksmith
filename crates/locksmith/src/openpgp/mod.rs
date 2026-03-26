use dterror::*;
use std::panic::Location;
use structstruck::strike;

#[derive(Debug, thiserror::Error)]
#[error("Invalid PIN length: provided {provided_length} < expected 6")]
pub struct PinLengthError {
    provided_length: usize,
}

strike! {
    #[structstruck::each[derive(Debug)]]
    #[derive(thiserror::Error)]
    #[error("could not sign message ({kind:?}) [{location}]")]
    pub struct SignError {
        kind: #[non_exhaustive] pub enum SignErrorKind {
            LoadCertificates,
            FindMatchingCard,
            NoMatchingCard,
            StartTransaction,
            GetCardStatus,
            InvalidCache,
            GetApplicationIdentifier,
            PromptPIN,
            InvalidPIN,
            VerifyPIN,
            InitCardSlot,
            SignData,
            EncodeSignedData,
        },
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
        location: &'static Location<'static>,
    }
}

impl FromContexts for SignError {
    type LongLivedContext = ();
    type ShortLivedContext = SignErrorKind;

    fn from_contexts(
        _long_lived_ctx: Self::LongLivedContext,
        short_lived_ctx: Self::ShortLivedContext,
        location: &'static std::panic::Location<'static>,
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    ) -> Self {
        Self {
            kind: short_lived_ctx,
            source: source.into(),
            location,
        }
    }
}

strike! {
    #[structstruck::each[derive(Debug)]]
    #[derive(thiserror::Error)]
    #[error("could not verify message ({kind:?}) [{location}]")]
    pub struct VerifyError {
        kind: #[non_exhaustive] pub enum VerifyErrorKind {
            IncompatibleDrift,
            LoadCertificates,
            InvalidSignatureCount,
            LoadSignatures,
            SignData,
        },
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
        location: &'static Location<'static>,
    }
}

impl FromContexts for VerifyError {
    type LongLivedContext = ();
    type ShortLivedContext = VerifyErrorKind;

    fn from_contexts(
        _long_lived_ctx: Self::LongLivedContext,
        short_lived_ctx: Self::ShortLivedContext,
        location: &'static std::panic::Location<'static>,
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    ) -> Self {
        Self {
            kind: short_lived_ctx,
            source: source.into(),
            location,
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(feature = "rpgpie")] {
        mod rpgpie;
        pub use rpgpie::*;
    } else if #[cfg(feature = "minipgp6")] {
        mod minipgp6;
        pub use minipgp6::*;
    } else {
        pub fn sign(certs: &str, data: &str) -> Result<String, SignError> {
            unimplemented!("neither rpgpie nor minipgp6 backend were selected");
        }
    }
}
