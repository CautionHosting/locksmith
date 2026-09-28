use dterror::*;
use std::panic::Location;
use structstruck::strike;

#[cfg(feature = "rpgpie")]
pub(crate) mod selected_card;
#[cfg(feature = "rpgpie")]
mod card_prompt;
mod keyring;
pub(crate) mod legacy_decrypt;
pub(crate) use keyring::reconstruct_keyring;

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
            LoadPrivateKeys,
            PromptPrivateKeyPassword,
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
        pub kind: #[non_exhaustive] pub enum VerifyErrorKind {
            SignatureFromFuture,
            LoadCertificates,
            InvalidSignatureCount,
            LoadSignatures,
            AllSignaturesInvalid {
                validation_errors: Vec<Box<dyn std::error::Error + Send + Sync + 'static>>,
            }
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
        pub fn sign(
            certs: &str,
            data: &str,
            opt_private_key_path: Option<&std::path::Path>,
        ) -> Result<String, SignError> {
            unimplemented!("neither rpgpie nor minipgp6 backend were selected");
        }

        pub fn verify_detached(certs: &str, data: &str, signature: &str) -> Result<(), VerifyError> {
            unimplemented!("neither rpgpie nor minipgp6 backend were selected");
        }
    }
}
