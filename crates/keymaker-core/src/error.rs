use std::panic::Location;

structstruck::strike! {
    #[structstruck::each[derive(Debug)]]
    #[derive(thiserror::Error)]
    #[error("could not generate quorum [{location}]")]
    #[non_exhaustive]
    pub struct GenerateQuorumError {
        kind: pub enum GenerateQuorumErrorKind {
            Entropy,
            ParseCerts,
            Shard,
            DeriveOpenPGPCert,
            SerializeOpenPGPCert,
        },
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
        location: &'static Location<'static>,
    }
}

impl GenerateQuorumError {
    /// The error kind, used by the HTTP layer to choose a status code.
    pub fn kind(&self) -> &GenerateQuorumErrorKind {
        &self.kind
    }

    /// Construct directly (used by the manual `Shard` arm in `generate_quorum`).
    #[track_caller]
    pub fn new(
        kind: GenerateQuorumErrorKind,
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    ) -> Self {
        Self {
            kind,
            source,
            location: Location::caller(),
        }
    }
}

impl dterror::FromContexts for GenerateQuorumError {
    type LongLivedContext = ();
    type ShortLivedContext = GenerateQuorumErrorKind;

    fn from_contexts(
        _long_lived_ctx: Self::LongLivedContext,
        short_lived_ctx: Self::ShortLivedContext,
        location: &'static Location<'static>,
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    ) -> Self {
        Self {
            kind: short_lived_ctx,
            source: Some(source),
            location,
        }
    }
}
