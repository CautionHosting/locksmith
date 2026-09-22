//! Shared PGP recovery fields. V1 proof contracts and custody interfaces stay separate.
use crate::{
    bundle::{KeymakerPcrPolicy, load_response_with_timestamp},
    legacy::{self, Error, ImportedV0},
};
use dterror::ResultExt;
use keymaker_models::generate_quorum::{GenerateQuorumBundle, deterministic_bundle_hash, v1};
use std::{collections::HashMap, time::SystemTime};

#[derive(Clone, Copy)]
pub struct RecoveryView<'a> {
    pub label: &'a HashMap<String, String>,
    pub keyring: &'a [v1::Key],
    pub threshold: u8,
    pub max: u8,
    pub shardfile: &'a str,
    pub public_key: &'a str,
    pub legacy: bool,
}
pub trait RecoverySource {
    fn recovery(&self) -> RecoveryView<'_>;
}
impl RecoverySource for RecoveryView<'_> {
    fn recovery(&self) -> RecoveryView<'_> {
        *self
    }
}
impl RecoverySource for v1::GenerateQuorumResponse {
    fn recovery(&self) -> RecoveryView<'_> {
        RecoveryView {
            label: &self.label,
            keyring: &self.keyring,
            threshold: self.threshold,
            max: self.max,
            shardfile: &self.shardfile,
            public_key: &self.public_key,
            legacy: false,
        }
    }
}
impl RecoverySource for GenerateQuorumBundle {
    fn recovery(&self) -> RecoveryView<'_> {
        let Self::V1(data) = self;
        data.recovery()
    }
}
#[derive(Clone, Debug)]
pub enum LoadedBundle {
    V1(GenerateQuorumBundle),
    ImportedV0(ImportedV0),
}
impl RecoverySource for LoadedBundle {
    fn recovery(&self) -> RecoveryView<'_> {
        match self {
            Self::V1(v) => v.recovery(),
            Self::ImportedV0(v) => v.recovery(),
        }
    }
}
impl LoadedBundle {
    pub fn bundle_id(&self) -> Option<[u8; 16]> {
        match self {
            Self::V1(GenerateQuorumBundle::V1(v)) => Some(v.bundle_id),
            Self::ImportedV0(_) => None,
        }
    }
    pub fn content_hash(&self) -> Result<String, Error> {
        match self {
            Self::V1(v) => Ok(smex::encode_to_string(
                deterministic_bundle_hash(v).with_contexts((), "hash V1 bundle")?,
            )),
            Self::ImportedV0(v) => v.content_hash(),
        }
    }
}
impl From<GenerateQuorumBundle> for LoadedBundle {
    fn from(value: GenerateQuorumBundle) -> Self {
        Self::V1(value)
    }
}

/// Legacy acceptance must be chosen by the caller, never inferred after V1 failure.
pub fn load_recovery_json(
    text: &str,
    policy: Option<&KeymakerPcrPolicy>,
    allow_legacy: bool,
) -> Result<(LoadedBundle, Option<SystemTime>), Error> {
    if legacy::is_imported_json(text)? {
        if !allow_legacy {
            return Err(Error::invalid(
                "ImportedV0 has no Keymaker proof; explicit --allow-legacy is required",
            ));
        }
        return Ok((LoadedBundle::ImportedV0(ImportedV0::from_json(text)?), None));
    }
    let response = serde_json::from_str(text).with_contexts(
        (),
        "expected proofed V1 bundle; raw V0 requires import-legacy",
    )?;
    let policy = policy.ok_or_else(|| Error::invalid("Keymaker PCR policy is required for V1"))?;
    let (bundle, at) = load_response_with_timestamp(response, policy)
        .with_contexts((), "V1 proof verification failed")?;
    Ok((LoadedBundle::V1(bundle), at))
}
