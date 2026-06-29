//! Pure quorum-generation logic shared by the `keymaker` and `keymaker-hosted` binaries.
//! No HTTP, no async runtime, no reboot behavior — those are deployment concerns owned by the
//! binaries.

mod certs;
mod error;
mod quorum;

pub use error::{GenerateQuorumError, GenerateQuorumErrorKind};

pub use certs::{ParseCertificatesError, parse_certs};

pub use quorum::{derive_openpgp_cert_from_entropy, generate_quorum, shard_entropy};

#[cfg(feature = "axum")]
pub mod http;
