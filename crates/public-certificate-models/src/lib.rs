/// Data together with its Caution necroproof.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proofed<T> {
    /// The data covered by `necroproof`.
    pub data: T,

    /// Necroproof over `data`.
    pub necroproof: Vec<u8>,
}

/// Request to derive a bundle of public OpenPGP certificates.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "version")]
pub enum PublicCertificateRequest {
    V1(v1::PublicCertificateRequest),
}

impl PublicCertificateRequest {
    /// Converts a versioned request into the latest request schema.
    #[must_use]
    pub fn to_latest(self) -> v1::PublicCertificateRequest {
        match self {
            Self::V1(request) => request,
        }
    }
}

/// Versioned public certificate bundle covered by a necroproof.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "version")]
pub enum PublicCertificateBundle {
    V1(v1::PublicCertificateBundle),
}

impl PublicCertificateBundle {
    /// Converts a versioned bundle into the latest bundle schema.
    #[must_use]
    pub fn to_latest(self) -> v1::PublicCertificateBundle {
        match self {
            Self::V1(bundle) => bundle,
        }
    }
}

/// Response returned by the public certificate service.
pub type PublicCertificateResponse = Proofed<PublicCertificateBundle>;

pub mod v1 {
    use std::num::NonZeroU8;

    /// Request to derive a bundle of public OpenPGP certificates.
    #[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct PublicCertificateRequest {
        /// Organization UUID, encoded as its canonical 16-byte representation.
        pub organization_id: [u8; 16],

        /// Non-zero number of certificates requested in the bundle.
        pub certificate_count: NonZeroU8,
    }

    /// Public certificate bundle covered by a necroproof.
    #[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct PublicCertificateBundle {
        /// Organization UUID, encoded as its canonical 16-byte representation.
        pub organization_id: [u8; 16],

        /// Per-request bundle UUID, encoded as its canonical 16-byte representation.
        pub bundle_id: [u8; 16],

        /// ASCII-armored public OpenPGP certificates. Each certificate contains its immutable
        /// certificate index as a self-notation and an embedded Caution team CA UID
        /// certification signature.
        pub certificates: Vec<String>,
    }
}
