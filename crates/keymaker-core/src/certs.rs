use sequoia_openpgp::cert::{Cert, CertParser};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use std::panic::Location;
use tracing::warn;

#[derive(Debug, thiserror::Error)]
#[error("could not parse valid certificates [{location}]")]
pub struct ParseCertificatesError {
    location: &'static Location<'static>,
    #[source]
    source: anyhow::Error,
}

impl From<anyhow::Error> for ParseCertificatesError {
    #[track_caller]
    fn from(source: anyhow::Error) -> Self {
        Self {
            location: Location::caller(),
            source,
        }
    }
}

/// Parse an armored keyring, keeping only certs that expose **both** an authentication key and a
/// storage-encryption key under the standard policy. Others are dropped with a warning.
pub fn parse_certs(armored_input: &str) -> Result<Vec<Cert>, ParseCertificatesError> {
    let cert_parser = CertParser::from_bytes(armored_input.as_bytes())?;
    let mut certs = vec![];
    let policy = StandardPolicy::new();

    for parseable_cert in cert_parser {
        let cert = parseable_cert?;
        let valid_cert = cert.with_policy(&policy, None)?;
        let has_auth = valid_cert.keys().for_authentication().next().is_some();
        let has_enc = valid_cert.keys().for_storage_encryption().next().is_some();

        if has_auth && has_enc {
            certs.push(cert);
        } else {
            warn!(
                ?has_auth,
                ?has_enc,
                key_id = ?valid_cert.keyid(),
                "key does not have both auth and enc"
            );
        }
    }

    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sequoia_openpgp::cert::CertBuilder;
    use sequoia_openpgp::serialize::SerializeInto;

    /// Armor a cert's public half to a String so `parse_certs` (which takes armored text) can read it.
    fn armored_public(cert: &sequoia_openpgp::cert::Cert) -> String {
        let bytes = cert.armored().to_vec().expect("armor public cert");
        String::from_utf8(bytes).expect("armor is ascii")
    }

    #[test]
    fn keeps_cert_with_both_auth_and_enc() {
        let (cert, _) = CertBuilder::new()
            .add_userid("valid")
            .add_authentication_subkey()
            .add_storage_encryption_subkey()
            .generate()
            .unwrap();
        let certs = parse_certs(&armored_public(&cert)).unwrap();
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn drops_cert_missing_encryption_subkey() {
        let (cert, _) = CertBuilder::new()
            .add_userid("auth-only")
            .add_authentication_subkey()
            .generate()
            .unwrap();
        let certs = parse_certs(&armored_public(&cert)).unwrap();
        assert!(certs.is_empty());
    }

    #[test]
    fn drops_cert_missing_authentication_subkey() {
        let (cert, _) = CertBuilder::new()
            .add_userid("enc-only")
            .add_storage_encryption_subkey()
            .generate()
            .unwrap();
        let certs = parse_certs(&armored_public(&cert)).unwrap();
        assert!(certs.is_empty());
    }
}
