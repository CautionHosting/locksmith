//! Bounded service work; the custody root remains owned by the enclave runtime.
use dterror::{FromContexts, ResultExt};
use keyfork_derive_openpgp::XPrvKey;
use keyfork_derive_util::DerivationPath;
use sequoia_openpgp::Cert;
use std::time::{Duration, Instant};

pub const REQUEST_BUDGET: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
#[error("certificate service unavailable ({kind}) [{location}]")]
pub struct Error {
    kind: &'static str,
    location: &'static std::panic::Location<'static>,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}
impl FromContexts for Error {
    type LongLivedContext = ();
    type ShortLivedContext = &'static str;
    fn from_contexts(
        _: (),
        kind: &'static str,
        location: &'static std::panic::Location<'static>,
        source: Box<dyn std::error::Error + Send + Sync>,
    ) -> Self {
        Self {
            kind,
            location,
            source: Some(source),
        }
    }
}
impl Error {
    #[track_caller]
    pub(crate) fn unavailable(kind: &'static str) -> Self {
        Self {
            kind,
            location: std::panic::Location::caller(),
            source: None,
        }
    }
}

pub(crate) fn remaining(deadline: Instant) -> Result<Duration, Error> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or_else(|| Error::unavailable("request deadline"))
}

pub(crate) async fn blocking<T: Send + 'static>(
    deadline: Instant,
    work: impl FnOnce() -> Result<T, Error> + Send + 'static,
) -> Result<T, Error> {
    let task = tokio::task::spawn_blocking(work);
    tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), task)
        .await
        .with_contexts((), "request deadline")?
        .with_contexts((), "service worker")?
}

/// All Keyfork operations in certificate generation share the HTTP operation's deadline.
pub(crate) fn derive_key(
    path: &DerivationPath,
    deadline: Instant,
) -> Result<keyfork_derive_openpgp::XPrv, Error> {
    remaining(deadline)?;
    let socket = keyforkd_client::get_socket().with_contexts((), "connect Keyfork")?;
    let left = remaining(deadline)?;
    socket
        .set_read_timeout(Some(left))
        .with_contexts((), "Keyfork read deadline")?;
    socket
        .set_write_timeout(Some(left))
        .with_contexts((), "Keyfork write deadline")?;
    let key = keyforkd_client::Client::new(socket)
        .request_xprv::<XPrvKey>(path)
        .with_contexts((), "derive Keyfork key")?;
    remaining(deadline)?;
    Ok(key)
}

pub(crate) fn root_ca(deadline: Instant) -> Result<Cert, Error> {
    let key = derive_key(&crate::derivation::default_openpgp_ca_path(), deadline)?;
    keyfork_derive_openpgp::derive(
        &key,
        &crate::derivation::public_certificate_key_flags(),
        &sequoia_openpgp::packet::UserID::from("Caution default OpenPGP CA"),
    )
    .with_contexts((), "derive custody CA")
}

pub(crate) fn check_root(expected: Option<&Cert>, deadline: Instant) -> Result<(), Error> {
    let actual = root_ca(deadline)?;
    if expected.is_some_and(|ca| ca.fingerprint() != actual.fingerprint()) {
        return Err(Error::unavailable(
            "configured CA does not match custody root",
        ));
    }
    remaining(deadline)?;
    Ok(())
}
