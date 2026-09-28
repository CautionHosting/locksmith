use crate::openpgp::{SignError, SignErrorKind, VerifyError, VerifyErrorKind};
use card_backend::SmartcardError;
use card_backend_pcsc::PcscBackend;
use dterror::*;
use openpgp_card::{
    Card,
    ocard::{KeyType, StatusBytes},
    state::Open,
};
use openpgp_card_rpgp::CardSlot;
use pgp::{
    crypto::hash::HashAlgorithm,
    types::{Fingerprint, KeyDetails, Password},
};
use rpgpie::{
    certificate::{Certificate, Checked},
    lookup::CertificateIndex,
    message::SignatureMode,
};
use std::panic::Location;

fn try_open_card(
    backend: Result<PcscBackend, SmartcardError>,
) -> Result<(Card<Open>, Fingerprint), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let mut card = Card::<Open>::new(backend?)?;
    let mut tx = card.transaction()?;
    let cs = CardSlot::init_from_card(&mut tx, KeyType::Signing, &|| {})?;

    let fpr = cs.public_key().fingerprint();

    drop(cs);
    drop(tx);

    Ok((card, fpr))
}

/// Hash used for signing when a certificate declares no preferred-hash subpacket
/// (or none we accept). SHA-512 is rpgpie's top preference and is supported by
/// the smartcards and key types we use.
const DEFAULT_HASH_ALGORITHM: HashAlgorithm = HashAlgorithm::Sha512;

/// Choose the signing hash for a certificate: its most-preferred hash that we
/// also accept, falling back to [`DEFAULT_HASH_ALGORITHM`] when the cert declares
/// no preferred-hash subpacket (e.g. keyfork-generated certs) or none we accept.
fn select_signing_hash(cert_algos: Option<&[HashAlgorithm]>) -> HashAlgorithm {
    cert_algos
        .and_then(|cert_algos| {
            rpgpie::policy::PREFERRED_HASH_ALGORITHMS
                .iter()
                .find(|algo| cert_algos.contains(algo))
                .copied()
        })
        .unwrap_or(DEFAULT_HASH_ALGORITHM)
}

fn find_open_cards_by_certs(
    certs: &[Checked],
) -> Result<
    Option<(Card<Open>, HashAlgorithm)>,
    Vec<Box<dyn std::error::Error + Send + Sync + 'static>>,
> {
    let backends = match PcscBackend::cards(None) {
        Ok(o) => o,
        Err(e) => {
            return Err(vec![Box::new(e)]);
        }
    };
    let index = CertificateIndex::index_as_data_signer(certs);
    let mut errors = vec![];

    for backend_result in backends {
        let (card, fpr) = match try_open_card(backend_result) {
            Ok(o) => o,
            Err(e) => {
                errors.push(e);
                continue;
            }
        };

        if let Some(checked) = index.lookup_fingerprint(&fpr).into_iter().next() {
            let preferred_hash_algo =
                select_signing_hash(checked.preferred_hash_algo(pgp::types::Timestamp::now()));

            return Ok(Some((card, preferred_hash_algo)));
        }
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    return Ok(None);
}

pub fn sign(
    certs: &str,
    data: &str,
    prompt: &mut dyn keyfork_prompt::PromptHandler,
    opt_private_key_path: Option<&std::path::Path>,
) -> Result<String, SignError> {
    use SignErrorKind as ErrorKind;

    let certificates = Certificate::load(&mut std::io::Cursor::new(certs))
        .with_contexts((), ErrorKind::LoadCertificates)?
        .into_iter()
        .map(Checked::from)
        .collect::<Vec<_>>();

    let index = CertificateIndex::index_as_data_signer(&certificates);

    // Try TSK-based signing if a private key path was provided.
    if let Some(private_key_path) = opt_private_key_path {
        let mut file = std::fs::File::open(private_key_path).map_err(|e| SignError {
            kind: ErrorKind::LoadPrivateKeys,
            source: Some(Box::new(e)),
            location: Location::caller(),
        })?;
        let tsks = rpgpie::tsk::Tsk::load(&mut file).map_err(|e| SignError {
            kind: ErrorKind::LoadPrivateKeys,
            source: Some(Box::new(e)),
            location: Location::caller(),
        })?;

        for tsk in &tsks {
            let cert = rpgpie::certificate::Certificate::from(tsk.clone());
            let checked = Checked::from(cert);

            let hash_algo =
                select_signing_hash(checked.preferred_hash_algo(pgp::types::Timestamp::now()));

            for data_signer in tsk.signing_capable_component_keys() {
                let fp = data_signer.fingerprint();
                if index.lookup_fingerprint(&fp).is_empty() {
                    continue;
                }

                let ssk = tsk.as_signed_secret_key();
                let is_encrypted = ssk.primary_key.secret_params().is_encrypted()
                    || ssk
                        .secret_subkeys
                        .iter()
                        .any(|s| s.secret_params().is_encrypted());
                let key_pw = if is_encrypted {
                    let password = keyfork_prompt::prompt_validated_passphrase(
                        prompt,
                        &format!("Unlock private key ({fp})\n\nPassword: "),
                        3,
                        Ok::<String, Box<dyn std::error::Error>>,
                    )
                    .with_contexts((), ErrorKind::PromptPrivateKeyPassword)?;
                    pgp::types::Password::from(password)
                } else {
                    pgp::types::Password::empty()
                };

                let signature = data_signer
                    .sign_data(data.as_bytes(), SignatureMode::Text, &key_pw, hash_algo)
                    .map_err(|e| SignError {
                        kind: ErrorKind::SignData,
                        source: Some(Box::new(e)),
                        location: Location::caller(),
                    })?;
                let mut signature_armored_bytes = vec![];
                rpgpie::signature::save(&[signature], true, &mut signature_armored_bytes)
                    .with_contexts((), ErrorKind::EncodeSignedData)?;

                return Ok(String::from_utf8(signature_armored_bytes)
                    .expect("ASCII armored values are always utf8"));
            }
        }
    }

    // No matching TSK found; fall through to smartcard path.
    let (mut card, hash_algo) = match find_open_cards_by_certs(&certificates) {
        Ok(Some(o)) => o,
        Ok(None) => {
            return Err(SignError {
                kind: ErrorKind::NoMatchingCard,
                source: None,
                location: Location::caller(),
            });
        }
        Err(e) => {
            // TODO: Handle multiple errors. For now, we're gonna treat the first as the source, as
            // traditionally it either would have been, or just ignored outright.
            return Err(SignError {
                kind: ErrorKind::FindMatchingCard,
                // NOTE: Precondition !.is_empty() should ensure it is Some.
                source: e.into_iter().next(),
                location: Location::caller(),
            });
        }
    };

    let mut tx = card
        .transaction()
        .with_contexts((), ErrorKind::StartTransaction)?;
    let cardholder_name = tx.cardholder_name().ok().filter(|name| name.is_empty());
    let card_id = tx
        .application_identifier()
        .with_contexts((), ErrorKind::GetApplicationIdentifier)?;

    let message_template = match cardholder_name {
        Some(name) => format!("Unlock card {card_id} ({name})"),
        None => format!("Unlock card {card_id}"),
    };

    let validator = |input: String| -> Result<String, Box<dyn std::error::Error>> {
        // NOTE: Yubikeys return an error when prompting with a PIN less than 6 characters.
        // It does not decrement the amount of allowed attempts.
        let provided_length = input.len();
        if provided_length < 6 {
            return Err(Box::new(crate::openpgp::PinLengthError { provided_length }));
        }

        return Ok(input);
    };

    // Unlocking the PIN during this session will allow the unlocked state to be used when calling
    // CardSlot::init_from_card. We will not need to store the valid PIN.
    loop {
        tx.invalidate_cache()
            .with_contexts((), ErrorKind::InvalidCache)?;
        let attempts = tx
            .pw_status_bytes()
            .with_contexts((), ErrorKind::GetCardStatus)?
            .err_count_pw1();
        if attempts == 0 {
            return Err(SignError {
                kind: ErrorKind::InvalidPIN,
                source: None,
                location: Location::caller(),
            });
        }

        let pin = super::card_prompt::validated_pin(
            prompt,
            &format!("{}\n{message_template}\nRemaining PIN entry attempts: {attempts}\n\nPIN: ", super::card_prompt::SIGN),
            3,
            validator,
        )
        .with_contexts((), ErrorKind::PromptPIN)?;

        match tx.verify_user_signing_pin(pin.clone().into()) {
            Ok(()) => {
                // We have a successful PIN and the card is unlocked.
                break;
            }
            Err(openpgp_card::Error::CardStatus(StatusBytes::SecurityStatusNotSatisfied)) => {
                // Invalid PIN has been entered, repeat.
                continue;
            }
            Err(e) => {
                // Unknown, but NOT an invalid PIN.
                // PINs that do not match the correct format SHOULD be captured by the validator.
                return Err(SignError {
                    kind: ErrorKind::VerifyPIN,
                    source: Some(Box::new(e)),
                    location: Location::caller(),
                });
            }
        }
    }

    let cs = CardSlot::init_from_card(&mut tx, KeyType::Signing, &|| {
        eprintln!("{} — touch the selected card to sign", super::card_prompt::SIGN);
    })
        .with_contexts((), ErrorKind::InitCardSlot)?;
    let signature = cs
        .sign_data(
            data.as_bytes(),
            /* if it's text */ true,
            &Password::empty(),
            hash_algo,
        )
        .with_contexts((), ErrorKind::SignData)?;
    let mut signature_armored_bytes = vec![];
    rpgpie::signature::save(&[signature], true, &mut signature_armored_bytes)
        .with_contexts((), ErrorKind::EncodeSignedData)?;

    eprintln!("✓ Encrypted submission signed");
    Ok(String::from_utf8(signature_armored_bytes).expect("ASCII armored values are always utf8"))
}

/// Allow the same future clock skew as the WebAuthn holder verifier.
const MAX_SIGNATURE_FUTURE_SKEW_SECS: u32 = 60;

pub fn verify_detached(certs: &str, data: &str, signature: &str) -> Result<(), VerifyError> {
    verify_detached_at(certs, data, signature, pgp::types::Timestamp::now())
}

fn verify_detached_at(
    certs: &str,
    data: &str,
    signature: &str,
    now: pgp::types::Timestamp,
) -> Result<(), VerifyError> {
    use VerifyErrorKind as ErrorKind;
    let certificates = Certificate::load(&mut std::io::Cursor::new(certs))
        .with_contexts((), ErrorKind::LoadCertificates)?
        .into_iter()
        .map(Checked::from)
        .collect::<Vec<_>>();

    let [signature] = &rpgpie::signature::load(&mut std::io::Cursor::new(signature))
        .with_contexts((), ErrorKind::LoadSignatures)?[..]
    else {
        return Err(VerifyError {
            kind: ErrorKind::InvalidSignatureCount,
            source: None,
            location: Location::caller(),
        });
    };

    let mut validation_errors = vec![];
    for cert in certificates {
        if let Some(created) = signature.created() {
            // Preserve eligibility at signing time, including certificate validity,
            // revocation, signing capability and the subkey's binding/back-signature.
            for verifier in cert.valid_signing_capable_component_keys_at(created) {
                let key = verifier.as_componentkey();
                if created < cert.primary_creation_time() || created < key.created_at() {
                    continue;
                }
                // Component verification retains algorithm policy and cryptography.
                // SignatureVerifier::verify adds a zero-skew clock check, so enforce
                // its temporal bounds here instead, without changing the signed data.
                match key.verify(signature, data.as_bytes()) {
                    Err(error) => validation_errors.push(error.into()),
                    Ok(()) => {
                        let ahead_seconds = created.as_secs().saturating_sub(now.as_secs());
                        if ahead_seconds > MAX_SIGNATURE_FUTURE_SKEW_SECS {
                            return Err(VerifyError {
                                kind: ErrorKind::SignatureFromFuture,
                                source: None,
                                location: Location::caller(),
                            });
                        }
                        return Ok(());
                    }
                }
            }
        }
    }

    Err(VerifyError {
        kind: ErrorKind::AllSignaturesInvalid { validation_errors },
        source: None,
        location: Location::caller(),
    })
}

#[cfg(test)]
#[path = "signature_time_tests.rs"]
mod signature_time_tests;

#[cfg(test)]
mod tests {
    use super::{DEFAULT_HASH_ALGORITHM, select_signing_hash};
    use pgp::crypto::hash::HashAlgorithm;

    #[test]
    fn falls_back_to_default_when_no_preferences() {
        // keyfork-generated certs declare no preferred-hash subpacket.
        assert_eq!(select_signing_hash(None), DEFAULT_HASH_ALGORITHM);
        // An empty preference list also falls back.
        assert_eq!(select_signing_hash(Some(&[])), DEFAULT_HASH_ALGORITHM);
    }

    #[test]
    fn falls_back_when_no_preference_is_accepted() {
        // Cert only declares a hash we don't accept (SHA-1) -> default.
        assert_eq!(
            select_signing_hash(Some(&[HashAlgorithm::Sha1])),
            DEFAULT_HASH_ALGORITHM
        );
    }

    #[test]
    fn uses_our_preference_order_among_accepted_hashes() {
        // Single accepted preference is honored.
        assert_eq!(
            select_signing_hash(Some(&[HashAlgorithm::Sha256])),
            HashAlgorithm::Sha256
        );
        // When the cert lists several, our order (SHA512 first) wins regardless
        // of the cert's ordering.
        assert_eq!(
            select_signing_hash(Some(&[HashAlgorithm::Sha384, HashAlgorithm::Sha512])),
            HashAlgorithm::Sha512
        );
    }
}
