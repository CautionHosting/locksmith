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

#[derive(Debug, thiserror::Error)]
#[error("no hash algorithms were valid on certificate {fpr}")]
pub struct NoHashAlgo {
    fpr: Fingerprint,
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
            let cert_algos = match checked.preferred_hash_algo(pgp::types::Timestamp::now()) {
                Some(o) => o,
                None => {
                    errors.push(Box::new(NoHashAlgo {
                        fpr: checked.fingerprint().clone(),
                    }));
                    continue;
                }
            };
            let preferred_hash_algo = match rpgpie::policy::PREFERRED_HASH_ALGORITHMS
                .iter()
                .find(|algo| cert_algos.contains(algo))
            {
                Some(algo) => algo,
                None => {
                    errors.push(Box::new(NoHashAlgo {
                        fpr: checked.fingerprint().clone(),
                    }));
                    continue;
                }
            };

            return Ok(Some((card, *preferred_hash_algo)));
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
) -> Result<String, SignError> {
    use SignErrorKind as ErrorKind;

    let certificates = Certificate::load(&mut std::io::Cursor::new(certs))
        .with_contexts((), ErrorKind::LoadCertificates)?
        .into_iter()
        .map(Checked::from)
        .collect::<Vec<_>>();

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

        let pin = keyfork_prompt::prompt_validated_passphrase(
            prompt,
            &format!("{message_template}\nRemaining PIN entry attempts: {attempts}\n\nPIN: "),
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

    let cs = CardSlot::init_from_card(&mut tx, KeyType::Signing, &|| {})
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

    Ok(String::from_utf8(signature_armored_bytes).expect("ASCII armored values are always utf8"))
}

// Use the current system time, minus 60 seconds to account for drift, before ensuring a signature
// is valid.
pub fn verify_detached(certs: &str, data: &str, signature: &str) -> Result<(), VerifyError> {
    use VerifyErrorKind as ErrorKind;
    // TODO: make use of this in combination with creation timestamp
    let now = std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(60))
        .ok_or(VerifyError {
            kind: ErrorKind::IncompatibleDrift,
            source: None,
            location: Location::caller(),
        })?;

    let certificates = Certificate::load(&mut std::io::Cursor::new(certs))
        .with_contexts((), ErrorKind::LoadCertificates)?
        .into_iter()
        .map(Checked::from)
        .collect::<Vec<_>>();

    // NOTE: .try_into() returns the Vec as the Err variant, which isn't std::error::Error.
    // This isn't my prettiest code, for sure.
    let [signature] = &rpgpie::signature::load(&mut std::io::Cursor::new(signature))
        .with_contexts((), ErrorKind::LoadSignatures)?[..]
    else {
        return Err(VerifyError {
            kind: ErrorKind::InvalidSignatureCount,
            source: None,
            location: Location::caller(),
        });
    };

    let mut has_valid_signature = false;
    let mut validation_errors = vec![];

    for cert in certificates {
        if let Some(creation_timestamp) = signature.created() {
            // verify that the certificate is valid when the signature was created
            // NOTE: we don't check that certificates are valid _at this point in time_.
            // should we? having to update a bundle would lead to misreproduction in enclaves.

            // NOTE: rpgpie does not verify that certificates are valid at time of signature
            for verification in cert
                .valid_signing_capable_component_keys_at(creation_timestamp)
                .into_iter()
                .map(|verifier| verifier.verify(signature, data.as_bytes()))
            {
                if let Err(e) = verification {
                    validation_errors.push(e.to_string());
                } else {
                    has_valid_signature = true;
                }
            }
        }
    }

    if !has_valid_signature {
        return Err(VerifyError {
            kind: VerifyErrorKind::AllSignaturesInvalid { validation_errors },
            source: None,
            location: Location::caller(),
        })
    }

    return Ok(())
}
