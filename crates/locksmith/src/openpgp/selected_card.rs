//! Select the requested holder before any PIN prompt or decryption operation.
use crate::{custody::pgp_error, release::Error};
use card_backend_pcsc::PcscBackend;
use dterror::ResultExt;
use keyfork_prompt::{PromptHandler, prompt_validated_passphrase};
use keyfork_shard::openpgp::EncryptedMessage;
use keymaker_models::generate_quorum::v1;
use openpgp_card_sequoia::{Card, state::Open};
use sequoia_openpgp::{
    self as pgp, Cert, Fingerprint, Packet, PacketPile,
    parse::{Parse, stream::*},
    policy::NullPolicy,
};
use std::{collections::HashSet, rc::Rc, sync::Mutex};

fn with_selected_card<C, R>(
    cards: impl IntoIterator<Item = Result<C, Error>>,
    allowed: &HashSet<Fingerprint>,
    mut inspect: impl FnMut(&mut C) -> Result<Option<Fingerprint>, Error>,
    operate: impl FnOnce(C) -> Result<R, Error>,
) -> Result<R, Error> {
    for card in cards {
        let mut card = card?;
        if inspect(&mut card)?.is_some_and(|fp| allowed.contains(&fp)) {
            return operate(card);
        }
    }
    Err(Error::invalid(
        "selected holder's smartcard is not connected",
    ))
}

struct Decryptor {
    card: Card<Open>,
    allowed: HashSet<Fingerprint>,
    signer: Option<Cert>,
    prompt: Rc<Mutex<Box<dyn PromptHandler>>>,
}
impl VerificationHelper for &mut Decryptor {
    fn get_certs(&mut self, _: &[pgp::KeyHandle]) -> pgp::Result<Vec<Cert>> {
        Ok(self.signer.iter().cloned().collect())
    }
    fn check(&mut self, structure: MessageStructure) -> pgp::Result<()> {
        let mut count = 0;
        for layer in structure {
            if let MessageLayer::SignatureGroup { results } = layer {
                for result in results {
                    result.map_err(|e| anyhow::anyhow!(e.to_string()))?;
                    count += 1;
                }
            }
        }
        if count != usize::from(self.signer.is_some()) {
            anyhow::bail!("unexpected share signature count");
        }
        Ok(())
    }
}
impl DecryptionHelper for &mut Decryptor {
    fn decrypt<D>(
        &mut self,
        packets: &[pgp::packet::PKESK],
        _: &[pgp::packet::SKESK],
        algorithm: Option<pgp::types::SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> pgp::Result<Option<Fingerprint>>
    where
        D: FnMut(pgp::types::SymmetricAlgorithm, &pgp::crypto::SessionKey) -> bool,
    {
        let mut transaction = self.card.transaction()?;
        let fingerprint = transaction
            .fingerprints()?
            .decryption()
            .map(|fp| Fingerprint::from_bytes(fp.as_bytes()))
            .ok_or_else(|| anyhow::anyhow!("card has no decryption key"))?;
        // Recheck on each transaction, before PIN entry, including metadata.
        if !self.allowed.contains(&fingerprint) {
            anyhow::bail!("selected smartcard changed");
        }
        let mut prompt = self
            .prompt
            .lock()
            .map_err(|_| anyhow::anyhow!("prompt unavailable"))?;
        let pin = prompt_validated_passphrase(
            &mut **prompt,
            &format!("Unlock selected holder card {}\nPIN: ", fingerprint),
            3,
            &|value: String| -> Result<String, Box<dyn std::error::Error>> {
                if value.trim().len() < 6 {
                    return Err("PIN must contain at least six characters".into());
                }
                Ok(value)
            },
        )?;
        drop(prompt);
        // One explicit card attempt; an invalid PIN is returned rather than retried silently.
        let mut user = transaction.to_user_card(pin.trim())?;
        let mut key = user.decryptor(&|| eprintln!("Touch the selected card to decrypt"))?;
        for packet in packets {
            if packet
                .decrypt(&mut key, algorithm)
                .is_some_and(|(a, s)| decrypt(a, &s))
            {
                return Ok(Some(fingerprint));
            }
        }
        anyhow::bail!("selected card cannot decrypt this message")
    }
}

pub(crate) fn decrypt(
    bundle: &v1::GenerateQuorumResponse,
    holder: &str,
    prompt: Rc<Mutex<Box<dyn PromptHandler>>>,
) -> Result<(Vec<u8>, u8, usize), Error> {
    let certificates = bundle
        .keyring
        .iter()
        .map(|entry| {
            let (v1::Key::OpenPGP { cert } | v1::Key::WebAuthn { cert, .. }) = entry;
            Cert::from_bytes(cert).map_err(pgp_error)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let indices: Vec<_> = certificates
        .iter()
        .enumerate()
        .filter(|(_, cert)| cert.fingerprint().to_string() == holder)
        .map(|(i, _)| i)
        .collect();
    let [index] = indices.as_slice() else {
        return Err(Error::invalid(
            "holder must identify exactly one certificate",
        ));
    };
    let index = *index;
    let allowed: HashSet<_> = certificates[index]
        .keys()
        .with_policy(&NullPolicy::new(), None)
        .for_storage_encryption()
        .map(|key| key.fingerprint())
        .collect();
    if allowed.is_empty() {
        return Err(Error::invalid("selected holder has no encryption key"));
    }
    let cards = PcscBackend::cards(None)
        .with_contexts((), "enumerate smartcards")?
        .map(|card| {
            card.with_contexts((), "open smartcard backend")
                .and_then(|card| Card::<Open>::new(card).with_contexts((), "open smartcard"))
        });
    with_selected_card(
        cards,
        &allowed,
        |card| {
            Ok(card
                .transaction()
                .with_contexts((), "inspect smartcard")?
                .fingerprints()
                .with_contexts((), "inspect smartcard fingerprints")?
                .decryption()
                .map(|fp| Fingerprint::from_bytes(fp.as_bytes())))
        },
        |card| {
            let mut helper = Decryptor {
                card,
                allowed: allowed.clone(),
                signer: None,
                prompt,
            };
            let mut recipients = Vec::new();
            let mut messages = Vec::new();
            for packet in PacketPile::from_bytes(bundle.shardfile.as_bytes())
                .map_err(pgp_error)?
                .into_children()
            {
                match packet {
                    Packet::PKESK(packet) => recipients.push(packet),
                    Packet::SEIP(packet) if !recipients.is_empty() => {
                        messages.push(EncryptedMessage::new(&mut recipients, packet))
                    }
                    _ => return Err(Error::invalid("invalid shardfile packet")),
                }
            }
            if !recipients.is_empty() || messages.len() != certificates.len() + 1 {
                return Err(Error::invalid("shardfile message count"));
            }
            let metadata = messages[0]
                .decrypt_with(&NullPolicy::new(), &mut helper)
                .with_contexts((), "decrypt selected holder metadata")?;
            if metadata.len() < 2 || metadata[0] != 1 || metadata[1] != bundle.threshold {
                return Err(Error::invalid("share metadata threshold/version"));
            }
            let metadata_certs = pgp::cert::CertParser::from_bytes(&metadata[2..])
                .map_err(pgp_error)?
                .collect::<pgp::Result<Vec<_>>>()
                .map_err(pgp_error)?;
            if metadata_certs.len() != certificates.len() + 1
                || metadata_certs[1..]
                    .iter()
                    .zip(&certificates)
                    .any(|(a, b)| a.fingerprint() != b.fingerprint())
            {
                return Err(Error::invalid("share metadata holder order"));
            }
            helper.signer = Some(metadata_certs[0].clone());
            let share = messages[index + 1]
                .decrypt_with(&NullPolicy::new(), &mut helper)
                .with_contexts((), "decrypt selected holder share")?;
            if share.len() != 33 || usize::from(share[0]) != index + 1 {
                return Err(Error::invalid("share coordinate"));
            }
            Ok((share, bundle.threshold, index))
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selection_precedes_pin_and_both_decryptions_in_either_order() {
        let a = Fingerprint::from_bytes(&[1; 20]);
        let b = Fingerprint::from_bytes(&[2; 20]);
        let allowed = HashSet::from([b.clone()]);
        for cards in [vec![a.clone(), b.clone()], vec![b.clone(), a.clone()]] {
            let mut operations = Vec::new();
            with_selected_card(
                cards.into_iter().map(Ok),
                &allowed,
                |fp| Ok(Some(fp.clone())),
                |card| {
                    operations.push((card.clone(), "PIN"));
                    operations.push((card.clone(), "metadata"));
                    operations.push((card, "share"));
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(
                operations,
                vec![
                    (b.clone(), "PIN"),
                    (b.clone(), "metadata"),
                    (b.clone(), "share")
                ]
            );
        }
        assert!(
            with_selected_card(
                [Ok(a)],
                &allowed,
                |fp| Ok(Some(fp.clone())),
                |_| -> Result<(), Error> { panic!("unselected card prompted/decrypted") }
            )
            .is_err()
        );
    }
}
