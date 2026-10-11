//! Fallible OpenPGP message decryption for legacy metadata and signed shares.
use crate::legacy::{Error, Prompt};
use dterror::ResultExt;
use keyfork_shard::openpgp::EncryptedMessage;
use sequoia_openpgp::{self as pgp, Cert, parse::stream::*, policy::NullPolicy};

struct Decryptor<'a> {
    private: &'a Cert,
    signer: Option<&'a Cert>,
    prompt: Prompt,
}
impl VerificationHelper for Decryptor<'_> {
    fn get_certs(&mut self, _: &[pgp::KeyHandle]) -> pgp::Result<Vec<Cert>> {
        Ok(self.signer.into_iter().cloned().collect())
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
            return Err(Error::invalid("unexpected share signature count").into());
        }
        Ok(())
    }
}
impl DecryptionHelper for Decryptor<'_> {
    fn decrypt<D>(
        &mut self,
        packets: &[pgp::packet::PKESK],
        _: &[pgp::packet::SKESK],
        algorithm: Option<pgp::types::SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> pgp::Result<Option<pgp::Fingerprint>>
    where
        D: FnMut(pgp::types::SymmetricAlgorithm, &pgp::crypto::SessionKey) -> bool,
    {
        for key in self
            .private
            .keys()
            .with_policy(&NullPolicy::new(), None)
            .for_storage_encryption()
            .secret()
        {
            let mut secret = key.key().clone();
            if !secret.has_unencrypted_secret() {
                let password = self
                    .prompt
                    .lock()
                    .map_err(|_| Error::invalid("prompt unavailable"))?
                    .prompt_passphrase("Legacy holder decryption passphrase: ")?;
                secret = secret.decrypt_secret(&password.as_str().into())?;
            }
            let mut pair = secret.into_keypair()?;
            for packet in packets {
                if packet
                    .decrypt(&mut pair, algorithm)
                    .is_some_and(|(a, s)| decrypt(a, &s))
                {
                    return Ok(Some(self.private.fingerprint()));
                }
            }
        }
        Err(Error::invalid("selected key cannot decrypt this message").into())
    }
}
pub(crate) fn decrypt(
    message: &EncryptedMessage,
    private: &Cert,
    signer: Option<&Cert>,
    prompt: Prompt,
) -> Result<Vec<u8>, Error> {
    message
        .decrypt_with(
            &NullPolicy::new(),
            Decryptor {
                private,
                signer,
                prompt,
            },
        )
        .with_contexts((), "decrypt legacy message")
}
