// Oneshot: Decrypt all files in /etc/caution and print out the KEY=value pairs

use ed25519_dalek::SigningKey;
use keyfork_derive_openpgp::derive_util::DerivationIndex;
use keyfork_derive_openpgp::openpgp::{
    Cert,
    packet::UserID,
    parse::{
        Parse,
        stream::{DecryptionHelper, DecryptorBuilder, VerificationHelper},
    },
    policy::NullPolicy,
    types::KeyFlags,
};
use keyfork_derive_path_data::paths;
use keyforkd_client::Client;
use std::collections::HashMap;
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};

pub struct SingleCertKeyring {
    tsk: Cert,
}

impl VerificationHelper for &SingleCertKeyring {
    fn get_certs(
        &mut self,
        _ids: &[sequoia_openpgp::KeyHandle],
    ) -> sequoia_openpgp::Result<Vec<Cert>> {
        Ok(vec![])
    }

    fn check(
        &mut self,
        _structure: sequoia_openpgp::parse::stream::MessageStructure,
    ) -> sequoia_openpgp::Result<()> {
        // NOTE: We assume that secrets are always valid.
        Ok(())
    }
}

impl DecryptionHelper for &SingleCertKeyring {
    fn decrypt<D>(
        &mut self,
        pkesks: &[sequoia_openpgp::packet::PKESK],
        _skesks: &[sequoia_openpgp::packet::SKESK],
        sym_algo: Option<sequoia_openpgp::types::SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> sequoia_openpgp::Result<Option<sequoia_openpgp::Fingerprint>>
    where
        D: FnMut(
            sequoia_openpgp::types::SymmetricAlgorithm,
            &sequoia_openpgp::crypto::SessionKey,
        ) -> bool,
    {
        let null = NullPolicy::new();
        for pkesk in pkesks {
            let recipient = pkesk.recipient();
            eprintln!("checking valid keys matching: {recipient}");
            if recipient.is_wildcard() || self.tsk.keys().any(|key| &key.keyid() == recipient) {
                eprintln!("any key in TSK matches");
                for key in self
                    .tsk
                    .keys()
                    .with_policy(&null, None)
                    .for_storage_encryption()
                    .secret()
                {
                    eprintln!("valid key is: {key_fp}", key_fp = key.fingerprint());
                    let secret_key = key.key().clone();
                    let mut keypair = if secret_key.has_unencrypted_secret() {
                        secret_key
                            .into_keypair()
                            .expect("ensured has_unencrypted_secret()")
                    } else {
                        eprintln!("could not decrypt with {recipient}; secret key encrypted");
                        continue;
                    };
                    if pkesk
                        .decrypt(&mut keypair, sym_algo)
                        .is_some_and(|(algo, sk)| decrypt(algo, &sk))
                    {
                        return Ok(Some(key.fingerprint()));
                    }
                }
            }
        }

        Err(anyhow::anyhow!("secret key not found for PKESKs"))
    }
}

fn decrypt_secret(
    keyring: &SingleCertKeyring,
    path: &Path,
) -> Result<String, Box<dyn std::error::Error>> {
    let policy = NullPolicy::new();
    let mut decryptor = DecryptorBuilder::from_file(path)?.with_policy(&policy, None, keyring)?;
    let mut secret = vec![];
    decryptor.read_to_end(&mut secret)?;
    let secret_str = String::from_utf8(secret)?;

    Ok(secret_str)
}

fn decrypt_secrets(
    keyring: SingleCertKeyring,
    paths: &[PathBuf],
) -> Result<HashMap<OsString, String>, Vec<Box<dyn std::error::Error>>> {
    let mut errors = vec![];
    let mut secrets = HashMap::new();
    for path in paths {
        let secret_name = path
            .with_extension("")
            .file_name()
            .expect("should have valid path; entry.file_name() existed")
            .to_owned();

        let secret = match decrypt_secret(&keyring, path) {
            Ok(o) => o,
            Err(e) => {
                errors.push(e);
                continue;
            }
        };

        secrets.insert(secret_name, secret);
    }

    if errors.is_empty() {
        Ok(secrets)
    } else {
        Err(errors)
    }
}

fn main() {
    let derivation_path = paths::OPENPGP
        .clone()
        .chain_push(DerivationIndex::new(0, true).expect("static index is always valid"));
    let derived_xprv = loop {
        let Ok(mut client) = Client::discover_socket() else {
            eprintln!("Unable to connect to keyforkd, sleebping");
            std::thread::sleep(std::time::Duration::from_secs(1));
            continue;
        };
        break client
            .request_xprv::<SigningKey>(&derivation_path)
            .expect("should be able to access keyforkd");
    };

    let subkeys = vec![
        KeyFlags::empty().set_certification(),
        KeyFlags::empty().set_signing(),
        KeyFlags::empty()
            .set_transport_encryption()
            .set_storage_encryption(),
        KeyFlags::empty().set_authentication(),
    ];
    let userid = UserID::from("Ephemeral Locksmith TSK");
    let tsk = keyfork_derive_openpgp::derive(&derived_xprv, &subkeys, &userid)
        .expect("should be able to derive key");
    eprintln!("derived tsk with fingerprint: {}", tsk.fingerprint());

    let entries = std::fs::read_dir("/etc/caution/secrets")
        .expect("should be able to read /etc/caution/secrets");
    let mut paths = vec![];
    for entry in entries {
        let path = entry
            .expect("should be able to read /etc/caution/secrets")
            .path();
        // NOTE: This will not support environment variables with `.` in their name.
        // Has anyone actually used these before? It's allowed by the C standard, but
        // it's also narsty.
        if path.is_file() && path.extension().is_some_and(|ext| ext == "asc") {
            paths.push(path);
        }
    }

    let secrets = match decrypt_secrets(SingleCertKeyring { tsk }, &paths) {
        Ok(o) => o,
        Err(errors) => {
            for error in errors {
                eprintln!("{error:?}");
            }
            return;
        }
    };

    for (name, value) in secrets {
        println!(
            "export {name}={value_quoted}",
            name = name.to_str().expect("name is UTF-8"),
            value_quoted = shlex::try_quote(value.trim()).expect("no nul bytes in UTF-8 str")
        );
    }
}
