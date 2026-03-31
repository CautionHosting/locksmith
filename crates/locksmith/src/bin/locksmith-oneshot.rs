// Oneshot: Decrypt all files in /etc/caution and print out the KEY=value pairs

use ed25519_dalek::SigningKey;
use keyfork_derive_openpgp::derive_util::DerivationIndex;
use keyfork_derive_openpgp::openpgp::{packet::UserID, types::KeyFlags};
use keyfork_derive_path_data::paths;
use keyforkd_client::Client;

fn main() {
    let derivation_path = paths::OPENPGP
        .clone()
        .chain_push(DerivationIndex::new(0, true).expect("static index is always valid"));
    let derived_xprv = Client::discover_socket()
        .expect("should be able to discover Keyfork socket")
        .request_xprv::<SigningKey>(&derivation_path)
        .expect("should be able to access keyforkd");

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
    dbg!(tsk);

    let path = env!("LOCKSMITH_ONESHOT_CONFIG_DIRECTORY");
    let entries = std::fs::read_dir(path)
        .expect("should be able to read /etc/caution/secrets");
    let mut paths = vec![];
    for entry in entries {
        let path = entry
            .expect("should be able to read /etc/caution/secrets")
            .path();
        if path.is_file() {
            paths.push(path);
        }
    }

    let mut secrets = std::collections::HashMap::new();
    for path in paths {
        let filename = path
            .file_name()
            .expect("should have valid path; entry.file_name() existed");
        secrets.insert(filename.to_owned(), vec![0u8; 0]);
    }
}
