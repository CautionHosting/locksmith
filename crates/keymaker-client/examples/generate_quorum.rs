use keymaker_client::{
    KeymakerClient,
    models::generate_quorum::{GenerateQuorumRequest, v1},
};

#[tokio::main]
async fn main() {
    let keyring =
        std::fs::read_to_string("keyring.asc").expect("should be able to find static keyring");
    let keys = parse_keyring(&keyring).expect("valid keyring with 2 to 254 certificates");
    let max = u8::try_from(keys.len()).expect("keyring length fits in u8");
    let client = KeymakerClient::new(Default::default(), "http://localhost:8080".parse().unwrap());
    let request = GenerateQuorumRequest::V1(v1::GenerateQuorumRequest {
        bundle_id: [0; 16],
        label: Default::default(),
        threshold: 2,
        max,
        keyring: keys
            .into_iter()
            .map(|cert| v1::Key::OpenPGP { cert })
            .collect(),
    });

    let response = client.generate_quorum(request).await.unwrap();
    let encoded = serde_json::to_string(&response).expect("could serialize json");
    std::fs::write("new-bundle.json", encoded).expect("could write bundle");
}

fn parse_keyring(keyring: &str) -> std::io::Result<Vec<String>> {
    use sequoia_openpgp::{cert::CertParser, parse::Parse, serialize::SerializeInto};
    use std::io::{Error, ErrorKind};

    let mut keys = Vec::new();
    for cert in CertParser::from_bytes(keyring.as_bytes()).map_err(Error::other)? {
        let cert = cert.map_err(Error::other)?;
        let armored = cert.armored().to_vec().map_err(Error::other)?;
        keys.push(String::from_utf8(armored).map_err(Error::other)?);
        if keys.len() > 254 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "at most 254 holders are supported",
            ));
        }
    }
    if keys.len() < 2 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "threshold 2 requires at least two holders",
        ));
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sequoia_openpgp::{Cert, cert::CertParser, parse::Parse};

    fn fixture_keyring() -> String {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/v0/bundle.json")).unwrap();
        fixture["keyring"].as_str().unwrap().to_owned()
    }

    #[test]
    fn splits_certificates_within_one_armor_block_in_order() {
        let keyring = fixture_keyring();
        assert_eq!(
            keyring
                .matches("-----BEGIN PGP PUBLIC KEY BLOCK-----")
                .count(),
            1
        );
        let expected: Vec<_> = CertParser::from_bytes(keyring.as_bytes())
            .unwrap()
            .map(|cert| cert.unwrap().fingerprint())
            .collect();
        let keys = parse_keyring(&keyring).unwrap();
        assert_eq!(keys.len(), 2);
        let actual: Vec<_> = keys
            .iter()
            .map(|key| {
                assert_eq!(CertParser::from_bytes(key.as_bytes()).unwrap().count(), 1);
                Cert::from_bytes(key.as_bytes()).unwrap().fingerprint()
            })
            .collect();
        assert_eq!(actual, expected);
        assert_eq!(parse_keyring(&keys.concat()).unwrap(), keys);
    }

    #[test]
    fn rejects_malformed_and_out_of_range_keyrings() {
        let keys = parse_keyring(&fixture_keyring()).unwrap();
        for input in [
            String::new(),
            "not a certificate".into(),
            keys[0].clone(),
            keys[0].repeat(255),
        ] {
            assert!(parse_keyring(&input).is_err());
        }
        assert_eq!(parse_keyring(&keys[0].repeat(254)).unwrap().len(), 254);
        let mut damaged = keys.concat();
        damaged.push_str(
            "\n-----BEGIN PGP PUBLIC KEY BLOCK-----\ninvalid\n-----END PGP PUBLIC KEY BLOCK-----\n",
        );
        assert!(parse_keyring(&damaged).is_err());
    }
}
