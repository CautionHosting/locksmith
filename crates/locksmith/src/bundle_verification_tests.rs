use super::*;

const PROOF: &[u8] = include_bytes!("../tests/data/aws-test.cbor");

fn fixture() -> (KeymakerPcrSet, Vec<u8>, Vec<u8>, SystemTime) {
    let pcrs = HashMap::from([
        (0, smex::decode_to_vec("ef093e4c1fd13878956589833c0e396b935cdf5ae45c1cc595e1a19a6da5812850f0ef3e77df918cb2a86d88ddf9cc03").unwrap()),
        (1, smex::decode_to_vec("ef093e4c1fd13878956589833c0e396b935cdf5ae45c1cc595e1a19a6da5812850f0ef3e77df918cb2a86d88ddf9cc03").unwrap()),
        (2, smex::decode_to_vec("21b9efbc184807662e966d34f390821309eeac6802309798826296bf3e8bec7c10edb30948c90ba67310f7b964fc500a").unwrap()),
    ]);
    let nonce =
        smex::decode_to_vec("d041b23bce8678bbc7c174bd8494c4f9759386eec963ec69bfd45c1452b10636")
            .unwrap();
    let document = Nitro::new(PROOF, pcrs.clone())
        .unwrap()
        .verify_at_attestation_time(Some(&nonce))
        .unwrap();
    let at = get_timestamp(&document).unwrap();
    let user_data = get_user_data(document).unwrap();
    (
        KeymakerPcrSet {
            pcrs,
            expires_at_unix_seconds: None,
        },
        nonce,
        user_data,
        at,
    )
}

#[test]
fn later_valid_policy_succeeds_after_a_failed_set() {
    let (set, nonce, data, _) = fixture();
    let mut wrong = set.clone();
    wrong.pcrs.get_mut(&0).unwrap()[0] ^= 1;
    KeymakerPcrPolicy {
        sets: vec![wrong, set],
    }
    .verify_necroproof(PROOF, &nonce, &data)
    .unwrap();
}

#[test]
fn diagnostics_include_each_set_and_underlying_reason() {
    let (set, _, data, _) = fixture();
    let error = KeymakerPcrPolicy {
        sets: vec![set.clone(), set],
    }
    .verify_necroproof(PROOF, &[1; 32], &data)
    .unwrap_err();
    let message = error.to_string();
    assert!(message.contains("set 0:"));
    assert!(message.contains("set 1:"));
    assert!(message.contains("nonce did not match"), "{message}");
    let VerifyNecroproofError::NoMatchingPcrSet { attempts, errors } = error else {
        panic!("wrong error")
    };
    assert_eq!(attempts, 2);
    assert_eq!(errors.len(), 2);
}

#[test]
fn expired_policy_is_reported_and_later_valid_policy_still_works() {
    let (set, nonce, data, at) = fixture();
    let mut expired = set.clone();
    expired.expires_at_unix_seconds =
        Some(at.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs());
    let error = KeymakerPcrPolicy {
        sets: vec![expired.clone()],
    }
    .verify_necroproof(PROOF, &nonce, &data)
    .unwrap_err();
    assert!(error.to_string().contains("PCR policy expired"), "{error}");
    KeymakerPcrPolicy {
        sets: vec![expired, set],
    }
    .verify_necroproof(PROOF, &nonce, &data)
    .unwrap();
}

#[test]
fn user_data_and_signature_failures_remain_rejected() {
    let (set, nonce, _, _) = fixture();
    let policy = KeymakerPcrPolicy { sets: vec![set] };
    let error = policy
        .verify_necroproof(PROOF, &nonce, b"wrong bundle hash")
        .unwrap_err();
    assert!(
        error.to_string().contains("user data did not match"),
        "{error}"
    );
    let mut tampered = PROOF.to_vec();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(
        policy
            .verify_necroproof(&tampered, &nonce, b"wrong bundle hash")
            .is_err()
    );
    assert!(matches!(
        KeymakerPcrPolicy { sets: vec![] }.verify_necroproof(PROOF, &nonce, b""),
        Err(VerifyNecroproofError::NoPcrSets)
    ));
}

#[test]
fn policy_cutoff_uses_generation_time_not_certificate_expiry_or_today() {
    let (set, nonce, data, generated_at) = fixture();
    let generated_seconds = generated_at
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // The fixture predates today and its certificate has expired. Acceptance
    // depends only on the authenticated generation time and the selected policy.
    for cutoff in [
        None,
        Some(generated_seconds + 1),
        Some(generated_seconds + 86400),
    ] {
        let mut allowed = set.clone();
        allowed.expires_at_unix_seconds = cutoff;
        KeymakerPcrPolicy {
            sets: vec![allowed],
        }
        .verify_necroproof(PROOF, &nonce, &data)
        .unwrap();
    }
    for cutoff in [generated_seconds - 1, generated_seconds] {
        let mut expired = set.clone();
        expired.expires_at_unix_seconds = Some(cutoff);
        assert!(
            KeymakerPcrPolicy {
                sets: vec![expired]
            }
            .verify_necroproof(PROOF, &nonce, &data)
            .unwrap_err()
            .to_string()
            .contains("PCR policy expired")
        );
    }
    let cutoff = SystemTime::UNIX_EPOCH + Duration::from_secs(generated_seconds);
    let mut set = set;
    set.expires_at_unix_seconds = Some(generated_seconds);
    assert!(set.is_valid_at(cutoff - Duration::from_nanos(1)));
    assert!(!set.is_valid_at(cutoff));
    assert!(!set.is_valid_at(cutoff + Duration::from_nanos(1)));
}
