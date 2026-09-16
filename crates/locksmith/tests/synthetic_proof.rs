use keymaker_models::{
    Proofed,
    generate_quorum::{
        GenerateQuorumResponse, deterministic_bundle_hash, deterministic_necroproof_nonce,
    },
};
use locksmith::bundle::{KeymakerPcrPolicy, load_response};
use serde_json::json;

#[test]
fn synthetic_proof_gate() {
    // Separate processes avoid mutating environment while Rust tests run threads.
    if std::env::var_os("LOCKSMITH_SYNTHETIC_TEST_CHILD").is_none() {
        for flag in [None, Some("0"), Some("1")] {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child
                .args(["--exact", "synthetic_proof_gate", "--nocapture"])
                .env("LOCKSMITH_SYNTHETIC_TEST_CHILD", "1")
                .env_remove("CAUTION_UNSAFE_KEY_SERVICE_E2E");
            if let Some(flag) = flag {
                child.env("CAUTION_UNSAFE_KEY_SERVICE_E2E", flag);
            }
            let output = child.output().unwrap();
            assert!(output.status.success(), "flag {flag:?}: {output:?}");
            assert!(
                String::from_utf8_lossy(&output.stdout)
                    .contains("test result: ok. 1 passed; 0 failed;"),
                "{output:?}"
            );
        }
        return;
    }
    let mut response: GenerateQuorumResponse = serde_json::from_value(json!({
        "data": {"version":"V1", "threshold":1, "max":1, "bundle_id":vec![1;16], "label":{}, "keyring":[], "public_key":"test", "shardfile":"test"},
        "necroproof":[]
    })).unwrap();
    let hash = deterministic_bundle_hash(&response.data).unwrap();
    response.necroproof = deterministic_necroproof_nonce(&hash).unwrap().to_vec();
    let policy = KeymakerPcrPolicy::from_json(
        &json!({"sets":[{"pcrs":{
            "0":"ab".repeat(48), "1":"ab".repeat(48), "2":"ab".repeat(48)
        }}]})
        .to_string(),
    )
    .unwrap();
    let accepted = cfg!(feature = "unsafe-e2e")
        && std::env::var("CAUTION_UNSAFE_KEY_SERVICE_E2E").as_deref() == Ok("1");
    assert_eq!(load_response(response.clone(), &policy).is_ok(), accepted);
    let mut wrong = response.clone();
    wrong.necroproof[0] ^= 1;
    assert!(load_response(wrong, &policy).is_err());
    for (field, value) in [
        ("public_key", json!("altered")),
        ("threshold", json!(2)),
        ("max", json!(2)),
    ] {
        let mut data = serde_json::to_value(&response.data).unwrap();
        data[field] = value;
        assert!(
            load_response(
                Proofed {
                    data: serde_json::from_value(data).unwrap(),
                    necroproof: response.necroproof.clone(),
                },
                &policy
            )
            .is_err(),
            "tampered {field}"
        );
    }
    for case in 0..5 {
        let mut wrong = policy.clone();
        match case {
            0 => {
                wrong.sets[0].pcrs.get_mut(&0).unwrap()[0] ^= 1;
            }
            1 => {
                wrong.sets[0].pcrs.remove(&2);
            }
            2 => {
                wrong.sets[0].pcrs.insert(3, vec![0xab; 48]);
            }
            3 => {
                wrong.sets[0].expires_at_unix_seconds = Some(2000000000);
            }
            _ => {
                wrong.sets.push(wrong.sets[0].clone());
            }
        }
        assert!(load_response(response.clone(), &wrong).is_err());
    }
}
