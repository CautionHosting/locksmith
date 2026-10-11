use keyfork_mnemonic::Mnemonic;

#[tokio::main]
async fn get_shards() -> Vec<u8> {
    let bundle_text = std::fs::read_to_string("/etc/caution/bundle.json").expect("has image-baked bundle");
    let legacy = locksmith::legacy::is_imported_json(&bundle_text).expect("valid bundle format");
    let policy = if legacy { None } else {
        let text = std::fs::read_to_string("/etc/caution/keymaker-pcr-policy.json").expect("has Keymaker PCR policy");
        Some(locksmith::bundle::KeymakerPcrPolicy::from_json(&text).expect("valid Keymaker PCR policy JSON"))
    };
    // Runtime approval comes from including this exact imported artifact in the measured image.
    let (bundle, generation_time) = locksmith::bundle::load_recovery_json(&bundle_text, policy.as_ref(), true)
        .expect("valid image-baked bundle");
    if legacy { tracing::warn!("Legacy V0 — no Keymaker generation proof; using image-baked recovery metadata"); }

    let address = "0.0.0.0:49504"
        .parse()
        .expect("known address can be parsed");
    loop {
        match locksmith::server::receive_shards_at(address, &bundle, generation_time).await {
            Ok(reconstituted_secret) => return reconstituted_secret,
            Err(error) if error.restarts_recovery() => {
                tracing::error!(%error, "recovered secret did not match the bundle; every holder must resubmit");
            }
            Err(error) => panic!("can get shards: {error:?}"),
        }
    }
}

#[tokio::main]
async fn get_shards_test_util() -> Vec<u8> {
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    vec![0u8; 32]
}

#[tokio::main]
async fn run_server(mnemonic: Mnemonic) {
    keyforkd::start_and_run_server(mnemonic)
        .await
        .expect("could start keyforkd");
}

fn main() {
    // NOTE: tracing_subscriber might not be thread safe
    tracing_subscriber::fmt::init();

    if let Some(mnemonic) = unsafe_test_mnemonic() {
        run_server(mnemonic);
        return;
    }

    // SAFETY: Before daemonizing, all threads should be joined. This will be done by the time
    // tokio::main returns.
    // testing value:
    // let secret = get_shards_test_util();
    let secret = get_shards();

    daemonize::Daemonize::new()
        .start()
        .expect("could not fork to background");

    let mnemonic =
        Mnemonic::try_from_slice(&secret).expect("reconstituted secret was of valid length");
    run_server(mnemonic);
}

fn unsafe_test_mnemonic() -> Option<Mnemonic> {
    #[cfg(feature = "unsafe-e2e")]
    if let Ok(secret_hex) = std::env::var("LOCKSMITHD_UNSAFE_TEST_SECRET_HEX") {
        tracing::warn!("UNSAFE E2E: bypassing quorum recovery");
        let secret = smex::decode_to_vec(&secret_hex)
            .expect("LOCKSMITHD_UNSAFE_TEST_SECRET_HEX must be hex-encoded");
        return Some(
            Mnemonic::try_from_slice(&secret)
                .expect("LOCKSMITHD_UNSAFE_TEST_SECRET_HEX must encode a valid mnemonic secret"),
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_mnemonic_requires_feature_and_environment() {
        const CHILD: &str = "LOCKSMITH_HOOK_TEST_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let enabled = cfg!(feature = "unsafe-e2e")
                && std::env::var_os("LOCKSMITHD_UNSAFE_TEST_SECRET_HEX").is_some();
            assert_eq!(unsafe_test_mnemonic().is_some(), enabled);
            return;
        }
        for enabled in [false, true] {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child
                .args([
                    "--exact",
                    "tests::unsafe_mnemonic_requires_feature_and_environment",
                ])
                .env(CHILD, "1")
                .env_remove("LOCKSMITHD_UNSAFE_TEST_SECRET_HEX");
            if enabled {
                child.env("LOCKSMITHD_UNSAFE_TEST_SECRET_HEX", "07".repeat(32));
            }
            let output = child.output().unwrap();
            assert!(
                String::from_utf8_lossy(&output.stdout)
                    .contains("test result: ok. 1 passed; 0 failed;"),
                "child must execute exactly one test: {:?}",
                output
            );
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
