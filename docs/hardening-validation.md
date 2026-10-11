# Public-service hardening validation

Validation date: 2026-09-18. Local uncommitted changes; no deployment or live Nitro acceptance performed.

## Source identification

- Locksmith base: `cd0f5fd44e252114c3bd160edd84c119b99263d0`.
- Locksmith changed implementation/test/configuration snapshot SHA-256: `deb9fde4dbd59a92f89f5985331cb415c4f5f9dff69db5e4b47fbb92091a0331`.
- Platform base: `b9a3188751f839d0b00195dd4983f290b0087fab`.
- Platform changed implementation/test/configuration snapshot SHA-256: `67ed74076dbe77646ab9ea6eb36d2261842a1ccb7b4026c2d015867e66b09a94`.

Snapshot digests concatenate sorted repository-relative paths, NUL, file bytes, NUL; documentation is excluded. The files are:

Locksmith:

```text
Cargo.lock
crates/locksmith/src/release/mod.rs
crates/locksmith/src/release/tests.rs
crates/public-cert-service/Cargo.toml
crates/public-cert-service/src/admission.rs
crates/public-cert-service/src/lib.rs
crates/public-cert-service/src/main.rs
crates/public-cert-service/src/release.rs
crates/public-cert-service/src/release_admission_tests.rs
crates/public-cert-service/src/release_tests.rs
crates/public-cert-service/src/routes.rs
crates/public-cert-service/src/service_tests.rs
examples/certificate-service/Containerfile
examples/certificate-service/caution.hcl
examples/certificate-service/check-inputs.py
examples/certificate-service/start.sh
examples/certificate-service/test_inputs.py
```

Platform:

```text
env.example
src/api/src/org_quorum.rs
src/api/src/org_quorum/certificates.rs
tests/e2e/soft-authenticator/src/bin/certificate-mock.rs
tests/e2e/test_quorum_mock.sh
```

## Results

| Check | Result |
| --- | --- |
| Locksmith default library suite | 38 passed |
| Certificate-service default library suite | 18 passed |
| Locksmith unsafe-E2E library suite | 39 passed |
| Certificate-service unsafe-E2E library suite | 19 passed |
| Platform API quorum tests | 18 passed, 1 database test intentionally ignored |
| Authenticated issuance plus mixed/all-WebAuthn HTTP recovery | Passed after adding issuance coverage |
| Final release admission timeout/disconnect regression | Passed |
| Deployment-input regression | Passed: old marker alone rejected, encrypted token accepted, plaintext rejected |
| Production certificate-service binary cargo check | Passed |
| Existing `make test-quorum-mock` | Passed, including disposable PostgreSQL orchestration and source-patched key-service share release |
| Changed-file whitespace and mock shell syntax | Passed |

The full mock suite ran from an isolated Platform copy with Cargo path patches for
Locksmith, keymaker-models and public-certificate-models pointing at the edited
Locksmith checkout. The standalone authenticator used the local public-certificate
models too. Actual Platform dependency pins and lockfiles were not changed.
Only those patched packages changed in the isolated lockfiles.

The mock checks actual Platform issuance authentication and asserts that Keymaker
receives no Authorization header. Separate service tests verify early rejection,
readiness coalescing/cache expiry, worker ownership through caller timeout/cancel,
and global/per-bundle quota cleanup, including an in-flight session.

Native tests used Homebrew nettle@3, OpenSSL and GMP. Platform loopback tests
were rerun outside the restricted sandbox after socket/macOS networking failures;
the rerun passed. The full mock used a disposable PostgreSQL container and cleaned
up its local services. Existing compiler warnings were not changed.

## Remaining operator acceptance

Follow [migration and manual acceptance](service-hardening.md). Preserve the
existing key service root key, CA and quorum bundle; provision the token, deploy Platform
and the combined certificate/recryptor service, recover the root and update trusted
PCR policies. Verify issuance/recovery, then repeat recovery after enclave restart.
No new PCR measurements, hardware passkey run, enclave build or Nitro deployment
are claimed by these local results. This increment does not close all issues under #7.
