# Minimal V1 completion validation

## Candidate

- Date: 2026-09-18.
- Locksmith base: `526bbb258c0cf1047bb78b99bb6e1cc16ee3fa27` plus this increment.
- Platform mock harness: `26d7b71166e9f041eaa904a87d0b891fd2803489`.
  An isolated archive uses local Cargo patches for Locksmith and its two model
  crates; the Platform checkout and its committed dependency pins are unchanged.
- SHA-256 of changed Rust/manifests: `4a52a9929a3dfa10b48c605c1f695bd15dec4bac456adef8f9b97a05a694e102`.
  Hash input is the sorted changed `crates/` paths (including new `service.rs`
  and `service_tests.rs`), each followed by NUL, file bytes and NUL.

## Automated results

| Check | Result |
| --- | --- |
| `cargo check --locked -p public-cert-service --bin public-cert-service` | Passed |
| `cargo test --locked -p locksmith -p public-cert-service --lib` | Passed: 34 + 15 tests |
| Same library suites with `--features unsafe-e2e` and `CAUTION_UNSAFE_KEY_SERVICE_E2E=1` | Passed: 35 + 16 tests |
| Platform `make test-quorum-mock`, using the local candidate | Passed |
| Existing certificate-service StageX build, Linux amd64, unsafe features disabled | Passed |

StageX build-stage image manifest: `186c5ec1d55442e1947a526eef8fd36b06454ac1414f99614b872e7c2b5c90c0`.
This is a build-stage digest, not an enclave measurement.

Native checks use Homebrew nettle@3/GMP/OpenSSL pkg-config paths. Socket-based
fixtures require execution outside the macOS command sandbox. Existing unrelated
Locksmith warnings remain unchanged.

Coverage added: AWS-signed attestation freshness at fixed clocks; destination
evidence rejected in another synthetic authorization session; recovered-root CA
matching; Keyfork loss/recovery and stalled I/O; single-flight certificate
generation retaining its permit after timeout or cancellation.

## Nitro acceptance

Candidate prepared as signed test-checkout commit
`da465e4e7ddffc4475c1a45a2c0bf2fc89af09ad`, based on the existing deployment
checkout `8b7d89f` and its unchanged bootstrap artifacts. Packaging preflight passes.

Live acceptance is pending for this increment. Automatic approval review blocked
the candidate push to the existing test deployment before execution. No remote
deployment, root recovery or restart was performed. Explicit approval of that
candidate/deployment is required to continue, followed by holder passkey approvals.
Local and synthetic success is not live Nitro evidence; no new measurements are
claimed here.

Reuse the existing external-PGP key service root key and test deployment inputs. Record
the deployed candidate revision and independently verified non-debug PCR0/1/2,
then exercise certificate creation, mixed recovery, below-threshold locking,
expected secret reconstruction, and recovery after enclave restart. Passkey
approvals require the existing holders. Keep those results distinct from a
restart of only the HTTP process, which preserves Keyfork's root.

## Deferred

Legacy compatibility, dashboard creation, endpoint access restrictions, shared
structure-hash registry, new supervision/health monitoring and release scheduling
changes are outside this increment. Endpoints remain public. The milestone does
not close every requirement under #7/#383/#384.
