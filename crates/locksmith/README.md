# PGP shard submission

The client and receiver reconstruct the bundle's OpenPGP certificates into one
in-memory public-key armor block for signing and signature verification. Every
holder's certificate is retained in order, including multiple certificates in a
legacy combined entry. Empty or malformed entries fail; WebAuthn entries return
an unsupported error because their shard transport is not implemented.

Reconstruction does not change the stored bundle, certificate strings, hash or
proof envelope.

Run `cargo test -p locksmith --lib --locked` and
`cargo check -p locksmith --all-targets --locked` from the workspace root.
The regression tests exercise software-key signing and receiver verification for
each holder, unrelated signatures, modified payloads and invalid keyring entries.
The synthetic envelope test checks preservation, not attestation validity.
These local tests do not establish full Nitro submission or smartcard readiness.

## Standalone CLI

```sh
locksmith ADDRESS [BUNDLE] [POLICY] [--keymaker-pcr-policy PATH]
locksmith 127.0.0.1:49504 --keymaker-pcr-policy keymaker-policy.json
```

The bundle defaults to `bundle.json`. Policy precedence is the named flag, then
the legacy third positional argument, then `KEYMAKER_PCR_POLICY_JSON` (a file
path, despite its name). Existing positional invocations remain supported.
Invalid arguments print usage and exit with status 2. This flag selects the
Keymaker proof policy, not destination-enclave PCRs; the standalone test binary
still hardcodes zero destination PCRs. Use Platform's CLI for its configured
destination verification flow.

## Proof diagnostics

When every PCR-policy set fails, the error includes each zero-based set index,
its verification error chain, or its expiry at proof creation. A failed set
does not prevent a later valid set from succeeding. No proof, credential or
bundle contents are included in these diagnostics.

Certificate validity is checked by Bootproof at the signed attestation timestamp,
without wall-clock substitution or a clock-skew adjustment. The deterministic
nonce and canonical bundle hash must still match. PCR-policy expiry is a cutoff
on the authenticated generation time, not the time the saved bundle is loaded:
a proof generated before the cutoff can remain valid after certificate expiry.
This follows [the timestamp policy in #7](https://codeberg.org/caution/locksmith/issues/7#issuecomment-19223141).

Tests use `tests/data/aws-test.cbor`, copied unchanged from Bootproof commit
`53a93872c17c22a253e4ecb8ade00c5964762e45`,
`crates/bootproof-sdk/src/format/data/aws-test.cbor`. This signed AWS fixture
tests historical verification and policy selection, not a proofed quorum bundle.
Fresh destination attestation, WebAuthn authorization and replay protection remain
separate requirements. Certificate-service integration, V0 compatibility, runtime
packaging and real Nitro deployment validation are still outstanding.

### Synthetic Keymaker proofs (tests only)

The non-default `unsafe-e2e` feature permits the existing Keymaker test proof only
when `CAUTION_UNSAFE_KEY_SERVICE_E2E=1` and the policy has exactly one non-expiring
set: PCRs 0, 1 and 2, each the byte `ab` repeated 48 times (96 hex characters).
The proof must equal the deterministic nonce recomputed from the canonical bundle
hash. Changed bundles, wrong proofs and other policies are rejected. Production
builds still reject this proof even with the environment variable set; normal
Nitro verification and the bundle format are unchanged.

Run `cargo test -p locksmith --test synthetic_proof` both without and with
`--features unsafe-e2e`. Each run checks absent, `0` and `1` runtime flags in
separate processes. Build the mock Keymaker with
`cargo build -p keymaker --no-default-features --features unsafe-e2e` and launch
it with the same environment flag. Never use these binaries or PCR values in a
production deployment. This exercises PGP orchestration, not attestation security.

[Design #7](https://codeberg.org/caution/locksmith/issues/7) remains authoritative:
V0 fallback/upgrade is deferred under [#11](https://codeberg.org/caution/locksmith/issues/11)
and PR #15; WebAuthn recryption is under [#12](https://codeberg.org/caution/locksmith/issues/12).
This test hook completes neither ticket. Real Nitro validation and production
policy provisioning remain release dependencies.
