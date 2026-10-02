# PGP shard submission

For explicit holder-assisted legacy imports, packaging and rebuild instructions,
see [Imported V0 recovery](../../docs/legacy-v0.md).

With a private-key file, the client selects the first holder in bundle order
whose matching private certificate has both decryption and usable signing keys.
It decrypts with only that certificate and signs against only that holder's
public certificate. To contribute as another holder, supply that holder's private
certificate separately. Missing matching keys fail before submission.

The client checks the decrypted threshold and share coordinate against the
bundle. Keymaker assigns coordinate `index + 1` to each holder in bundle order;
this invariant also identifies the signer after smartcard decryption. A smartcard
signing key must match that holder. Old encryption keys remain usable for stored
shares; signing still follows the existing signature policy.

Before listening, the receiver prepares each
holder entry separately and reads the threshold from the verified bundle.
Empty or malformed entries fail at startup; WebAuthn/mixed bundles report an
unsupported error because their shard transport is not implemented.

A signature must identify exactly one bundle holder. Recovery counts each holder
and share coordinate once, rejects conflicting client thresholds and malformed
shares, and leaves the remaining count unchanged on rejection. The existing
`Accepted`/`Rejected` wire responses are unchanged. After the required distinct
contributions arrive, the recovered entropy must derive the same OpenPGP primary
key fingerprint as the proof-bound bundle before any seed is served. A mismatch
terminates recovery; the listener stops on both success and failure. This check
detects incorrect recovery but does not identify which holder supplied bad data
or prevent an authorized holder from denying recovery.

Reconstruction does not change the stored bundle, certificate strings, hash or
proof envelope.

Recovery frame bodies must be between 32 bytes and 1 MiB, including the checksum;
the length is checked before allocation. Each listener admits at most 32 active
connections and closes excess connections immediately. Each connection has five
minutes to finish the entire exchange, including PIN/QR approval and socket I/O.
The overall wait for the quorum remains unlimited. If disconnected while idle or
busy, start a fresh submission; if an acknowledgement was lost, check the CLI and
quorum status first because an already accepted share is not rolled back.
These limits preserve the wire format and require rebuilding and redeploying the
Locksmith receiver, then verifying the updated image. Updating the CLI alone does
not harden existing deployed receivers. They bound resources, not availability
under a sustained flood.

Run `cargo test -p locksmith --lib --locked` and
`cargo check -p locksmith --all-targets --locked` from the workspace root.
The regression tests exercise software-key signing and receiver verification for
each holder, multi-holder private files through 2-of-2 recovery, missing signing
keys, mismatched coordinates/thresholds, unrelated signatures, modified payloads
and invalid keyring entries.
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

`bundle::load_response_with_timestamp` returns the verified bundle and
`Some(SystemTime)` from the signed attestation, allowing callers to validate
historical holder eligibility at generation time. The existing `load_response`
continues to return only the bundle. The explicitly enabled synthetic test path
returns `None` because its proof has no authenticated time.

Expiry values outside the host's supported `SystemTime` range are rejected when
parsing the policy. Every PCR value must decode to exactly 48 bytes; truncated
values fail with a policy diagnostic. Missing or null expiry values mean no cutoff.

Tests use `tests/data/aws-test.cbor`, copied unchanged from Bootproof commit
`53a93872c17c22a253e4ecb8ade00c5964762e45`,
`crates/bootproof-sdk/src/format/data/aws-test.cbor`. This signed AWS fixture
tests historical verification and policy selection, not a proofed quorum bundle.
Fresh destination attestation, WebAuthn authorization and replay protection remain
separate requirements. The [runtime image](../../README.md#locksmith-runtime-image)
packages operator-supplied bundle, policy and ciphertext inputs. Certificate-service
integration, V0 compatibility and real Nitro deployment validation remain outstanding.

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
