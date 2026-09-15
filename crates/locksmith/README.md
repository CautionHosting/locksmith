# PGP shard submission

The client and receiver reconstruct the bundle's OpenPGP certificates into one
in-memory public-key armor block for signing and signature verification. Every
holder's certificate is retained in order, including multiple certificates in a
legacy combined entry. Empty or malformed entries fail; WebAuthn entries return
an unsupported error because their shard transport is not implemented.

Reconstruction does not change the stored bundle, certificate strings, hash or
proof envelope. Historical proof verification remains separate work.

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

The certificate-validation time remains unchanged; historical proof validation
still needs the shared Bootproof fix. Tests use fixed policy dates with
`tests/data/aws-test.cbor`, copied unchanged from Bootproof commit
`53a93872c17c22a253e4ecb8ade00c5964762e45`,
`crates/bootproof-sdk/src/format/data/aws-test.cbor`. This signed AWS fixture
tests the low-level verifier and policy selection, not a proofed quorum bundle.
