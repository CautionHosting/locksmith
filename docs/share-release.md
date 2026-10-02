# WebAuthn share recovery

See [the current V1 contract](v1-contract.md) for the accepted CA-certified UID
profile, critical-notation checks, fixed compatibility fixtures and first-test scope.
See [key-service deployment](key-service-deployment.md) for configuration, proof checks,
root unlock and trust-policy updates.

The existing certificate service also hosts `/v1/releases/begin`, `/prepare` and
`/complete`. It uses the same bootstrapped Keyforkd key service root key. Keymaker remains
single-use and is not called during recovery, retries or restarts.

Set `CAUTION_RELEASE_CONFIG` to an immutable image file containing `rp_id`, `origin`,
`keymaker_policy_path`, and `ca_cert_path`. See the certificate-service example.
Origin must be HTTPS and match the registered Platform origin. Bundle credential
snapshots must contain the passkey used to approve. CA and Keymaker policy files
are independently verified public trust inputs, not discovered from a service.
The deployment example uses `/etc/caution/keymaker-pcr-policy.json` for both root
recovery and application release. Its `sets` list retains approved historical
measurements and optional generation-time cutoffs; a `current` marker is not needed
to verify necroproofs. Preserve the sets needed by the existing root when updating
application-generation trust. See [policy migration](key-service-deployment.md#migrating-a-deployment-with-two-policy-files).

Begin authenticates the proofed bundle at generation time and its selected
certificate's CA-certified organization/bundle/index. Prepare checks fresh
nonce-bound destination Nitro evidence against the holder-approved PCR0/1/2.
Responses attest the exact request hash, context and WebAuthn options under a fresh
CLI nonce. The CLI independently verifies both enclaves. Usernames have no role
in release authorization.

Pending state stays in the enclave, with a three-minute lifetime, 64-entry global
limit and eight entries per authenticated organization/bundle. Reservations remain
counted while preparation runs; overload returns 503. Complete atomically consumes the state before verifying the raw WebAuthn
assertion, requires verified UV, then derives only the selected private key.
Failed and concurrent attempts cannot reuse authorization. Restart invalidates
pending requests. Multiple passkeys on a holder authorize the same share.

The key service root key lives in Keyfork for the enclave's lifetime. Restarting only the
HTTP process invalidates pending approvals but retains that root. Restarting the
enclave requires fresh external-PGP quorum recovery of the existing root bundle;
it does not require generating a new bundle or calling Keymaker.

Before binding its listener, the service derives the root CA from Keyfork and
checks its fingerprint against the CA in `CAUTION_RELEASE_CONFIG`, when configured.
`GET /health` repeats that check on demand, caching success and failure for two
seconds and coalescing concurrent refreshes. It returns 503 when Keyfork is unusable
or the CA mismatches. A disconnected or timed-out caller does not end a refresh. No background health monitor is installed.

Certificate generation runs on a blocking worker, with one operation admitted at
a time. Busy/unavailable operations return 503. The 60-second request budget covers
derivation, Keyfork socket I/O and proof generation; a timeout or disconnected
caller does not free the slot until its worker finishes. Release routes share four blocking-worker permits, acquired before scheduling,
with the same 60-second request budget and bounded Keyfork I/O. Those permits stay
held until workers finish even after timeout or disconnect.

Certificate issuance requires `PUBLIC_CERTIFICATE_SERVICE_TOKEN` as a bearer token
before request-body processing (401 if absent/incorrect; 503 if the service token
is not configured). Release routes remain public and WebAuthn-authorized. Missing
issuance configuration does not disable recovery in a running service. The example
deployment requires the encrypted token as a startup input.
See [hardening and acceptance checks](service-hardening.md).

Recryption checks the shardfile's threshold, holder order, signature and share
coordinate. Plaintext and derived private keys stay in the key-service enclave.
The response is the unchanged Locksmith holder-signed X25519/HKDF/AES-GCM
request, relayed on the destination connection used for attestation.

## Local checks

`cargo test -p locksmith --lib` checks default proof rejection and authorization.
`CAUTION_UNSAFE_KEY_SERVICE_E2E=1 cargo test -p locksmith --lib --features unsafe-e2e release::tests`
exercises synthetic live evidence and mixed share recryption using a software
passkey. Synthetic evidence additionally requires the exact three nonzero `ab`
PCRs (48 bytes each). Default builds reject it even with the flag set. These tests
are not Nitro or real-device evidence.

The default release tests also verify freshness using the AWS-signed attestation
fixture at fixed clocks. The synthetic mixed-recovery test rejects destination
evidence reused under another authorization session's transport nonce.
`cargo test -p public-cert-service --lib` checks readiness, CA mismatch, unavailable
and stalled Keyfork, and generation admission after timeout or cancellation.

`CAUTION_UNSAFE_KEY_SERVICE_E2E=1 cargo test -p public-cert-service --lib --features unsafe-e2e release::tests`
runs the actual key-service HTTP handlers and Locksmith TCP receiver with the same
test Keyforkd root: WebAuthn-only and mixed recovery, below-threshold locking,
second-passkey duplicate-holder rejection, replay rejection and expected secret
reconstruction. No Keymaker or deployed service is used.

## Status

The minimal V1 completion increment covers these tests, readiness and bounded
certificate generation. Legacy compatibility, dashboard creation, further endpoint access
restrictions and the shared structure-hash registry remain deferred. It does not
close every requirement under #7, #383 or #384. See
[the validation record](minimal-v1-validation.md) for this increment's evidence.

Acceptance applies to the exact revisions and measurements in that record.
Credential rotation, multi-instance state and production root management remain
separate work; #7/#10/#11/#12 are not closed by this change.

## Durable key-service identities

WebAuthn holder snapshots are validated at authenticated Keymaker generation time.
The CLI and receiver verify current transport signatures against those exact
eligible signing keys, even after snapshot expiry. Signatures are not backdated;
proof-bound bundles are unchanged. External-PGP verification retains its existing
certificate-lifetime rules. A configured CA primary key is a durable trust anchor:
snapshot expiration alone does not retire it, while revocation, algorithm,
certification-signature and organization/bundle/index checks remain enforced.
These rules do not discover later revocations or rotate the stored holder keys.
Deleting or resetting a Platform credential does not revoke its authority in
existing quorum bundles.

Explicit smartcard holder selection filters encryption fingerprints before PIN
entry and both metadata/share decryption. An absent selected card fails without
prompting another holder's card. Unit tests cover both enumeration orders; physical
multi-card operation remains a hardware acceptance check.

External-PGP smartcard and private-key signing use the certificate's accepted
hash preferences when available, otherwise SHA-512. This permits signing with
older certificates that omit hash preferences. To use this client-side fix,
update Platform's pinned Locksmith revision and rebuild the CLI; existing bundles,
the key service root key and deployed services do not need replacement.

## Smartcard prompt progress

External-PGP card recovery labels its three operations: decrypt/check bundle
metadata, decrypt the selected holder's share, and sign the encrypted submission
to the destination. Each PIN and touch instruction names its operation. Completion
is printed only after that operation succeeds; signing completion is not a share
acceptance acknowledgement. The destination's response determines acceptance.

Interactive card PIN entry stays inline with hidden input, preserving the CLI's
application/holder/destination summary and earlier progress. Echo is disabled before
the prompt appears, protecting immediate input. It does not clear the screen or
cache a PIN. Ctrl-C cancels and restores terminal input settings. Explicit
headless prompting and noninteractive handling keep their existing behavior. The
three card operations and their PIN/touch requirements are unchanged. No bundle,
protocol or enclave redeployment is required; rebuild the consuming CLI.

Regression checks: run `cargo test -p locksmith --lib`, then pass the resulting
Locksmith test executable to
`python3 crates/locksmith/tests/card_prompt_pty.py /path/to/locksmith-test-binary`.
The PTY test sends input as soon as `PIN: ` appears and covers hidden input, multiline
prompt layout, retained output and terminal restoration on success, cancellation,
and validation exhaustion. It does not validate a physical YubiKey; manually recover
one share and confirm all three labelled operations and final acknowledgement.

Local validation: Locksmith library regressions and PTY success, cancellation,
and three-attempt PIN-format validation pass on macOS. Physical-card acceptance
remains pending: cancel at each of the three PIN prompts and confirm that no later
operation or submission occurs; then complete recovery and confirm the receiver
acknowledges the share. Existing error propagation still stops metadata failure
before share decryption, share failure before signing, and signing failure before
network submission. These hardware failure paths were source-reviewed, not
exercised against a physical card.

## Certified indices and independent recipients

Release obtains the certificate derivation index from the canonical
`Caution public certificate index=N` UID authenticated by the configured CA at
bundle-generation time. The index is independent of `holder_position`, which
continues to address the holder inside the proof-bound keyring. Subsets and
reordered certificates therefore retain their original derivation indices.
Conflicting authenticated indices or organizations, malformed indices, and
invalid CA/bundle context are rejected. Existing affected bundles need no format
change or reordering; deploy the corrected certificate service to recover them.

Keymaker rejects ECDH recipients in different holders sharing the same curve and
public point even when their KDF hash or cipher differs. Equivalent subkeys within
one holder are deduplicated for validation and remain valid for shard encryption. Normalization applies only to copied
comparison material; the certificates and encryption parameters are unchanged.
An existing quorum with shared encryption material remains weak after upgrading
validation and requires a separate assessment/migration. Coordinate the matching
Platform API/CLI checks with the Keymaker deployment. Rebuild the affected services
and establish the trusted PCR policies for those builds; a client update alone
does not update the services.

Focused regression checks:

```sh
cargo test --locked -p keymaker --no-default-features
cargo test --locked -p locksmith --lib release::tests
CAUTION_UNSAFE_KEY_SERVICE_E2E=1 cargo test --locked -p locksmith --lib --features unsafe-e2e release::tests
```

The tests cover independent KDF variations, canonical certified indices and
invalid contexts, and synthetic subset/reordered/mixed release through assertion
verification and share re-encryption. Synthetic tests supply fixture private keys;
they do not establish live key-service key provisioning or Nitro behavior.

Validation on 2026-09-19: Keymaker's host suite passed (10 tests), including
within-holder KDF variants, cross-holder rejection in both orders, and real 1-of-1
shard encryption with equivalent subkeys. The gated synthetic release suite passed (10 tests), including 1-of-1 certificate-index-1,
reordered WebAuthn, and mixed-holder cases. No service deployment or live Nitro
validation was performed.
