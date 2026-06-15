# WebAuthn share recovery

The existing certificate service also hosts `/v1/releases/begin`, `/prepare` and
`/complete`. It uses the same bootstrapped Keyforkd custody root. Keymaker remains
single-use and is not called during recovery, retries or restarts.

Set `CAUTION_RELEASE_CONFIG` to an immutable image file containing `rp_id`, `origin`,
`keymaker_policy_path`, and `ca_cert_path`. See the certificate-service example.
Origin must be HTTPS and match the registered Platform origin. Bundle credential
snapshots must contain the passkey used to approve. CA and Keymaker policy files
are independently verified public trust inputs, not discovered from a service.

Begin authenticates the proofed bundle at generation time and its selected
certificate's CA-certified organization/bundle/index. Prepare checks fresh
nonce-bound destination Nitro evidence against the holder-approved PCR0/1/2.
Responses attest the exact request hash, context and WebAuthn options under a fresh
CLI nonce. The CLI independently verifies both enclaves. Usernames have no role
in release authorization.

Pending state stays in the enclave, with a three-minute lifetime and 64-entry
limit. Complete atomically consumes the state before verifying the raw WebAuthn
assertion, requires verified UV, then derives only the selected private key.
Failed and concurrent attempts cannot reuse authorization. Restart invalidates
pending requests. Multiple passkeys on a holder authorize the same share.

The custody root lives in Keyfork for the enclave's lifetime. Restarting only the
HTTP process invalidates pending approvals but retains that root. Restarting the
enclave requires fresh external-PGP quorum recovery of the existing root bundle;
it does not require generating a new bundle or calling Keymaker.

Before binding its listener, the service derives the root CA from Keyfork and
checks its fingerprint against the CA in `CAUTION_RELEASE_CONFIG`, when configured.
`GET /health` repeats that check on demand and returns 503 when Keyfork is unusable
or the CA mismatches. No background health monitor is installed.

Certificate generation runs on a blocking worker, with one operation admitted at
a time. Busy/unavailable operations return 503. The 60-second request budget covers
derivation, Keyfork socket I/O and proof generation; a timeout or disconnected
caller does not free the slot until its worker finishes. Release scheduling is
unchanged. Endpoints remain public for now; certificate issuance does not authorize
share release.

Recryption checks the shardfile's threshold, holder order, signature and share
coordinate. Plaintext and derived private keys stay in the custody enclave.
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
runs the actual custody HTTP handlers and Locksmith TCP receiver with the same
test Keyforkd root: WebAuthn-only and mixed recovery, below-threshold locking,
second-passkey duplicate-holder rejection, replay rejection and expected secret
reconstruction. No Keymaker or deployed service is used.

## Status

The minimal V1 completion increment covers these tests, readiness and bounded
certificate generation. Legacy compatibility, dashboard creation, endpoint access
restrictions and the shared structure-hash registry remain deferred. It does not
close every requirement under #7, #383 or #384. See
[the validation record](minimal-v1-validation.md) for this increment's evidence.

Acceptance applies to the exact revisions and measurements in that record.
Credential rotation, multi-instance state and production root management remain
separate work; #7/#10/#11/#12 are not closed by this change.

## Durable custody identities

WebAuthn holder snapshots are validated at authenticated Keymaker generation time.
The CLI and receiver verify current transport signatures against those exact
eligible signing keys, even after snapshot expiry. Signatures are not backdated;
proof-bound bundles are unchanged. External-PGP verification retains its existing
certificate-lifetime rules. A configured CA primary key is a durable trust anchor:
snapshot expiration alone does not retire it, while revocation, algorithm,
certification-signature and organization/bundle/index checks remain enforced.
These rules do not discover later revocations or rotate the stored holder keys.

Explicit smartcard holder selection filters encryption fingerprints before PIN
entry and both metadata/share decryption. An absent selected card fails without
prompting another holder's card. Unit tests cover both enumeration orders; physical
multi-card operation remains a hardware acceptance check.

External-PGP smartcard and private-key signing use the certificate's accepted
hash preferences when available, otherwise SHA-512. This permits signing with
older certificates that omit hash preferences. To use this client-side fix,
update Platform's pinned Locksmith revision and rebuild the CLI; existing bundles,
the custody root and deployed services do not need replacement.
