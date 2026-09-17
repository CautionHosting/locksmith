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

`CAUTION_UNSAFE_KEY_SERVICE_E2E=1 cargo test -p public-cert-service --lib --features unsafe-e2e release::tests`
runs the actual custody HTTP handlers and Locksmith TCP receiver with the same
test Keyforkd root: WebAuthn-only and mixed recovery, below-threshold locking,
second-passkey duplicate-holder rejection, replay rejection and expected secret
reconstruction. No Keymaker or deployed service is used.

## Status

Local authorization/HTTP recovery tests and production StageX custody/runtime
builds pass. Platform integration tests, virtual-browser approval and its API
StageX build also pass with a temporary source override. Final immutable
dependency/runtime pins and the consolidated real Nitro test remain pending.
Do not deploy until those pins and the automated acceptance gate are complete. V0/earlier-V1
compatibility, credential rotation, multi-instance state and production root
management remain separate work; #7/#10/#11/#12 are not closed by this change.
