# Certificate and share-release service

This example runs certificate derivation and WebAuthn-authorized share recryption
in the same enclave, using the same externally bootstrapped Keyforkd key service root key.
**Deployment remains gated on final Platform dependency pins and automated tests.**
It does not implement production root management or close #7/#10/#11/#12.

## Prepare the existing deployment checkout

Use the existing certificate-service deployment worktree. Preserve its root
bundle, Keymaker policy, encrypted issuance token and public CA. Do not create
a new root for this upgrade. The example folder is not a standalone repository:
Caution builds the whole Locksmith checkout using the root `caution.hcl`.

For a new deployment, start from these templates. For an existing deployment,
retain its RP ID/origin and update only the policy path as described in the
[migration steps](../../docs/key-service-deployment.md#migrating-a-deployment-with-two-policy-files).

```sh
cp examples/certificate-service/caution.hcl caution.hcl
cp examples/certificate-service/release-config.example.json .caution/release-config.json
```

Configure the exact registered Platform RP ID and HTTPS origin. Required inputs:

| File | Purpose |
| --- | --- |
| `.caution/quorum-bundle.json` | Existing external-PGP root quorum, proofed V1 envelope |
| `.caution/keymaker-pcr-policy.json` | Approved Keymaker PCR sets for both the existing root and application bundles |
| `.caution/secrets/PUBLIC_CERTIFICATE_SERVICE_TOKEN.asc` | Encrypted 32-byte hex issuance token, shared with Platform |
| `.caution/caution-ca.asc` | Public CA from the verified root bundle |
| `.caution/release-config.json` | RP/origin and paths to measured verifier inputs |

The image contains these public/encrypted inputs. Never copy private holder keys
or plaintext root material into the checkout. Both root recovery and application
share release read `/etc/caution/keymaker-pcr-policy.json`; configure that path in
`release-config.json`. The shared policy can contain several approved PCR sets
and generation-time cutoffs. It has no `current` flag: each necroproof is checked
against its authenticated generation time, including proofs from older images.
Retain the sets needed by the existing root and supported application bundles.
See [migration from two policies](../../docs/key-service-deployment.md#migrating-a-deployment-with-two-policy-files)
before rebasing an existing deployment that still has separate files.

```sh
python3 examples/certificate-service/check-inputs.py
```

Preflight checks packaging; CLI and runtime still verify cryptographic proofs.
Verify the root bundle and intended application bundles against the same policy
before committing or deploying. Adding approved Keymaker measurements changes
the measured key-service image: rebuild/redeploy, verify, recover the existing
root and refresh client/Platform service trust. See
[Keymaker upgrades](../../docs/key-service-deployment.md#keymaker-upgrades-and-release-trust).
For a new service, follow [initial bootstrap](../../docs/key-service-deployment.md#initial-bootstrap)
to create the external-PGP root quorum, export its public CA and provision the
issuance token. Existing-root upgrades do not generate another quorum.

## Automated gate and manual acceptance

See [share-release verification and local tests](../../docs/share-release.md) and
Platform's `docs/share-recovery.md`. Keep unsafe E2E features out of deployment.
The packaging regressions and production StageX build stage can be checked
without any root artifacts:

```sh
python3 examples/certificate-service/test_inputs.py
docker build --target build -f examples/certificate-service/Containerfile .
```

After the gate passes, deploy the updated service from this checkout and unlock
it with the existing external-PGP root holders. Record the new non-debug PCRs;
configure those independently verified measurements in the CLI's recryptor
policy and Platform's certificate-service policy. Release routes remain public. Certificate issuance requires the shared bearer token;
it is not permission to release a share. See [migration and acceptance](../../docs/service-hardening.md).

The encrypted token replaces the old fixed bootstrap marker: its `env::vault`
reference still enables Locksmith and gates application startup on root recovery.
The token is not the key service root key and cannot replace the external-PGP quorum.

Startup verifies the configured CA against the recovered Keyfork root before
serving. `/health` caches success and failure for two seconds and returns 503 if that root
cannot be used or does not match. Concurrent checks share one refresh.
Certificate generation admits one blocking worker with a 60-second request budget,
including Keyfork I/O; busy requests return 503. Timed-out workers retain their
slot until they finish. Restarting only HTTP preserves Keyfork; an enclave restart
requires fresh quorum recovery of the existing root bundle.

Use an existing WebAuthn bundle to exercise native and browser approvals against
an application enclave: locked below threshold, expected secret at threshold,
replay rejection, one share per holder, then restart both enclaves and repeat.
The passkeys must already exist in the bundle's credential snapshots.

Generate a mixed quorum only after deploying **one fresh Keymaker** and updating
Platform's Keymaker address and verified PCR policy, and deploying a key service
whose shared generation policy accepts that image. Recover it with external PGP
plus WebAuthn. Recovery, approval retries and restarts never call Keymaker.
Record source revisions, PCRs, bundle identifiers and results; synthetic/local
success does not establish real Nitro acceptance.

Both certificate-service image recipes include the pinned PCSC build dependency
required by the current Locksmith dependency graph. The deployable example
normalizes public configuration and encrypted bootstrap files to `0644`, and
directories/start script to `0755`, before copying them into the runtime image.
Host umask must not change the measured configuration. This does not change the
key service root key or the `/etc/caution` configuration layout.
