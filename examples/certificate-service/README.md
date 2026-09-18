# Certificate and share-release service

This example runs certificate derivation and WebAuthn-authorized share recryption
in the same enclave, using the same externally bootstrapped Keyforkd custody root.
**Deployment remains gated on final Platform dependency pins and automated tests.**
It does not implement production root management or close #7/#10/#11/#12.

## Prepare the existing deployment checkout

Use the existing certificate-service deployment worktree. Preserve its root
bundle, Keymaker policy, encrypted issuance token and public CA. Do not create
a new root for this upgrade. The example folder is not a standalone repository:
Caution builds the whole Locksmith checkout using the root `caution.hcl`.

```sh
cp examples/certificate-service/caution.hcl caution.hcl
cp examples/certificate-service/release-config.example.json .caution/release-config.json
```

Configure the exact registered Platform RP ID and HTTPS origin. Required inputs:

| File | Purpose |
| --- | --- |
| `.caution/quorum-bundle.json` | Existing external-PGP root quorum, proofed V1 envelope |
| `.caution/keymaker-pcr-policy.json` | Independently verified policy for that root bundle |
| `.caution/secrets/PUBLIC_CERTIFICATE_SERVICE_TOKEN.asc` | Encrypted 32-byte hex issuance token, shared with Platform |
| `.caution/caution-ca.asc` | Public CA from the verified root bundle |
| `.caution/release-config.json` | RP/origin and paths to measured verifier inputs |
| `.caution/release-keymaker-pcr-policy.json` | Independently verified Keymaker policies for application bundles to recover |

The image contains these public/encrypted inputs. Never copy private holder keys
or plaintext root material into the checkout. The release generation policy can
contain several approved PCR sets/cutoffs; it is distinct from the root's policy.

```sh
python3 examples/certificate-service/check-inputs.py
```

Preflight checks packaging; CLI and runtime still verify cryptographic proofs.
The root must be externally recoverable without this service. If starting a
completely new disposable test, first create an external-PGP root quorum and
encrypt the token using `caution secret encrypt PUBLIC_CERTIFICATE_SERVICE_TOKEN`; each new
quorum consumes **one fresh Keymaker**. An existing-root upgrade consumes none.

## Automated gate and manual acceptance

See [share-release verification and local tests](../../docs/share-release.md) and
Platform's `docs/share-recovery.md`. Keep unsafe E2E features out of deployment.
The production StageX build stage can be checked without any root artifacts:

```sh
docker build --target build -f examples/certificate-service/Containerfile .
```

After the gate passes, deploy the updated service from this checkout and unlock
it with the existing external-PGP root holders. Record the new non-debug PCRs;
configure those independently verified measurements in the CLI's recryptor
policy and Platform's certificate-service policy. Release routes remain public. Certificate issuance requires the shared bearer token;
it is not permission to release a share. See [migration and acceptance](../../docs/service-hardening.md).

The encrypted token replaces the old fixed bootstrap marker: its `env::vault`
reference still enables Locksmith and gates application startup on root recovery.
The token is not the custody root and cannot replace the external-PGP quorum.

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
Platform's Keymaker address and verified PCR policy. Recover it with external PGP
plus WebAuthn. Recovery, approval retries and restarts never call Keymaker.
Record source revisions, PCRs, bundle identifiers and results; synthetic/local
success does not establish real Nitro acceptance.

Both certificate-service image recipes include the pinned PCSC build dependency
required by the current Locksmith dependency graph. The deployable example
normalizes public configuration and encrypted bootstrap files to `0644`, and
directories/start script to `0755`, before copying them into the runtime image.
Host umask must not change the measured configuration. This does not change the
custody root or the `/etc/caution` configuration layout.
