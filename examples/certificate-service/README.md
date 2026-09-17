# Certificate and share-release service

This example runs certificate derivation and WebAuthn-authorized share recryption
in the same enclave, using the same externally bootstrapped Keyforkd custody root.
**Deployment remains gated on final Platform dependency pins and automated tests.**
It does not implement production root management or close #7/#10/#11/#12.

## Prepare the existing deployment checkout

Use the existing certificate-service deployment worktree. Preserve its root
bundle, Keymaker policy, encrypted bootstrap marker and public CA. Do not create
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
| `.caution/secrets/CERTIFICATE_BOOTSTRAP.asc` | Existing encrypted `certificate-service-bootstrap-v1` startup marker |
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
encrypt the marker using `caution secret encrypt CERTIFICATE_BOOTSTRAP`; each new
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
policy and Platform's certificate-service policy. Restrict test ingress as
appropriate: public certificate issuance is not permission to release a share.

Use an existing WebAuthn bundle to exercise native and browser approvals against
an application enclave: locked below threshold, expected secret at threshold,
replay rejection, one share per holder, then restart both enclaves and repeat.
The passkeys must already exist in the bundle's credential snapshots.

Generate a mixed quorum only after deploying **one fresh Keymaker** and updating
Platform's Keymaker address and verified PCR policy. Recover it with external PGP
plus WebAuthn. Recovery, approval retries and restarts never call Keymaker.
Record source revisions, PCRs, bundle identifiers and results; synthetic/local
success does not establish real Nitro acceptance.
