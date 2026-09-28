# Deploy the certificate and share-release service

For an existing service, preserve the root bundle, public CA and encrypted token;
an application Keymaker upgrade does not require a new key service root key.
See the [certificate-service example](../examples/certificate-service/README.md)
for packaged inputs.

## Initial bootstrap

This procedure is for operators deploying the key service and its Keymaker.
Users of hosted Keymaker generation do not construct the operator's generation
policy; self-hosting users must establish their own verified policy.

With an updated Platform API and CLI, hosted-service users can run:

```sh
export CAUTION_BACKEND_URL=https://platform.example.com
caution verify --service keymaker
caution verify --service key-service
```

With `CAUTION_BACKEND_URL` exported, `--url` is optional. An explicit `--url`
overrides the environment variable for that command. Replace the placeholder URL
with your Platform endpoint.

These commands discover the endpoint, ask before reproducing the advertised pinned
source, verify fresh attestation, and ask before saving client trust shared by
projects on that Platform. First-use hosted creation/passkey release offers the
same setup.

This client setup leaves application measurements and existing bundle policies
unchanged. It does **not** install operator policies or `caution-ca` on Platform,
configure gateway release trust, or package policies in the key-service image.
Continue with the operator steps below; retain historical generation policies
when approving newer service images. `caution secret inspect` checks a bundle
against the existing project policy or saved Keymaker trust.

Skip this section when deploying or upgrading an existing root. For a new service,
use a dedicated checkout without an existing root bundle. Select external PGP root
holders using registered organization keys, a local public keyring, or both, as
shown below. Keep private keys with the holders. The root must be recoverable
without this service's passkeys.

### Establish the Keymaker policy

After deploying Keymaker, verify it from its own checkout against a locally
reproduced build. Use the intended Platform backend for this and subsequent CLI
commands (`CAUTION_BACKEND_URL` or `--url`):

```sh
cd /path/to/keymaker-checkout
caution verify
```

Continue only after verification succeeds for the intended non-debug deployment.
The CLI saves its verified PCR0/1/2 in `.caution/trusted_hashes.json`. Pass this file
from the **Keymaker checkout** directly to `caution secret init` from the **new
key-service checkout**. No JSON conversion is needed:

```sh
cd /path/to/key-service-checkout
```

Replace the checkout paths. `caution secret init` converts the flat
`pcr0`/`pcr1`/`pcr2` input into one non-expiring set and saves the existing `sets`
format in `.caution/keymaker-pcr-policy.json`. `verified_at` and `tls` are metadata, not
proof of verification or a policy expiry. For multiple approved measurement sets
or per-set cutoffs, use the existing `sets` format:

```json
{"sets":[{"pcrs":{"0":"<PCR0 hex>","1":"<PCR1 hex>","2":"<PCR2 hex>"},"expires_at_unix_seconds":null}]}
```

Add one entry per approved image, using 96 hexadecimal characters for each PCR.
Each optional expiry is checked against the bundle's signed attestation timestamp.
Do not mix flat PCR fields with `sets` or expiry fields; such inputs are rejected.
Do not substitute unverified values from `/attestation`, or reuse an older saved
file after a failed verification. Trust comes from successful verification, not
the file format. Retain the Keymaker revision and verification record with the policy.

Flat input requires an updated Caution CLI. Services and runtimes continue to
consume the saved `sets` policy, so this convenience requires no Locksmith upgrade
or dependency-pin change. Package the saved policy, not the original flat file.

### Configure Platform trust before uploading

When uploading a bundle to Platform (the default), its API independently verifies
the proof against the server's `KEYMAKER_PCR_POLICY_PATH`. The CLI's
`--keymaker-pcr-policy` does not update that server policy. Before generation with
upload enabled, the Platform operator must add the verified Keymaker measurements
to the API's policy, retaining approved sets needed by existing bundles.

The API requires **`sets` format**, not the flat `trusted_hashes.json` accepted by
the updated CLI. To prepare a new policy from the verified Keymaker checkout:

```sh
jq -e '{sets: [{pcrs: {"0": .pcr0, "1": .pcr1, "2": .pcr2}}]}' \
  /path/to/keymaker-checkout/.caution/trusted_hashes.json \
  > /path/to/new-keymaker-pcr-policy.json
```

Install the reviewed policy at the API's configured path and ensure the running
API can read the updated file. The upload handler reads the file on each request;
changing its configured environment path requires restarting/reloading the API.
This is an operator prerequisite; ordinary hosted-service users do not administer
this policy. Local-only generation with `--no-upload` does not require it.

If generation already succeeded but upload failed, the saved
`.caution/keymaker-pcr-policy.json` is already in `sets` format. Use its verified
measurements to update the API policy and retain the existing bundle. Do not rerun
`secret init` to retry upload: it creates another root and can overwrite the local
bundle. A locally verified bundle can still be used for key-service bootstrap.

### Generate the root quorum

Choose one holder-selection method below; do not run each example to create
separate roots. Set the threshold explicitly to the required number of shares.

**Recommended: select registered holders with the CLI.** This avoids manually
exporting and combining certificates, and explicitly selects each holder's
registered key. Authenticate to the intended Platform organization and select
external PGP custody. No local `.asc` file is needed when all selected certificates
are registered:

```sh
caution secret init --threshold 2 \
  --holder alice=external-pgp --pgp-key alice=ALICE_FULL_FINGERPRINT \
  --holder bob=external-pgp --pgp-key bob=BOB_FULL_FINGERPRINT \
  --keymaker-url https://keymaker.example.com \
  --keymaker-pcr-policy /path/to/keymaker-checkout/.caution/trusted_hashes.json
```

Replace the usernames and fingerprints. `--holder` accepts a username or user UUID;
`--pgp-key` selects an active registered key by full fingerprint or registration
UUID, not a key file path. It is optional when the holder has one eligible key;
select it explicitly to disambiguate multiple keys. This selects the public
certificate, not the private key or card used later to unlock the service.
Organization lookup requires authentication even with `--no-upload`.

**Alternative for unregistered holders or bootstrap without Platform lookup:**
collect the holders' public certificates in `root-holders.asc`. Never include
private-key exports:

```sh
caution secret init root-holders.asc --threshold 2 \
  --keymaker-url https://keymaker.example.com \
  --keymaker-pcr-policy /path/to/keymaker-checkout/.caution/trusted_hashes.json --no-upload
```

**Combine both:** supply a keyring containing only the additional local public
certificates alongside the registered holders:

```sh
caution secret init additional-holders.asc --threshold 2 \
  --holder alice=external-pgp --pgp-key alice=ALICE_FULL_FINGERPRINT \
  --keymaker-url https://keymaker.example.com \
  --keymaker-pcr-policy /path/to/keymaker-checkout/.caution/trusted_hashes.json
```

Each local certificate and each selected organization user contributes one holder.
Do not select an organization user twice or repeat a certificate across the inputs.
`--max`, if supplied, must equal the combined holder count. These root-bootstrap
examples use only external PGP custody, never `--holder USER=webauthn`.

`--no-upload` skips bundle registration; registered-holder lookup still requires
authentication. Upload includes encrypted shares, public certificates and proof,
never plaintext root material or holder private keys. Local files are saved either
way; retain them if upload fails rather than regenerate.

After the chosen generation command succeeds, export the new public CA:

```sh
jq -er '.data.public_key' .caution/quorum-bundle.json > .caution/caution-ca.asc
```

Keymaker generates the root entropy inside its enclave and encrypts its shares to
those holders. The CLI verifies the proof and saves the bundle and bootstrap policy
under `.caution/`. Operators receive no plaintext root. The exported public key
identifies the CA derived from that root; retain it with the bundle and policy.

Provision this same **public** `caution-ca.asc` on the Platform API host (for
example, using `scp`) and mount it read-only into the API container. With
Platform's default Makefile policy-directory mount, place it in
`~/.config/caution/policies/caution-ca.asc` on the host running Platform and set
this container-visible path in the API's private environment configuration:

```sh
CAUTION_CA_CERT_PATH=/run/config/caution-ca.asc
```

Use the actual mounted path if your deployment differs. Platform uses this CA to
validate the holder certificates issued by the key service during WebAuthn/mixed
quorum creation; uploading the root bundle does not configure it automatically.
Configure it before enabling issuance against the new root. The API reads the
certificate on each issuance request; changes to environment or mounts require
restarting/recreating the affected API process/container. Copy only the exported
public certificate, never holder private keys. The CA certificate and the verified
live key-service PCR policy are separate trust inputs; configure both.

Generate a separate issuance token in an existing private directory outside Git,
then encrypt it to the root bundle. Use a new file path:

```sh
(umask 077; set -C
 printf 'PUBLIC_CERTIFICATE_SERVICE_TOKEN=%s\n' "$(openssl rand -hex 32)" \
   > /private/path/key-service.env)
caution secret encrypt PUBLIC_CERTIFICATE_SERVICE_TOKEN \
  --env-file /private/path/key-service.env
```

Set the identical token as `PUBLIC_CERTIFICATE_SERVICE_TOKEN` in Platform's private
API configuration. Package only `.caution/secrets/PUBLIC_CERTIFICATE_SERVICE_TOKEN.asc`;
never commit the plaintext file. Recreate/redeploy the API container to load changed
environment values; restarting the same Docker container does not update them.
The token permits certificate issuance; it is not the root key or permission to
release shares.

## Trust inputs

| Policy | Verifies | When to change |
| --- | --- | --- |
| Platform API `KEYMAKER_PCR_POLICY_PATH` | Bundles generated through or uploaded to Platform | Add verified Keymaker measurements before using a new image; retain approved sets needed by existing bundles. |
| Platform API `CAUTION_CA_CERT_PATH` | Holder certificates issued by the key service | Provision the exported public CA when establishing a new service root; an image-only upgrade retains it. |
| `.caution/keymaker-pcr-policy.json` | The bundle for the key service root key | Only when its root trust requirements change; retain the root's generation measurements. |
| `.caution/release-keymaker-pcr-policy.json` | Application bundles presented for share release | Add independently verified application Keymaker measurements; retain approved sets needed by existing bundles. |
| Client recryptor PCR policy | The running key service | Refresh after verifying a changed service image or embedded configuration. |

For a new service, if the same verified Keymaker image generates both the root
bundle and application bundles, initialize the release policy from the root's
generation policy:

```sh
cp .caution/keymaker-pcr-policy.json .caution/release-keymaker-pcr-policy.json
```

If application bundles use other Keymaker images, include their independently
verified measurement sets instead. For an existing service, preserve approved
sets still needed by existing application bundles rather than overwrite them.

The two Keymaker policies are packaged separately. Replacing the bootstrap
policy with an application policy can prevent the service from starting.
A missing application measurement set causes release-begin verification to fail.

`.caution/release-config.json` contains the registered Platform RP ID/origin and
paths to the packaged release policy and CA:

```json
{
  "rp_id": "dashboard.example.com",
  "origin": "https://dashboard.example.com",
  "keymaker_policy_path": "/etc/caution/release-keymaker-pcr-policy.json",
  "ca_cert_path": "/etc/caution/caution-ca.asc"
}
```

There is no Keymaker URL in this configuration. Release verifies the signed
Keymaker evidence embedded in each bundle without contacting Keymaker.

## Check and deploy

Use `examples/certificate-service/Containerfile` in the deployment's `caution.hcl`,
with `/start-certificate-service` and the `PUBLIC_CERTIFICATE_SERVICE_TOKEN` vault
input, as shown in the example. Configure HTTPS for the service endpoint.
From the deployment checkout, check packaging:

```sh
python3 examples/certificate-service/check-inputs.py
```

**Current checker limitation:** it requires a threshold of at least two, although
the CLI/runtime support 1-of-N. For an intentional 1-of-N root, it stops before
checking the remaining inputs. Review the example's [required-input list](../examples/certificate-service/README.md#prepare-the-existing-deployment-checkout)
manually and still verify the root proof below. Do not regenerate a valid root
merely to satisfy this checker.

Inspect the root bundle to verify its proof and review the bundle identity,
generation time, threshold and holder certificates. Packaging checks do not
verify cryptographic proofs:

```sh
caution secret inspect --bundle .caution/quorum-bundle.json \
  --keymaker-pcr-policy .caution/keymaker-pcr-policy.json
```

If application bundles already exist, also verify each generation-policy set you
need to support against a corresponding bundle. For fresh bootstrap without an
application bundle, defer this check until one has been generated:

```sh
caution secret inspect --bundle /path/to/application/.caution/quorum-bundle.json \
  --keymaker-pcr-policy .caution/release-keymaker-pcr-policy.json
```

Commit the public/encrypted image inputs before deploying; the builder receives
committed files, not working-tree edits:

```sh
git add caution.hcl \
  .caution/quorum-bundle.json .caution/keymaker-pcr-policy.json \
  .caution/caution-ca.asc .caution/release-config.json \
  .caution/release-keymaker-pcr-policy.json \
  .caution/secrets/PUBLIC_CERTIFICATE_SERVICE_TOKEN.asc
git diff --cached --stat
git commit -S -m "Configure key-service bootstrap inputs"
```

Include any intended Containerfile/start-script changes as well. Keep private keys
and plaintext token files outside Git. `.caution/deployment.json` identifies the
app for local CLI commands; committing it is not required to deploy.

Git remotes are shared between worktrees. Inspect `git remote -v` and confirm the
target URL contains the key-service app ID from its local deployment file. If
`caution init` just created the correct `caution` remote, name it once with
`git remote rename caution caution-key-service`. Use that name when deploying the
current branch:

```sh
git push caution-key-service HEAD:main
```

Startup waits for the configured root quorum before starting the HTTP service.
While deployment waits for health, use another terminal in the same checkout.
Once the new enclave is reachable, verify it and repeat share submission for
each required external-PGP root holder:

```sh
caution verify
caution secret send-shard --bundle .caution/quorum-bundle.json
curl --fail https://key-service.example.com/health
```

Use independently verified non-debug PCR0/1/2 for Platform's
`PUBLIC_CERTIFICATE_PCR_POLICY_PATH`, gateway `RECRYPTOR_PCR_POLICY_PATH`, and
CLI `--recryptor-pcr-policy` files. Reload affected services to pick up changed
configuration. Do not reuse the previous image's measurements after an image change.
An enclave restart requires the same root quorum again; no new Keymaker is needed.

Share submission remains supported after an enclave has been waiting for days.
External-PGP signatures allow up to 60 seconds of future clock skew; a larger
skew is rejected with a clock-specific message. Check the signer and enclave
clocks if this occurs. Receiver fixes require rebuilding, redeploying and verifying
the application enclave, then resubmitting the existing quorum shares. Preserve
the bundle and encrypted secrets.
Each rejected submission logs one bounded cause category, without raw parser input,
payloads or signatures, regardless of the number of holders.

See [acceptance checks](service-hardening.md#manual-acceptance) for issuance and
application share release. Updating CLI or Platform dependencies alone does not
redeploy this service.
