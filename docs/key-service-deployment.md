# Deploy the certificate and share-release service

For an existing service, preserve the root bundle, public CA and encrypted token;
an application Keymaker upgrade does not require a new key service root key.
See the [certificate-service example](../examples/certificate-service/README.md)
for packaged inputs.

## Initial bootstrap

Skip this section when deploying or upgrading an existing root. For a new service,
use a dedicated checkout without an existing root bundle. Collect independent
root holders' public PGP certificates in `root-holders.asc`; keep their private keys
with the holders. The root must be recoverable without this service's passkeys.

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

### Generate the root quorum

```sh
caution secret init root-holders.asc --threshold 2 \
  --keymaker-url https://keymaker.example.com \
  --keymaker-pcr-policy /path/to/keymaker-checkout/.caution/trusted_hashes.json --no-upload
jq -r '.data.public_key' .caution/quorum-bundle.json > .caution/caution-ca.asc
```

Keymaker generates the root entropy inside its enclave and encrypts its shares to
those holders. The CLI verifies the proof and saves the bundle and bootstrap policy
under `.caution/`. Operators receive no plaintext root. The exported public key
identifies the CA derived from that root; retain it with the bundle and policy.

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
never commit the plaintext file. The token permits certificate issuance; it is not
the key service root key or authorization to release shares. Continue below to
configure, deploy, verify and unlock the service with the root holders' quorum.

## Trust inputs

| Policy | Verifies | When to change |
| --- | --- | --- |
| `.caution/keymaker-pcr-policy.json` | The bundle for the key service root key | Only when its root trust requirements change; retain the root's generation measurements. |
| `.caution/release-keymaker-pcr-policy.json` | Application bundles presented for share release | Add independently verified application Keymaker measurements; retain approved sets needed by existing bundles. |
| Client recryptor PCR policy | The running key service | Refresh after verifying a changed service image or embedded configuration. |

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
From the deployment checkout, check packaging and both bundle proofs:

```sh
python3 examples/certificate-service/check-inputs.py
caution secret inspect --bundle .caution/quorum-bundle.json \
  --keymaker-pcr-policy .caution/keymaker-pcr-policy.json
caution secret inspect --bundle /path/to/application/.caution/quorum-bundle.json \
  --keymaker-pcr-policy .caution/release-keymaker-pcr-policy.json
```

Both proof checks must pass; packaging preflight alone does not verify proofs.
Review and commit the deployment inputs, then push to the key-service app's remote:

```sh
git push caution HEAD:main
```

Startup waits for the existing root quorum before starting the HTTP service.
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
See [acceptance checks](service-hardening.md#manual-acceptance) for issuance and
application share release. Updating CLI or Platform dependencies alone does not
redeploy this service.
