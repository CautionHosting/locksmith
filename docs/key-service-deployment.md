# Deploy the certificate and share-release service

Use an existing deployment checkout with an external-PGP bundle for the key service root key
and a provisioned issuance token. See the [certificate-service example](../examples/certificate-service/README.md)
for required inputs. Preserve the root bundle, public CA and encrypted token;
an application Keymaker upgrade does not require a new key service root key.

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
