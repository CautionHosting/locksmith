# Certificate-service and recryptor hardening

Certificate issuance requires a backend-only 32-byte hex bearer token; Platform
sends it only to the certificate endpoint, over HTTPS and without redirects.
Loopback HTTP is allowed only in explicit unsafe E2E builds with
`CAUTION_UNSAFE_KEY_SERVICE_E2E=1`. Neither logs nor source-controlled configuration
should contain the token. HTTPS termination is a trusted intermediary: the Nitro
response proof does not hide the outbound token from a terminating proxy. This is
issuance admission control, not holder authorization.

Readiness caches positive and negative results for two seconds with one refresh.
Startup root verification remains uncached. Release routes remain public, admit
four blocking workers, retain permits until actual completion and use a 60-second
request budget, including Keyfork I/O. Sessions expire after three minutes, with
64 globally and eight per authenticated organization/bundle. Preparing sessions
keep their reservations. Busy requests return 503. These limits bound work and
reduce monopolization; they do not guarantee availability during sustained floods.
Keep session IDs private: invalid preparation deliberately consumes an attempt.

## Migration (operator commands, not performed by the implementation)

Use the existing custody deployment checkout and its existing root quorum/CA.
Do not generate a new custody root or replace the CA. No Keymaker change is needed
for this migration or recovery of existing application bundles.

Generate the token into a private temporary env file, then encrypt only that key:

```sh
umask 077
TOKEN_ENV=$(mktemp /tmp/custody-token.XXXXXX)
printf 'PUBLIC_CERTIFICATE_SERVICE_TOKEN=%s\n' "$(openssl rand -hex 32)" > "$TOKEN_ENV"
caution secret encrypt PUBLIC_CERTIFICATE_SERVICE_TOKEN \
  --env-file "$TOKEN_ENV" --bundle .caution/quorum-bundle.json
```

Set the **same** value in the Platform API backend `.env`. On the API host, with
the private token file available, set `PLATFORM_ENV` to the actual backend env
file (the local development default is `~/.config/caution/.env`):

```sh
PLATFORM_ENV="$HOME/.config/caution/.env"
python3 - "$TOKEN_ENV" "$PLATFORM_ENV" <<'PYENV'
from pathlib import Path
import sys
source, target = map(Path, sys.argv[1:])
entry = source.read_text().strip()
assert entry.startswith("PUBLIC_CERTIFICATE_SERVICE_TOKEN=")
lines = target.read_text().splitlines()
lines = [line for line in lines if line.split("=", 1)[0].strip() != "PUBLIC_CERTIFICATE_SERVICE_TOKEN"]
target.write_text("\n".join(lines + [entry]) + "\n")
PYENV
```

Keep the private env file until provisioning is done; never commit it. Recreate
the API process/container using its existing deployment procedure so it reads the
new environment. Deploying the updated Platform first is compatible with the old
certificate endpoint.

Update the custody checkout to the reviewed Locksmith revision. Use:

```hcl
command = "/start-certificate-service"
env = {
  PUBLIC_CERTIFICATE_SERVICE_TOKEN = env::vault("PUBLIC_CERTIFICATE_SERVICE_TOKEN")
}
```

The updated start script, Containerfile and preflight require the encrypted token,
not `CERTIFICATE_BOOTSTRAP`. Preserve the existing root bundle, root Keymaker policy,
release configuration and CA. The old marker is no longer packaged; do not remove
other secrets. Review and commit the deployment inputs before deployment:

```sh
python3 examples/certificate-service/check-inputs.py
git push caution HEAD:main
```

Recover the custody enclave with the existing external-PGP holders, repeating
this command and selecting each required holder:

```sh
caution secret send-shard --bundle .caution/quorum-bundle.json
caution verify
```

Use the newly independently verified non-debug PCR0/1/2 to update Platform's
`PUBLIC_CERTIFICATE_PCR_POLICY_PATH` file and each recovery client's recryptor
policy. Updating Platform's environment or trust files may require recreating the
API container to refresh mounts. The existing CA and bundle files stay unchanged.

## Manual acceptance

Set the existing custody URL, and load the generated env file without echoing it:

```sh
CERT_URL=https://insecure-recryptor.kobl.one
. "$TOKEN_ENV"
curl -sS -i --max-time 65 "$CERT_URL/health"
curl -sS -i --max-time 65 "$CERT_URL/v1/public-certificates" \
  -H 'Content-Type: application/json' --data '{}'
```

Expect health 200 after recovery and issuance 401 without credentials (also with
an incorrect token). Missing server token configuration returns 503. Test one
certificate with the correct token; passing headers through stdin keeps the token
out of curl's command-line arguments:

```sh
printf 'Authorization: Bearer %s\n' "$PUBLIC_CERTIFICATE_SERVICE_TOKEN" | \
  curl --silent --show-error --fail-with-body --max-time 65 \
    "$CERT_URL/v1/public-certificates" --header @- \
    -H 'Content-Type: application/json' \
    --data '{"version":"V1","organization_id":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],"certificate_count":1}'
```

Expect one certificate plus a proof; this curl check does not verify the proof.
Use normal Platform WebAuthn/mixed creation when testing the full issuance path
(with a fresh Keymaker as usual for new quorum generation).

In an existing application's checkout, with the application awaiting quorum:

```sh
caution --verbose --qr secret send-shard \
  --bundle .caution/quorum-bundle.json \
  --recryptor-url https://insecure-recryptor.kobl.one \
  --recryptor-pcr-policy .caution/recryptor-pcr-policy.json
```

Select a passkey holder. Reaching the release-approval QR exercises begin/prepare
and client-side evidence verification. Approve to exercise complete and submit a
share; supply the remaining quorum shares and check the expected application
secret. Repeat after restarting the custody enclave and recovering its existing
root. Record revisions, bundle IDs, PCRs and results. Do not load-test the public
service to validate limits; use the automated saturation tests.

Delete the private temporary env file after provisioning and testing, and unset
`PUBLIC_CERTIFICATE_SERVICE_TOKEN` in the test shell. Token rotation requires
updating both deployments; encrypted input changes require fresh measurements.

## Automated validation

See `hardening-validation.md` for the tested source revisions and results. Local
and synthetic tests are not live Nitro acceptance.
