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

## Deployment

Follow [key-service deployment](key-service-deployment.md) for the separate bootstrap and
release policies, proof checks, deployment, root unlock and client trust updates.
The issuance token must already be provisioned in the Platform API and encrypted
for the key service root key; never commit the plaintext token.

## Manual acceptance

Set the key-service URL. For the authenticated issuance check, load the existing
private token env file without echoing it:

```sh
KEY_SERVICE_URL=https://key-service.example.com
. /path/to/private/key-service-token.env
curl -sS -i --max-time 65 "$KEY_SERVICE_URL/health"
curl -sS -i --max-time 65 "$KEY_SERVICE_URL/v1/public-certificates" \
  -H 'Content-Type: application/json' --data '{}'
```

Expect health 200 after recovery and issuance 401 without credentials (also with
an incorrect token). Missing server token configuration returns 503. Test one
certificate with the correct token; passing headers through stdin keeps the token
out of curl's command-line arguments:

```sh
printf 'Authorization: Bearer %s\n' "$PUBLIC_CERTIFICATE_SERVICE_TOKEN" | \
  curl --silent --show-error --fail-with-body --max-time 65 \
    "$KEY_SERVICE_URL/v1/public-certificates" --header @- \
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
  --recryptor-url https://key-service.example.com \
  --recryptor-pcr-policy .caution/recryptor-pcr-policy.json
```

Select a passkey holder. Reaching the release-approval QR exercises begin/prepare
and client-side evidence verification. Approve to exercise complete and submit a
share; supply the remaining quorum shares and check the expected application
secret. Repeat after restarting the key-service enclave and recovering its existing
root. Record revisions, bundle IDs, PCRs and results. Do not load-test the public
service to validate limits; use the automated saturation tests.

Unset `PUBLIC_CERTIFICATE_SERVICE_TOKEN` in the test shell after testing. Token rotation requires
updating both deployments; encrypted input changes require fresh measurements.

## Automated validation

See `hardening-validation.md` for the tested source revisions and results. Local
and synthetic tests are not live Nitro acceptance.
