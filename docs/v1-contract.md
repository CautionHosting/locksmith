# Current V1 contract

This is the first-test contract for certificate issuance, quorum creation and
recovery. It records existing encodings and the accepted certificate-binding
design. The local critical-notation verification patch is not yet published or
deployed. No schema, hashing or wire-format change is introduced.

## Envelopes and identities

Both responses use `{ "data": { "version": "V1", ... }, "necroproof": [...] }`.
The proof authenticates the complete typed `data`; it is not part of its own hash.
UUIDs are canonical 16-byte arrays, not strings. Current V1 is the only supported
wire/bundle generation; legacy migration is separate.

| Artifact | Required data |
| --- | --- |
| Certificate request | `version`, `organization_id`, nonzero `certificate_count` |
| Certificate response data | `version`, `organization_id`, service-generated `bundle_id`, ordered armored public `certificates` |
| Keymaker request | `version`, `bundle_id`, `label`, `threshold`, `max`, ordered `keyring` |
| Keymaker response data | Request fields plus `shardfile`, `public_key` |

Platform authorizes organization membership. Certificate callers cannot select
bundle IDs, paths or indices. Issuance chooses a fresh UUID and consecutive
certificate indices. Keymaker receives explicit quorum parameters; `max` equals
the holder count and the threshold must satisfy its current validation rules.
An external-PGP holder carries a certificate; a WebAuthn holder carries its
certificate and credential snapshot. Multiple credentials remain one holder/share.
Unknown fields and unsupported version/shape substitutions fail typed decoding.

## Certificate profile and accepted deviation

The account path is `m/pgp'/kmkr'/<org words>'/<bundle words>'/<index>'`.
Each UUID contributes four big-endian 32-bit words with the high bit cleared,
then hardened. This conversion is lossy: authorization must bind the full UUIDs,
not merely the path. Existing path vectors freeze the exact conversion.
The configured CA derives at `m/pgp'/0'`.

Key order is primary certification, signing, transport/storage encryption, then
authentication. Each holder certificate has the canonical self-signed UID
`Caution public certificate index=N`; `N` is an unsigned decimal `u8` without
leading zeros or a sign. The trusted CA certifies this UID and includes exactly
one **hashed, critical** notation for each of:

- `organization-id@caution.co`: full organization UUID, emitted as lowercase hex;
- `bundle-id@caution.co`: full bundle UUID, emitted as lowercase hex.

**Accepted deviation:** the identifiers are bound by the CA certification and
the index by its signed UID. They are not three critical self-notations on the
holder certificate. This replaces that original ticket wording explicitly.

API and recryptor require valid signatures, the configured independent CA anchor,
and authenticated context. Missing, duplicate, unhashed, noncritical or mismatched
required context fails closed. Conflicting certified contexts remain rejected by
the recryptor. No private packets are accepted. The API checks issuance ordering;
the recryptor obtains the immutable certificate index from the certified UID,
independently of its position in a later mixed quorum. Reordering holders never
changes the derivation index or grants an additional share.

Current issuance already sets both critical flags. This verifier change preserves
its existing artifacts; certificates previously accepted without those flags
will now fail. Do not strip flags, rewrite certificates or silently regenerate a
bundle as an upgrade workaround.

## Exact bytes, hashes and proofs

| Artifact | SHA-256 input | Nitro nonce expectation |
| --- | --- | --- |
| Certificate response | `serde_cbor::to_vec(&PublicCertificateBundle)` | Absent/null |
| Keymaker response | `serde_cbor::to_vec(&serde_cbor::value::to_value(&GenerateQuorumBundle))` | Deterministic nonce below |

For Keymaker, compute the nonce as SHA-256 of the CBOR serialization of
`("keymaker-generate-quorum-necroproof-nonce-v1", bundle_hash.as_slice())`.
Both Nitro documents bind `user_data` to their artifact hash. Preserve these exact
Rust types/encodings: typed-struct CBOR and canonical `Value` map CBOR are distinct.
Armored certificate text, ordered arrays and all required fields are hash inputs.
Keymaker label map insertion order does not affect its canonical hash.

Verification checks the AWS chain/signature at the authenticated attestation
timestamp, expected nonce, independently approved PCRs and exact payload hash.
PCR-policy expiry is a generation-time cutoff. This establishes historical
provenance, not current service freshness or permission to release a share.
Certificate/key eligibility uses authenticated generation time where specified by
the existing validators; live holder signatures and release authorization retain
their current-time checks. Configured CA primary keys are durable anchors;
snapshot expiry alone does not remove one, while revocation checks still apply.

Current artifact separation combines strict typed schemas, different required
payloads/hashes, nonce expectations and independently configured PCR trust.
The public-certificate hash has no additional global structure identifier.
A general Caution-wide identifier/hash registry is explicitly deferred. Adding
another artifact type must not assume these V1 checks automatically separate it.

Live release still requires fresh custody/destination evidence, approved PCRs,
WebAuthn RP/origin/challenge and user verification, one-use unexpired authorization,
and a destination-bound encrypted submission. Historical proofs and the issuance
bearer token cannot replace those checks.

## Compatibility fixtures and changes

[`tests/fixtures/v1-contract.json`](../tests/fixtures/v1-contract.json) is copied
byte-for-byte into Platform. Service, model, API and recryptor tests consume it.
It fixes CBOR bytes, hashes, the Keymaker nonce, two public service-issued
certificates, their CA, a verification timestamp and certified identities.
Tests do not regenerate expected values. Existing path, label-order, negative
certificate and proof tests remain in place.

The fixture certificates were generated once by the real service derivation code
using disposable Keyfork seed `[0x56; 32]`. No private certificate or Nitro proof
is included. The quorum credential/shardfile strings are encoding placeholders:
this is not a recoverable application bundle or live-Nitro acceptance evidence.
Exact fixture certificate bytes are frozen examples, not a promise that repeated
issuance at another time reproduces every signature byte.

Any incompatible change to encoding, proof inputs, certificate/profile semantics
or required fields needs an explicit new version and artifact migration decision.
Do not update golden expectations merely to make a changed implementation pass.
Before shipping this patch, publish its Locksmith revision, align Platform's
shared dependencies, mock helper and default runtime pin, then rerun the focused
and synthetic recovery checks. No local-path overrides belong in committed files.

Named custodians, organizational recovery drills, long-term root/rotation
procedures and the general registry are later work. The first test retains real
quorum custody, enclave-only private material and all attestation/authorization
requirements. See [service operations](service-hardening.md) and
[recovery](share-release.md); record exact revisions/PCRs/scenarios separately
before claiming live acceptance.

## Local validation — 21 September 2026

Working-tree patch over Locksmith `2da3be5` and Platform `e38a05b`; not committed,
published or deployed. Tested on macOS with Homebrew `nettle@3` and `openssl@3`:

| Check | Result |
| --- | --- |
| `cargo test --locked --offline -p keymaker-models -p public-cert-service -p locksmith --lib` | Models 6 passed; Locksmith 40 passed, one unrelated PTY-driver test ignored; service 19 passed |
| `CAUTION_UNSAFE_KEY_SERVICE_E2E=1 cargo test --locked --offline -p locksmith -p public-cert-service --lib --features unsafe-e2e release::tests` | Locksmith 12 passed; actual custody HTTP/destination recovery test passed, covering mixed and WebAuthn-only quorums |
| Platform `cargo test --locked --offline -p api org_quorum::certificates` | 7 passed using the local Locksmith patch in an isolated temporary workspace |

The temporary Platform workspace patched only Locksmith/model dependency sources;
the source checkout's manifests, Cargo.lock and runtime pin are unchanged. The
first sandboxed API run passed six tests but macOS system-configuration access
panicked in the existing HTTP-client test; all seven passed outside the sandbox.
The initial Nettle 4 header failure was resolved by using installed Nettle 3.

Both fixture copies have SHA-256
`82e74d053976b47edba6e4f11b143c3184bc422c67b3a16c3599bee924e0403a`.
Python independently checked SHA-256 of both recorded CBOR byte sequences.
All pre-existing test functions were retained. These are local/synthetic results;
no fresh real-Nitro, physical-authenticator, deployment or organizational recovery
drill is claimed. Publishing, coordinated pins and exact-revision live acceptance
remain separate release steps.
