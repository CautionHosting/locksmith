# Imported V0 recovery

V0 has no Keymaker generation proof. Importing it does not establish historical
origin: a holder can recover its encrypted metadata, but cannot retroactively
create a Nitro attestation binding its generation. A signed Platform upload
records explicit acceptance of the artifact, not verification of encrypted metadata.

Use the updated Platform CLI for the one-time import:

```sh
caution secret import-legacy --bundle /path/original-v0.json \
  --keyring /path/holder.private.asc
# Or omit --keyring and select an attached OpenPGP card:
# caution secret import-legacy --bundle /path/original-v0.json --holder FULL_FINGERPRINT
caution secret inspect --bundle .caution/quorum-bundle.json
```

The default output is `.caution/quorum-bundle.json`; `--output PATH` selects a
new path. Existing files are never overwritten. `--upload` optionally uses the
existing signed Platform endpoint with `allow_legacy: true`. Keep the original.
Import decrypts metadata only, never reconstructs the secret, and preserves the
quorum public key, encrypted shares and existing encrypted application secrets.
The ImportedV0 identity is SHA-256 of canonical CBOR containing its domain tag
and complete contents; it has no invented UUID, generation time or proof.

Only the known unversioned PGP shape is accepted. Checksum mismatches, malformed
packets, inconsistent threshold/recipient counts, duplicate or ineligible holders,
and V1-shaped inputs fail closed. Restore inconsistent source data from its
original backup; there is no repair override or raw-V0 runtime fallback.

Package the imported file at `/etc/caution/bundle.json` in the reviewed application
image, retaining `/etc/caution/secrets/*.asc`. Rebuild with the updated Locksmith
runtime, redeploy, and independently verify the new application PCRs with
`caution verify` before holders release. Including ImportedV0 in that measured
image is runtime approval. No Keymaker PCR policy is loaded for ImportedV0;
V1 still requires its generation policy and a valid proof. Legacy acceptance
never bypasses V1 failure.

```sh
# Only for new or changed secret values; existing ciphertext needs no re-encryption.
caution secret encrypt SECRET --env-file /private/app.env --allow-legacy
# Each holder releases independently after verifying the rebuilt destination:
caution secret send-shard --holder FULL_FINGERPRINT --allow-legacy
# Private-key alternative: add --keyring /path/holder.private.asc
```

CLI encryption/release require `--allow-legacy` every time, also for downloaded
artifacts. Inspection reports “Legacy V0 — no Keymaker generation proof”. Sender
paths recheck the imported threshold and full ordered certificates against the
encrypted metadata. Fresh destination attestation, signed submissions, distinct
holders/coordinates, threshold enforcement and recovered-public-key matching are
unchanged. External PGP signing keys must remain usable under current policy;
expired historical encryption subkeys may still decrypt their stored shares.

The standalone `locksmith` developer CLI remains V1-only; use `caution` for legacy
operations. WebAuthn, custody, Bootproof, V1 generation and V1 proof interfaces
are unchanged. Earlier V1 formats are not migrated.

## Release gate

Run the frozen fixture tests and Platform's disposable `test_quorum_mock.sh`.
Before claiming production support, separately record a real Nitro recovery of
an existing legacy bundle (including decrypting existing ciphertext), and an
OpenPGP-card import/release smoke test: correct card selection, hidden PIN input,
cancellation, metadata-only import, and successful threshold recovery. Local,
software-key and synthetic tests do not satisfy those gates.
