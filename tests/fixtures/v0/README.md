# Historical V0 fixture — public test keys

Every private key here is deliberately public test data. Never use these keys or
this quorum in production. The 2-of-2 quorum entropy is `[7; 32]`.
The fixture removes the derivation dependency’s one-day lifetime from the quorum
certificate and all its subkeys, preserving their key material. A regression test
checks non-expiring validity and encryption eligibility at 2100-01-01. Production
certificate generation is unchanged.

`bundle.json` uses the historical `OpenPGP.shard_and_encrypt` semantics: one
unsigned encrypted metadata message (version byte, threshold byte, root signing
certificate, ordered recipients), followed by each signed, encrypted share. Its
keyring checksum is SHA-256 over the exact armored string. `pre-import.asc` was
encrypted to the historically derived quorum public certificate before import.
`imported.json` preserves that original payload and adds only the format tag,
threshold and ordered public holder certificates. Platform carries a byte-identical
copy as `tests/fixtures/imported-v0.json`.

Explicit regeneration (changes random holder keys; update all frozen copies):

```sh
cargo test --locked -p locksmith --lib legacy::tests::generate_fixture -- --ignored --exact
```

Tests decrypt metadata with either holder, reject inconsistent imports, and recover
the same quorum key to decrypt the pre-import ciphertext. The Platform disposable
harness additionally checks signed upload/download and new CLI ciphertext recovery.
The root `bundle-2-of-4.json` is an inconsistent checksum rejection fixture; it is
not repaired. These fixtures are local cryptographic evidence, not Nitro or card evidence.
