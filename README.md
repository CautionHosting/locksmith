# Locksmith workspace

## Keymaker v1 validation

Keymaker requires `1 <= threshold <= max <= 254`, with `max` equal to the number
of structured holders. Each holder must supply exactly one public OpenPGP
certificate with supported, live, non-revoked signing, authentication and
storage-encryption keys. Duplicate primary certificates and encryption keys
shared between holders are rejected, including reused encryption material with
different creation timestamps. Expired or revoked certificates are rejected.
Invalid requests return HTTP 400 before
entropy generation; Keymaker's existing one-shot reboot lifecycle is unchanged.

The proof-bound V1 response requires `threshold` and `max`, populated from the
same values passed to shard generation. Callers must compare them with their
original request after verifying the proof. The proof authenticates those
parameters under the measured Keymaker implementation; it is not an independent
proof of correct secret sharing.

This intentionally breaks the previous V1 response contract without changing its
version tag. Updated readers reject bundles missing either field, including old
stored bundles used for recovery. Older readers reject the new fields. Do not
add fields to an existing bundle: that invalidates its proof. Upgrade Keymaker,
shared models, clients and Locksmith runtimes together, rebuild the enclave and
independently establish its new trusted PCR policy. Existing encrypted material
is not migrated by this change; local synthetic tests do not establish Nitro
readiness.

Both OpenPGP and WebAuthn entries are accepted and retained in their original
order. Caution's organization/bundle critical notation names are recognized;
this capability check does not verify the Caution CA or authorize WebAuthn
recovery. Certificate derivation verification and WebAuthn transport remain
separate integration work.

## Explicitly unsafe local testing

Ordinary builds ignore `CAUTION_UNSAFE_KEY_SERVICE_E2E` and
`LOCKSMITHD_UNSAFE_TEST_SECRET_HEX`. The shortcuts require both the affected
crate's non-default `unsafe-e2e` feature and its runtime environment variable:

```sh
cargo build -p keymaker --locked --no-default-features --features unsafe-e2e
cargo build -p public-cert-service --locked --features unsafe-e2e
cargo build -p locksmith --locked --features unsafe-e2e
```

Keymaker and public-cert-service use `CAUTION_UNSAFE_KEY_SERVICE_E2E=1` for fake
proofs; Keymaker also uses constant entropy. Only the exact value `1` enables
these hooks; unset, empty, `0`, and other values leave them disabled.
Locksmithd accepts a hex-encoded test mnemonic secret through
`LOCKSMITHD_UNSAFE_TEST_SECRET_HEX`, bypassing
quorum recovery. Each activated shortcut logs a warning without the secret.
The Keymaker command disables its default `selfnuke` feature for host testing.
Never use these feature builds (including `--all-features`) for production.
No tracked harness in this repository sets these variables; external harnesses
must explicitly enable the corresponding feature when building.

## Validation

```sh
cargo test -p locksmith -p public-cert-service --locked
cargo test -p keymaker --locked --no-default-features
cargo test -p locksmith -p public-cert-service --locked --features locksmith/unsafe-e2e,public-cert-service/unsafe-e2e
cargo test -p keymaker --locked --no-default-features --features unsafe-e2e
cargo check --workspace --all-targets --locked
```

On macOS/Homebrew, native builds may need:

```sh
export PKG_CONFIG_PATH=/opt/homebrew/opt/nettle@3/lib/pkgconfig:/opt/homebrew/opt/gmp/lib/pkgconfig:/opt/homebrew/opt/openssl@3/lib/pkgconfig
```

The default workspace check requires Linux for Keymaker's `selfnuke` reboot
code. On macOS, check the workspace with `--exclude keymaker`, then run
`cargo check -p keymaker --all-targets --locked --no-default-features`.

Unsafe-hook tests use subprocesses to isolate environment variables. Local
mixed-generation tests use fake proofs and do not establish Nitro readiness.
See [Locksmith usage and verification limits](crates/locksmith/README.md).
