# Locksmith & Keymaker

A confidential-computing key-quorum system that runs inside AWS Nitro Enclaves on the
[Caution](https://caution.co) platform. It splits a secret across a quorum of
OpenPGP-smartcard holders using Shamir's Secret Sharing, then reconstitutes it inside an
attested enclave to decrypt application secrets at boot.

- **keymaker** — *creates* a quorum: given a keyring of OpenPGP certs plus a threshold/max, it
  generates entropy, Shamir-shards it, derives an OpenPGP cert, and returns a quorum bundle.
- **locksmith** — *recovers* a quorum at runtime, as the enclave's boot process: it collects
  shards from quorum members, reconstitutes the secret, and decrypts the app's secrets.

## Docs

- Caution platform docs — https://docs.caution.co
- Key services / Locksmith concept — https://docs.caution.co/concepts/key-services/
- `caution.hcl` reference — https://docs.caution.co/reference/caution-hcl/
- Source — https://codeberg.org/caution/locksmith

## Deploying keymaker

This repo ships **two** keymaker deployment modes. Caution deploys whichever branch you push,
reading the root `caution.hcl` on that branch.

### One-shot keymaker (the default — what the docs describe)

`git push caution main` deploys the **single-use, self-nuking** keymaker (`/keymaker`). It
serves `/generate_quorum` once, then reboots the host so the entropy never persists. This is
the mode you use to mint your own quorum bundle:

```sh
caution init
git push caution main
# then point KEYMAKER_URL at the deployed app and run `caution secret new ...`
```

The root `caution.hcl` on `main` is this mode.

### Hosted keymaker (run by Caution)

Caution runs an **always-on** keymaker (`/keymaker-hosted`, no self-nuke) at
**https://keymaker.caution.co**, deployed from the **`deploy/hosted`** branch. That branch's
root `caution.hcl` carries the hosted configuration (the `keymaker-hosted` binary and the
`keymaker.caution.co` domain). It's a convenience endpoint so you don't have to stand up your
own one-shot keymaker first.
