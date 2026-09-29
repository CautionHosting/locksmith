#!/usr/bin/env python3
"""Check packaging inputs only; the production loader verifies the proof at startup."""
import json
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[2]
try:
    envelope = json.loads((root / ".caution/quorum-bundle.json").read_text())
    data = envelope["data"]
    holders = data["keyring"]
    if data["version"] != "V1" or not envelope["necroproof"]:
        raise ValueError("a proofed V1 root bundle is required")
    if not holders or any(set(holder) != {"OpenPGP"} for holder in holders):
        raise ValueError("the key service root key must use only external OpenPGP holders")
    if not 1 <= data["threshold"] <= data["max"] == len(holders):
        raise ValueError("root threshold must be between one and the holder count")
    if not data["public_key"].startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----"):
        raise ValueError("root public certificate is missing")
    policy = json.loads((root / ".caution/keymaker-pcr-policy.json").read_text())
    if not policy["sets"]:
        raise ValueError("Keymaker PCR policy is empty")
    for entry in policy["sets"]:
        for index in ("0", "1", "2"):
            value = bytes.fromhex(entry["pcrs"][index])
            if len(value) != 48 or value in (bytes(48), bytes([0xab]) * 48):
                raise ValueError("use independently verified, non-debug Keymaker PCR0/1/2")
    release = json.loads((root / ".caution/release-config.json").read_text())
    if not release["origin"].startswith("https://") or not release["rp_id"]:
        raise ValueError("configure the registered HTTPS Platform origin and RP ID")
    if release["keymaker_policy_path"] != "/etc/caution/keymaker-pcr-policy.json" or release["ca_cert_path"] != "/etc/caution/caution-ca.asc":
        raise ValueError("release configuration must use the shared Keymaker policy and packaged CA")
    if not (root / ".caution/caution-ca.asc").read_text().startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----"):
        raise ValueError("public Caution CA certificate is missing")
    token = root / ".caution/secrets/PUBLIC_CERTIFICATE_SERVICE_TOKEN.asc"
    if not token.is_file() or not token.read_text().startswith("-----BEGIN PGP MESSAGE-----"):
        raise ValueError("encrypted issuance token is missing")
except (OSError, ValueError, KeyError, TypeError) as error:
    sys.exit(f"Bootstrap input check failed: {error}")
print("Packaging inputs present; cryptographic verification still required by CLI/runtime.")
