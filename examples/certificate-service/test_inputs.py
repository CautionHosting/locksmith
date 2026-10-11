"""Packaging regressions for the shared generation policy and encrypted token."""
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

class Inputs(unittest.TestCase):
    def test_token_replaces_marker_without_replacing_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = root / "examples/certificate-service/check-inputs.py"
            script.parent.mkdir(parents=True)
            shutil.copyfile(Path(__file__).with_name("check-inputs.py"), script)
            caution = root / ".caution"
            (caution / "secrets").mkdir(parents=True)
            (caution / "quorum-bundle.json").write_text(json.dumps({"necroproof": [1], "data": {
                "version": "V1", "keyring": [{"OpenPGP": {}}, {"OpenPGP": {}}],
                "threshold": 2, "max": 2, "public_key": "-----BEGIN PGP PUBLIC KEY BLOCK-----"}}))
            policy_path = caution / "keymaker-pcr-policy.json"
            policy = {"sets": [
                {"pcrs": {str(i): "01" * 48 for i in range(3)}, "expires_at_unix_seconds": 100},
                {"pcrs": {str(i): "02" * 48 for i in range(3)}},
            ]}
            policy_path.write_text(json.dumps(policy))
            (caution / "caution-ca.asc").write_text("-----BEGIN PGP PUBLIC KEY BLOCK-----")
            config = {"origin": "https://example.com", "rp_id": "example.com",
                "keymaker_policy_path": "/etc/caution/keymaker-pcr-policy.json", "ca_cert_path": "/etc/caution/caution-ca.asc"}
            config_path = caution / "release-config.json"
            config_path.write_text(json.dumps(config))
            marker = caution / "secrets/CERTIFICATE_BOOTSTRAP.asc"
            marker.write_text("-----BEGIN PGP MESSAGE-----")
            def check():
                return subprocess.run(["python3", str(script)], capture_output=True, text=True)
            self.assertIn("encrypted issuance token is missing", check().stderr)
            token = caution / "secrets/PUBLIC_CERTIFICATE_SERVICE_TOKEN.asc"
            token.write_text("-----BEGIN PGP MESSAGE-----")
            marker.unlink()
            self.assertEqual(check().returncode, 0)
            self.assertFalse((caution / "release-keymaker-pcr-policy.json").exists())

            # A supported 1-of-N root must still check all remaining inputs.
            bundle_path = caution / "quorum-bundle.json"
            bundle = json.loads(bundle_path.read_text())
            bundle["data"]["threshold"] = 1
            bundle_path.write_text(json.dumps(bundle))
            self.assertEqual(check().returncode, 0)
            for threshold in [0, 3]:
                bundle["data"]["threshold"] = threshold
                bundle_path.write_text(json.dumps(bundle))
                self.assertIn("root threshold", check().stderr)
            bundle["data"]["threshold"] = 1
            bundle_path.write_text(json.dumps(bundle))
            token.write_text("plaintext is not a packaged secret")
            self.assertIn("encrypted issuance token is missing", check().stderr)
            token.write_text("-----BEGIN PGP MESSAGE-----")

            # A stale deployment config cannot point at an unpackaged second policy.
            config["keymaker_policy_path"] = "/etc/caution/release-keymaker-pcr-policy.json"
            config_path.write_text(json.dumps(config))
            self.assertIn("shared Keymaker policy", check().stderr)
            config["keymaker_policy_path"] = "/etc/caution/keymaker-pcr-policy.json"
            config_path.write_text(json.dumps(config))
            policy_path.write_text(json.dumps({"sets": []}))
            self.assertIn("Keymaker PCR policy is empty", check().stderr)
            policy_path.write_text(json.dumps(policy))
            self.assertEqual(check().returncode, 0)

if __name__ == "__main__":
    unittest.main()
