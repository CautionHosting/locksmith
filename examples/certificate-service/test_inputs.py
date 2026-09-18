"""Regression for the measured deployment's required encrypted token input."""
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
            for name in ["keymaker-pcr-policy.json", "release-keymaker-pcr-policy.json"]:
                (caution / name).write_text(json.dumps({"sets": [{"pcrs": {str(i): "01" * 48 for i in range(3)}}]}))
            (caution / "caution-ca.asc").write_text("-----BEGIN PGP PUBLIC KEY BLOCK-----")
            (caution / "release-config.json").write_text(json.dumps({"origin": "https://example.com", "rp_id": "example.com",
                "keymaker_policy_path": "/etc/caution/release-keymaker-pcr-policy.json", "ca_cert_path": "/etc/caution/caution-ca.asc"}))
            marker = caution / "secrets/CERTIFICATE_BOOTSTRAP.asc"
            marker.write_text("-----BEGIN PGP MESSAGE-----")
            def check():
                return subprocess.run(["python3", str(script)], capture_output=True, text=True)
            self.assertIn("encrypted issuance token is missing", check().stderr)
            token = caution / "secrets/PUBLIC_CERTIFICATE_SERVICE_TOKEN.asc"
            token.write_text("-----BEGIN PGP MESSAGE-----")
            marker.unlink()
            self.assertEqual(check().returncode, 0)
            token.write_text("plaintext is not a packaged secret")
            self.assertNotEqual(check().returncode, 0)

if __name__ == "__main__":
    unittest.main()
