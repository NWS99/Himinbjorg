import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from validate_security_artifacts import ArtifactError, validate_authority, validate_capability, validate_fixture  # noqa: E402


class SecurityArtifactTests(unittest.TestCase):
    def test_all_stable_fixtures_validate(self):
        for path in sorted((ROOT / "tests/fixtures/security/v1").glob("*.json")):
            with self.subTest(path=path.name): validate_fixture(path)

    def test_unknown_authority_field_fails_closed(self):
        value = json.loads((ROOT / "tests/fixtures/security/v1/research.json").read_text())["cases"][0]["authority"]
        value["future_field"] = True
        with self.assertRaisesRegex(ArtifactError, "unknown fields"): validate_authority(value)

    def test_unknown_version_fails_closed(self):
        value = json.loads((ROOT / "tests/fixtures/security/v1/research.json").read_text())["cases"][0]["authority"]
        value["schema_version"] = "9.0.0"
        with self.assertRaisesRegex(ArtifactError, "unknown version"): validate_authority(value)

    def test_generic_shell_cannot_be_accepted(self):
        value = json.loads((ROOT / "tests/fixtures/security/v1/host.json").read_text())["cases"][1]["capability"]
        with self.assertRaisesRegex(ArtifactError, "forbidden"): validate_capability(value)

    def test_delegation_can_only_narrow(self):
        value = json.loads((ROOT / "tests/fixtures/security/v1/research.json").read_text())["cases"][0]["authority"]
        value["security_domain"] = {"schema_version":"1.0.0", "domain":"host", "parent_domain":"research"}
        with self.assertRaisesRegex(ArtifactError, "expands"): validate_authority(value)


if __name__ == "__main__": unittest.main()
