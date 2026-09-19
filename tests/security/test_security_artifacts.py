import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from validate_authority_schemas import authority_digest  # noqa: E402
from validate_security_artifacts import ArtifactError, digest, validate_authority, validate_capability, validate_fixture  # noqa: E402


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

    def test_duplicate_fixture_keys_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"fixture_version":"1.0.0","fixture_version":"1.0.0"}', encoding="utf-8")
            with self.assertRaisesRegex(ArtifactError, "duplicate JSON key"):
                validate_fixture(path)

    def test_foreign_authority_digest_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = json.loads((ROOT / "tests/fixtures/security/v1/research.json").read_text(encoding="utf-8"))
            fixture["cases"][0]["capability"]["authority_digest"] = "f" * 64
            path = Path(directory) / "research.json"
            path.write_text(json.dumps(fixture), encoding="utf-8")
            with self.assertRaisesRegex(ArtifactError, "authority_digest"):
                validate_fixture(path)

    def test_authority_digest_serialization_matches_for_unicode(self):
        authority = json.loads((ROOT / "tests/fixtures/security/v1/research.json").read_text(encoding="utf-8"))["cases"][0]["authority"]
        authority["principal"]["id"] = "research-wörker-01"
        self.assertEqual(digest(authority), authority_digest(authority))

    def test_fixture_expected_label_is_semantically_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = json.loads((ROOT / "tests/fixtures/security/v1/research.json").read_text(encoding="utf-8"))
            fixture["cases"][1]["expected"] = "authorized"
            path = Path(directory) / "research.json"
            path.write_text(json.dumps(fixture), encoding="utf-8")
            with self.assertRaisesRegex(ArtifactError, "authorized case"):
                validate_fixture(path)


if __name__ == "__main__": unittest.main()
