import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from validate_threat_model import ThreatModelError, load, validate  # noqa: E402


class ThreatModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifact = load(ROOT / "contracts/security/v1/threat-model.json")
        cls.contract = load(ROOT / "contracts/security/v1/security-contract.json")

    def mutated(self):
        return copy.deepcopy(self.artifact)

    def test_golden_threat_model_is_valid(self):
        validate(self.artifact, self.contract)

    def test_matrix_cannot_drift_from_frozen_contract(self):
        artifact = self.mutated()
        artifact["capability_matrix"][0]["network_access"] = "deny"
        with self.assertRaisesRegex(ThreatModelError, "capability matrix disagrees"):
            validate(artifact, self.contract)

    def test_capability_must_name_enforcement_owner(self):
        artifact = self.mutated()
        artifact["capabilities"][0]["enforcement_owner"] = ""
        with self.assertRaisesRegex(ThreatModelError, "missing enforcement owner"):
            validate(artifact, self.contract)

    def test_unknown_capability_boundary_fails_closed(self):
        artifact = self.mutated()
        artifact["capabilities"][0]["trust_boundary"] = "TB-999"
        with self.assertRaisesRegex(ThreatModelError, "unknown trust boundary"):
            validate(artifact, self.contract)


if __name__ == "__main__":
    unittest.main()
