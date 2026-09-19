import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from validate_threat_model import ThreatModelError, load, validate, validate_source_lock  # noqa: E402


class ThreatModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifact = load(ROOT / "contracts/security/v1/threat-model.json")
        cls.contract = load(ROOT / "contracts/security/v1/security-contract.json")

    def mutated(self):
        return copy.deepcopy(self.artifact)

    def test_golden_threat_model_is_valid(self):
        validate(self.artifact, self.contract)

    def test_golden_source_contract_matches_review_lock(self):
        validate_source_lock(
            ROOT / "contracts/security/v1/security-contract.json",
            ROOT / "contracts/security/v1/security-contract.sha256",
        )

    def test_source_contract_cannot_be_redirected(self):
        artifact = self.mutated()
        artifact["source_contract"] = "other.json"
        with self.assertRaisesRegex(ThreatModelError, "source_contract"):
            validate(artifact, self.contract)

    def test_source_contract_digest_binding_cannot_change(self):
        artifact = self.mutated()
        artifact["source_contract_sha256"] = "0" * 64
        with self.assertRaisesRegex(ThreatModelError, "digest binding"):
            validate(artifact, self.contract)

    def test_coordinated_contract_and_projection_drift_fails(self):
        mutations = (
            lambda artifact, contract: (
                artifact["security_goals"].__setitem__(0, "attacker_defined_goal"),
                contract["security_goals"].__setitem__(0, "attacker_defined_goal"),
            ),
            lambda artifact, contract: (
                artifact["capability_matrix"][0].__setitem__("network_access", "deny"),
                contract["capability_matrix"][0].__setitem__("network_access", "deny"),
            ),
            lambda artifact, contract: (
                artifact["attacker_paths"].__setitem__(0, "renamed_or_weakened_attack"),
                contract["attacker_paths"][0].__setitem__("name", "renamed_or_weakened_attack"),
            ),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                artifact = self.mutated()
                contract = copy.deepcopy(self.contract)
                mutate(artifact, contract)
                with self.assertRaisesRegex(ThreatModelError, "semantic digest"):
                    validate(artifact, contract)

    def test_security_goals_cannot_be_removed(self):
        artifact = self.mutated()
        artifact["security_goals"] = artifact["security_goals"][:-1]
        with self.assertRaisesRegex(ThreatModelError, "security_goals"):
            validate(artifact, self.contract)

    def test_non_goals_cannot_be_removed(self):
        artifact = self.mutated()
        artifact["non_goals"] = artifact["non_goals"][:-1]
        with self.assertRaisesRegex(ThreatModelError, "non_goals"):
            validate(artifact, self.contract)

    def test_principal_catalog_cannot_drift(self):
        artifact = self.mutated()
        artifact["principal_classes"][0]["security_authority"] = "unbounded"
        with self.assertRaisesRegex(ThreatModelError, "principal_classes"):
            validate(artifact, self.contract)

    def test_model_policy_cannot_become_hard_enforcement(self):
        artifact = self.mutated()
        artifact["enforcement_boundary"]["model_safety_policy"] = "authoritative"
        with self.assertRaisesRegex(ThreatModelError, "hard enforcement"):
            validate(artifact, self.contract)

    def test_unresolved_choices_must_remain_explicit(self):
        artifact = self.mutated()
        del artifact["unresolved_architecture_choices"]
        with self.assertRaisesRegex(ThreatModelError, "unresolved_architecture_choices"):
            validate(artifact, self.contract)

    def test_trust_boundary_catalog_cannot_drift(self):
        artifact = self.mutated()
        artifact["trust_boundaries"][0]["id"] = "invented_boundary"
        with self.assertRaisesRegex(ThreatModelError, "catalog disagrees"):
            validate(artifact, self.contract)

    def test_trust_boundary_endpoints_cannot_drift(self):
        artifact = self.mutated()
        artifact["trust_boundaries"][0]["to"] = ["untrusted_sink"]
        with self.assertRaisesRegex(ThreatModelError, "destination endpoint changed"):
            validate(artifact, self.contract)

    def test_credential_admin_and_activation_remain_separate(self):
        artifact = self.mutated()
        artifact["trust_boundaries"] = [
            item for item in artifact["trust_boundaries"] if item["id"] != "human_to_credential_admin"
        ]
        with self.assertRaisesRegex(ThreatModelError, "catalog disagrees"):
            validate(artifact, self.contract)

    def test_matrix_cannot_drift_from_frozen_contract(self):
        artifact = self.mutated()
        artifact["capability_matrix"][0]["network_access"] = "deny"
        with self.assertRaisesRegex(ThreatModelError, "capability matrix disagrees"):
            validate(artifact, self.contract)

    def test_capability_enforcement_owner_must_match_contract(self):
        artifact = self.mutated()
        artifact["capabilities"][0]["enforcement_owner"] = "llm"
        with self.assertRaisesRegex(ThreatModelError, "enforcement owner disagrees"):
            validate(artifact, self.contract)

    def test_capability_boundary_must_be_canonical(self):
        artifact = self.mutated()
        artifact["capabilities"][0]["trust_boundary"] = "control_plane_to_release"
        with self.assertRaisesRegex(ThreatModelError, "canonical trust boundary changed"):
            validate(artifact, self.contract)

    def test_duplicate_capability_fails(self):
        artifact = self.mutated()
        artifact["capabilities"].append(copy.deepcopy(artifact["capabilities"][0]))
        with self.assertRaisesRegex(ThreatModelError, "ids must be unique"):
            validate(artifact, self.contract)

    def test_attacker_path_cannot_be_removed(self):
        artifact = self.mutated()
        artifact["attacker_paths"] = artifact["attacker_paths"][:-1]
        with self.assertRaisesRegex(ThreatModelError, "attacker path catalog"):
            validate(artifact, self.contract)

    def test_duplicate_attacker_path_fails(self):
        artifact = self.mutated()
        artifact["attacker_paths"].append(artifact["attacker_paths"][0])
        with self.assertRaisesRegex(ThreatModelError, "attacker path catalog"):
            validate(artifact, self.contract)

    def test_required_abuse_case_mapping_cannot_drift(self):
        artifact = self.mutated()
        artifact["scope_coverage"]["confused_deputy_and_capability_composition"] = []
        with self.assertRaisesRegex(ThreatModelError, "abuse-case coverage"):
            validate(artifact, self.contract)


if __name__ == "__main__":
    unittest.main()
