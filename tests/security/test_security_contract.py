import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from validate_security_contract import ContractError, validate_contract  # noqa: E402


class SecurityContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = json.loads((ROOT / "contracts/security/v1/security-contract.json").read_text(encoding="utf-8"))

    def mutated(self):
        return copy.deepcopy(self.contract)

    def test_golden_contract_is_valid(self):
        validate_contract(self.contract)

    def test_capability_cannot_become_authority(self):
        contract = self.mutated()
        contract["authority_semantics"]["capability_is_authority"] = True
        with self.assertRaisesRegex(ContractError, "capability_is_authority"):
            validate_contract(contract)

    def test_secret_reference_cannot_become_authority(self):
        contract = self.mutated()
        contract["authority_semantics"]["secret_ref_is_authority"] = True
        with self.assertRaisesRegex(ContractError, "secret_ref_is_authority"):
            validate_contract(contract)

    def test_delegation_cannot_union_rights(self):
        contract = self.mutated()
        contract["authority_semantics"]["delegation_operator"] = "union"
        with self.assertRaisesRegex(ContractError, "delegation must be intersection"):
            validate_contract(contract)

    def test_ambiguity_cannot_default_allow(self):
        contract = self.mutated()
        contract["authority_semantics"]["unknown_or_ambiguous"] = "allow"
        with self.assertRaisesRegex(ContractError, "ambiguity must deny"):
            validate_contract(contract)

    def test_taint_cannot_be_cleared_by_reviewer(self):
        contract = self.mutated()
        contract["provenance_semantics"]["review_may_clear_taint"] = True
        with self.assertRaisesRegex(ContractError, "review must not clear taint"):
            validate_contract(contract)

    def test_generic_host_shell_cannot_default_allow(self):
        contract = self.mutated()
        next(item for item in contract["capability_classes"] if item["id"] == "generic_host_shell")["default_policy"] = "allow"
        with self.assertRaisesRegex(ContractError, "generic host shell"):
            validate_contract(contract)

    def test_invariant_without_owner_fails(self):
        contract = self.mutated()
        contract["hard_invariants"][0]["owner_issues"] = []
        with self.assertRaisesRegex(ContractError, "missing owner_issues"):
            validate_contract(contract)

    def test_attacker_path_without_owner_fails(self):
        contract = self.mutated()
        contract["attacker_paths"][0]["owner_issues"] = ["not-an-issue"]
        with self.assertRaisesRegex(ContractError, "invalid owner issue"):
            validate_contract(contract)

    def test_required_action_cannot_be_deleted(self):
        contract = self.mutated()
        contract["action_classes"] = [item for item in contract["action_classes"] if item["id"] != "delete"]
        with self.assertRaisesRegex(ContractError, "action vocabulary"):
            validate_contract(contract)

    def test_required_invariant_cannot_be_deleted(self):
        contract = self.mutated()
        contract["hard_invariants"] = contract["hard_invariants"][:-1]
        with self.assertRaisesRegex(ContractError, "hard invariant catalog"):
            validate_contract(contract)

    def test_unknown_owner_issue_fails(self):
        contract = self.mutated()
        contract["hard_invariants"][0]["owner_issues"] = ["N-999999"]
        with self.assertRaisesRegex(ContractError, "unknown owner issue"):
            validate_contract(contract)

    def test_release_semantics_cannot_be_weakened(self):
        contract = self.mutated()
        next(item for item in contract["action_classes"] if item["id"] == "release")["effect"] = "benign_read"
        with self.assertRaisesRegex(ContractError, "release action semantics"):
            validate_contract(contract)

    def test_capability_matrix_requires_every_cell(self):
        contract = self.mutated()
        del contract["capability_matrix"][0]["host_read"]
        with self.assertRaisesRegex(ContractError, "incomplete capability coverage"):
            validate_contract(contract)


if __name__ == "__main__":
    unittest.main()
