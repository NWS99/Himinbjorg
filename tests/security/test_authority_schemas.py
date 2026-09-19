import hashlib
import json
import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from validate_authority_schemas import (  # noqa: E402
    CAPABILITIES,
    ContractError,
    RESOURCE_TYPES,
    evaluate_authority,
    load_json,
    stable_json,
    validate_bundle,
    validate_schema_artifact,
)


class AuthoritySchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = ROOT / "contracts/security/v1/security-contract.json"
        cls.digest = hashlib.sha256(cls.contract.read_bytes()).hexdigest()

    def schema(self):
        return {
            "schema_version": "1.0.0",
            "source_contract_digest": self.digest,
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "capability": {"type": "string", "enum": sorted(CAPABILITIES)},
                "resource_type": {"type": "string", "enum": sorted(RESOURCE_TYPES)},
                "policy_state": {"type": "string", "enum": ["allow", "ask", "deny"]},
            },
            "required": ["capability", "resource_type", "policy_state"],
        }

    def request(self, **changes):
        value = {"source_contract_digest": self.digest, "capability": "host_read", "resource_type": "workspace", "security_domain": "coding", "policy_state": "allow"}
        value.update(changes)
        return value

    def test_golden_schema_is_valid(self):
        validate_schema_artifact(self.schema(), "authority.schema.json", self.digest)

    def test_source_contract_digest_is_bound(self):
        value = self.schema()
        value["source_contract_digest"] = "0" * 64
        with self.assertRaisesRegex(ContractError, "digest mismatch"):
            validate_schema_artifact(value, "authority.schema.json", self.digest)

    def test_unknown_version_fails_closed(self):
        value = self.schema()
        value["schema_version"] = "9.9.9"
        with self.assertRaisesRegex(ContractError, "unknown schema_version"):
            validate_schema_artifact(value, "authority.schema.json", self.digest)

    def test_unknown_field_fails_closed(self):
        value = self.schema()
        value["surprise"] = True
        with self.assertRaisesRegex(ContractError, "unknown schema fields"):
            validate_schema_artifact(value, "authority.schema.json", self.digest)

    def test_duplicate_json_keys_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"id":"one","id":"two"}', encoding="utf-8")
            with self.assertRaisesRegex(ContractError, "duplicate JSON key"):
                load_json(path)

    def test_stable_serialization_is_key_order_independent(self):
        self.assertEqual(stable_json({"b": 2, "a": 1}), '{"a":1,"b":2}')
        self.assertEqual(stable_json({"a": 1, "b": 2}), stable_json({"b": 2, "a": 1}))

    def test_unknown_capability_and_resource_fail_closed(self):
        value = self.schema()
        value["properties"]["capability"]["enum"].append("root_shell")
        with self.assertRaisesRegex(ContractError, "capability vocabulary"):
            validate_schema_artifact(value, "authority.schema.json", self.digest)
        value = self.schema()
        value["properties"]["resource_type"]["enum"].append("everything")
        with self.assertRaisesRegex(ContractError, "resource vocabulary"):
            validate_schema_artifact(value, "authority.schema.json", self.digest)

    def test_authorized_case_allows(self):
        self.assertEqual(evaluate_authority(self.request(), digest=self.digest), "allow")

    def test_unauthorized_case_denies(self):
        self.assertEqual(evaluate_authority(self.request(policy_state="deny"), digest=self.digest), "deny")

    def test_stale_replayed_and_ambiguous_deny(self):
        for case in ("stale", "replayed", "ambiguous"):
            self.assertEqual(evaluate_authority(self.request(case=case), digest=self.digest), "deny")

    def test_unknown_digest_denies(self):
        self.assertEqual(evaluate_authority(self.request(source_contract_digest="bad"), digest=self.digest), "deny")

    def test_communication_never_grants_authority(self):
        with self.assertRaisesRegex(ContractError, "communication"):
            evaluate_authority(self.request(communication_grants_authority=True), digest=self.digest)

    def test_delegation_is_intersection(self):
        parent = self.request(policy_state="allow")
        self.assertEqual(evaluate_authority(self.request(policy_state="deny"), digest=self.digest, delegated=parent), "deny")
        self.assertEqual(evaluate_authority(self.request(policy_state="allow"), digest=self.digest, delegated=self.request(policy_state="deny")), "deny")

    def test_bundle_requires_all_schemas_and_fixtures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            schemas = root / "schemas"
            fixtures = root / "fixtures"
            schemas.mkdir()
            fixtures.mkdir()
            for name in ("authority.schema.json", "capability.schema.json", "canonical-resource.schema.json", "constraint.schema.json", "security-domain.schema.json", "provenance.schema.json"):
                (schemas / name).write_text(json.dumps(self.schema()), encoding="utf-8")
            fixture = {"id": "authorized", "expected_decision": "allow", "request": self.request()}
            (fixtures / "authorized.json").write_text(json.dumps(fixture), encoding="utf-8")
            validate_bundle(schemas, fixtures, self.contract)

    def test_fixture_expected_policy_state_is_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            schemas, fixtures = root / "schemas", root / "fixtures"
            schemas.mkdir(); fixtures.mkdir()
            for name in ("authority.schema.json", "capability.schema.json", "canonical-resource.schema.json", "constraint.schema.json", "security-domain.schema.json", "provenance.schema.json"):
                (schemas / name).write_text(json.dumps(self.schema()), encoding="utf-8")
            (fixtures / "bad.json").write_text(json.dumps({"id": "bad", "expected_decision": "allow", "request": self.request(policy_state="deny")}), encoding="utf-8")
            with self.assertRaisesRegex(ContractError, "expected allow"):
                validate_bundle(schemas, fixtures, self.contract)


if __name__ == "__main__":
    unittest.main()
