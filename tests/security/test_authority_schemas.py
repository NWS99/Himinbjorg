import hashlib
import copy
import json
import shutil
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
    authority_digest,
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

    def full_case(self, filename="research.json", index=0):
        fixture = json.loads((ROOT / "tests/fixtures/security/v1" / filename).read_text(encoding="utf-8"))
        case = fixture["cases"][index]
        return {
            "source_contract_digest": self.digest,
            "authority": copy.deepcopy(case["authority"]),
            "capability": copy.deepcopy(case["capability"]),
            "agent_domain": fixture["agent_domain"],
        }, copy.deepcopy(case["trusted_state"])

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

    def test_type_accepts_string_or_string_array(self):
        value = self.schema()
        value["properties"]["nullable_note"] = {"type": ["string", "null"]}
        validate_schema_artifact(value, "authority.schema.json", self.digest)

    def test_schema_rejects_invalid_type_array(self):
        value = self.schema()
        value["properties"]["nullable_note"] = {"type": ["string", "string"]}
        with self.assertRaisesRegex(ContractError, "unknown type"):
            validate_schema_artifact(value, "authority.schema.json", self.digest)

    def test_incomplete_legacy_request_denies(self):
        self.assertEqual(evaluate_authority(self.request(), digest=self.digest), "deny")

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

    def test_incomplete_generic_host_shell_request_denies(self):
        request = self.request(capability="generic_host_shell", resource_type="process", security_domain="research")
        self.assertEqual(evaluate_authority(request, digest=self.digest), "deny")

    def test_full_path_requires_bound_authority_digest(self):
        request, state = self.full_case()
        self.assertEqual(evaluate_authority(request, digest=self.digest, replay_state=set(), freshness_context=state), "allow")
        request["capability"]["authority_digest"] = "b" * 64
        self.assertEqual(evaluate_authority(request, digest=self.digest, replay_state=set(), freshness_context=state), "deny")

    def test_full_path_requires_replay_and_freshness_context(self):
        request, state = self.full_case()
        self.assertEqual(evaluate_authority(request, digest=self.digest, freshness_context=state), "deny")
        self.assertEqual(evaluate_authority(request, digest=self.digest, replay_state=set()), "deny")

    def test_full_path_replay_state_is_single_use(self):
        request, state = self.full_case()
        replay_state = set()
        self.assertEqual(evaluate_authority(request, digest=self.digest, replay_state=replay_state, freshness_context=state), "allow")
        self.assertEqual(evaluate_authority(request, digest=self.digest, replay_state=replay_state, freshness_context=state), "deny")

    def test_consistent_old_worker_state_does_not_override_trusted_state(self):
        request, state = self.full_case()
        request["authority"]["canonical_resource"]["generation"] = "old"
        request["capability"]["resource"]["generation"] = "old"
        request["capability"]["authority_digest"] = authority_digest(request["authority"])
        self.assertEqual(evaluate_authority(request, digest=self.digest, replay_state=set(), freshness_context=state), "deny")

    def test_delegation_rejects_broader_release_child(self):
        parent, state = self.full_case("coding.json", 0)
        child = copy.deepcopy(parent)
        child["authority"]["security_domain"]["domain"] = "release"
        child["authority"]["action"] = "release"
        child["capability"]["capability"] = "sandbox_shell"
        child["authority"]["constraints"]["idempotency_key"] = "coding-child-001"
        child["authority"]["constraints"]["fencing_token"] = "coding-child-fence-001"
        child["capability"]["authority_digest"] = authority_digest(child["authority"])
        self.assertEqual(evaluate_authority(child, digest=self.digest, delegated=parent, replay_state=set(), freshness_context=state), "deny")

    def test_same_scope_delegation_is_allowed_as_intersection(self):
        parent, state = self.full_case("research.json", 0)
        child = copy.deepcopy(parent)
        child["authority"]["constraints"]["idempotency_key"] = "research-child-001"
        child["authority"]["constraints"]["fencing_token"] = "research-child-fence-001"
        child["authority"]["parent_authority_digest"] = authority_digest(parent["authority"])
        child["capability"]["authority_digest"] = authority_digest(child["authority"])
        self.assertEqual(evaluate_authority(child, digest=self.digest, delegated=parent, replay_state=set(), freshness_context=state), "allow")

    def test_action_capability_domain_product_relation_fails_closed(self):
        request, state = self.full_case("host.json", 0)
        request["authority"]["action"] = "release"
        request["capability"]["authority_digest"] = authority_digest(request["authority"])
        self.assertEqual(evaluate_authority(request, digest=self.digest, replay_state=set(), freshness_context=state), "deny")

    def test_unreviewed_action_capability_relations_fail_closed(self):
        for action in ("delete", "external_send", "publish", "model_request", "attest"):
            with self.subTest(action=action):
                request, state = self.full_case("research.json", 0)
                request["authority"]["action"] = action
                request["capability"]["authority_digest"] = authority_digest(request["authority"])
                self.assertEqual(evaluate_authority(request, digest=self.digest, replay_state=set(), freshness_context=state), "deny")

    def test_delegation_cannot_rewrite_sticky_provenance(self):
        parent, state = self.full_case("research.json", 0)
        child = copy.deepcopy(parent)
        child["authority"]["constraints"]["idempotency_key"] = "research-child-provenance"
        child["authority"]["constraints"]["fencing_token"] = "research-child-provenance-fence"
        child["authority"]["parent_authority_digest"] = authority_digest(parent["authority"])
        child["authority"]["provenance_requirements"]["exposure"] = "X2"
        child["capability"]["authority_digest"] = authority_digest(child["authority"])
        self.assertEqual(evaluate_authority(child, digest=self.digest, delegated=parent, replay_state=set(), freshness_context=state), "deny")

    def test_missing_release_matrix_row_fails_closed(self):
        request, state = self.full_case("coding.json", 0)
        request["agent_domain"] = "release"
        request["authority"]["security_domain"]["domain"] = "release"
        request["authority"]["action"] = "release"
        request["capability"]["domain"] = "release"
        request["capability"]["capability"] = "sandbox_shell"
        request["capability"]["authority_digest"] = authority_digest(request["authority"])
        self.assertEqual(evaluate_authority(request, digest=self.digest, replay_state=set(), freshness_context=state), "deny")

    def test_bundle_requires_all_schemas_and_fixtures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            schemas = root / "schemas"
            fixtures = root / "fixtures"
            schemas.mkdir()
            fixtures.mkdir()
            for name in ("authority.schema.json", "capability.schema.json", "canonical-resource.schema.json", "constraints.schema.json", "principal.schema.json", "security-domain.schema.json", "provenance.schema.json"):
                shutil.copy(ROOT / "contracts/security/v1" / name, schemas / name)
            shutil.copy(ROOT / "tests/fixtures/security/v1/research.json", fixtures / "research.json")
            validate_bundle(schemas, fixtures, self.contract)

    def test_fixture_expected_policy_state_is_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            schemas, fixtures = root / "schemas", root / "fixtures"
            schemas.mkdir()
            fixtures.mkdir()
            for name in ("authority.schema.json", "capability.schema.json", "canonical-resource.schema.json", "constraints.schema.json", "principal.schema.json", "security-domain.schema.json", "provenance.schema.json"):
                shutil.copy(ROOT / "contracts/security/v1" / name, schemas / name)
            fixture = json.loads((ROOT / "tests/fixtures/security/v1/research.json").read_text(encoding="utf-8"))
            fixture["cases"][1]["expected"] = "authorized"
            (fixtures / "research.json").write_text(json.dumps(fixture), encoding="utf-8")
            with self.assertRaisesRegex(ContractError, "expected allow"):
                validate_bundle(schemas, fixtures, self.contract)


if __name__ == "__main__":
    unittest.main()
