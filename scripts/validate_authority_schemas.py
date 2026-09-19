#!/usr/bin/env python3
"""Offline, deterministic validation for the N-110 schema bundle.

This validator intentionally implements only the small JSON-Schema vocabulary
used by the contract. It does not import ``jsonschema``: validation must work
in the bootstrap repository and must fail closed when the vocabulary changes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "contracts/security/v1"
FIXTURES_DIR = ROOT / "tests/fixtures/security/v1"
CONTRACT_PATH = ROOT / "contracts/security/v1/security-contract.json"

SCHEMA_NAMES = (
    "authority.schema.json",
    "capability.schema.json",
    "canonical-resource.schema.json",
    "constraints.schema.json",
    "principal.schema.json",
    "provenance.schema.json",
    "security-domain.schema.json",
)
SCHEMA_VERSION = "1.0.0"
POLICY_STATES = {"allow", "ask", "deny"}
CAPABILITIES = {
    "sandbox_shell", "host_exec", "host_read", "user_write", "network_access",
    "credential_activate", "privileged_action", "generic_host_shell",
}
RESOURCE_TYPES = {
    "artifact", "filesystem_path", "workspace", "process", "network_destination",
    "external_identity", "secret_ref", "consumer_profile", "model_provider",
    "policy", "candidate", "release_target",
}
SECURITY_DOMAINS = {"research", "coding", "host", "credential_consumer", "release"}
PROVENANCE_CLASSES = {"user_authorized", "tool_verified", "agent_derived", "untrusted_external"}
PRINCIPAL_CLASSES = {
    "human", "control_plane_service", "cognition_worker", "execution_adapter",
    "gate_runner", "credential_broker", "release_controller",
}
ACTIONS = {
    "read", "workspace_write", "sandbox_execute", "host_execute", "network_request",
    "external_send", "publish", "delete", "credential_activate", "model_request",
    "attest", "release",
}
EXPOSURES = {f"X{i}" for i in range(5)}
DECISION_CASES = {"authorized", "unauthorized", "stale", "replayed", "ambiguous"}
CONTRACT_DIGEST = "c1cb5e367886e6b93b3843d6f7806178a9a583e197e6a6d30231997b15854830"

class ContractError(ValueError):
    """Raised for every invalid or ambiguous contract input."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractError(f"cannot load {path}: {error}") from error


def stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def source_contract_digest(contract_path: Path) -> str:
    try:
        return hashlib.sha256(contract_path.read_bytes()).hexdigest()
    except OSError as error:
        raise ContractError(f"cannot read source contract: {error}") from error


def authority_digest(authority: dict[str, Any]) -> str:
    """Return the stable digest that a capability must bind to."""
    return hashlib.sha256(stable_json(authority).encode("utf-8")).hexdigest()


def _load_contract_policy(contract_path: Path, digest: str) -> dict[str, Any]:
    """Load the reviewed matrix and delegation relation, failing closed on drift."""
    require(source_contract_digest(contract_path) == digest == CONTRACT_DIGEST, "source contract digest is not the reviewed N-110 digest")
    contract = load_json(contract_path)
    require(isinstance(contract, dict) and contract.get("contract_version") == SCHEMA_VERSION and contract.get("status") == "frozen", "security contract is not frozen")
    capability_defaults = {
        item.get("id"): item.get("default_policy")
        for item in contract.get("capability_classes", [])
        if isinstance(item, dict)
    }
    require(set(capability_defaults) == CAPABILITIES, "security contract capability vocabulary drift")
    matrix: dict[str, dict[str, str]] = {}
    for row in contract.get("capability_matrix", []):
        require(isinstance(row, dict) and isinstance(row.get("domain"), str) and row["domain"] not in matrix, "security contract capability matrix has duplicate or invalid domain")
        require(set(row) == {"domain"} | CAPABILITIES, f"security contract capability matrix/{row.get('domain')}: incomplete capability coverage")
        require(all(row[capability] in POLICY_STATES for capability in CAPABILITIES), f"security contract capability matrix/{row.get('domain')}: invalid decision")
        matrix[row["domain"]] = {capability: row[capability] for capability in CAPABILITIES}
    require(matrix, "security contract capability matrix is missing")
    require(all(default in POLICY_STATES for default in capability_defaults.values()), "security contract capability defaults are invalid")
    transitions = set()
    delegation = contract.get("security_domain_delegation")
    require(isinstance(delegation, dict), "security contract delegation policy is missing")
    for item in delegation.get("allowed_transitions", []):
        require(isinstance(item, dict) and isinstance(item.get("parent"), str) and isinstance(item.get("child"), str), "security contract delegation transition is invalid")
        transitions.add((item["parent"], item["child"]))
    require(transitions, "security contract delegation transitions are missing")
    return {"capability_defaults": capability_defaults, "matrix": matrix, "transitions": transitions}


def _check_enum(name: str, value: Any, allowed: set[str]) -> None:
    if value is not None:
        require(isinstance(value, str) and value in allowed, f"unknown {name}: {value!r}")


def _check_enum_vocabulary(location: str, key: str, child: dict[str, Any]) -> None:
    vocabularies = {
        "capability": CAPABILITIES,
        "resource_type": RESOURCE_TYPES,
        "decision": POLICY_STATES,
        "domain": SECURITY_DOMAINS,
        "minimum_class": PROVENANCE_CLASSES,
        "class": PRINCIPAL_CLASSES,
        "action": ACTIONS,
        "exposure": EXPOSURES,
    }
    allowed = vocabularies.get(key)
    if allowed is not None and "enum" in child:
        require(isinstance(child["enum"], list) and all(isinstance(item, str) for item in child["enum"]), f"{location}: {key} vocabulary must be a string list")
        label = "resource" if key == "resource_type" else key
        require(set(child["enum"]) == allowed, f"{location}: {label} vocabulary drift")


def _check_schema_keywords(node: Any, location: str) -> None:
    require(isinstance(node, dict), f"{location}: schema node must be an object")
    allowed = {
        "$schema", "$id", "$comment", "title", "description", "type", "properties", "required",
        "additionalProperties", "items", "enum", "const", "pattern", "format", "default", "examples",
        "minLength", "maxLength", "minItems", "maxItems", "uniqueItems", "minimum", "maximum",
        "allOf", "anyOf", "oneOf", "not", "$defs", "$ref", "source_contract_digest", "schema_version",
        "vocabulary",
    }
    require(set(node).issubset(allowed), f"{location}: unknown schema fields")
    if "type" in node:
        types = node["type"]
        if isinstance(types, str):
            types = [types]
        require(
            isinstance(types, list) and types and
            all(isinstance(item, str) and item in {"object", "array", "string", "boolean", "integer", "number", "null"} for item in types) and
            len(types) == len(set(types)),
            f"{location}: unknown type",
        )
    if "additionalProperties" in node:
        require(node["additionalProperties"] is False or isinstance(node["additionalProperties"], dict), f"{location}: additionalProperties must be false or a schema")
    if "properties" in node:
        require(isinstance(node["properties"], dict), f"{location}: properties must be an object")
        for key, child in node["properties"].items():
            require(isinstance(key, str) and key, f"{location}: invalid property name")
            _check_schema_keywords(child, f"{location}.properties.{key}")
            _check_enum_vocabulary(f"{location}.properties.{key}", key, child)
    for key in ("items", "additionalProperties"):
        if isinstance(node.get(key), dict):
            _check_schema_keywords(node[key], f"{location}.{key}")
    if isinstance(node.get("not"), dict):
        _check_schema_keywords(node["not"], f"{location}.not")
    for key in ("allOf", "anyOf", "oneOf"):
        if key in node:
            require(isinstance(node[key], list) and node[key], f"{location}: {key} must be non-empty")
            for index, child in enumerate(node[key]):
                _check_schema_keywords(child, f"{location}.{key}[{index}]")
    if "$defs" in node:
        require(isinstance(node["$defs"], dict), f"{location}: $defs must be an object")
        for key, child in node["$defs"].items():
            _check_schema_keywords(child, f"{location}.$defs.{key}")


def validate_schema_artifact(value: dict[str, Any], name: str, digest: str) -> None:
    require(value.get("schema_version") == SCHEMA_VERSION, f"{name}: unknown schema_version")
    require(value.get("source_contract_digest") == digest, f"{name}: source-contract digest mismatch")
    require(value.get("type") == "object", f"{name}: root type must be object")
    require(value.get("additionalProperties") is False, f"{name}: root must be closed")
    require(isinstance(value.get("properties"), dict), f"{name}: properties must be present")
    require(isinstance(value.get("required"), list), f"{name}: required must be present")
    require(set(value["required"]).issubset(value["properties"]), f"{name}: required field is undefined")
    _check_schema_keywords(value, name)


def _validate_instance_fields(value: Any, name: str, required: set[str], allowed: set[str]) -> dict[str, Any]:
    require(isinstance(value, dict), f"{name}: object required")
    unknown = set(value) - allowed
    require(not unknown, f"{name}: unknown fields {sorted(unknown)}")
    require(required <= set(value), f"{name}: missing fields {sorted(required - set(value))}")
    return value


def _validate_digest(value: Any, name: str) -> None:
    require(isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value), f"{name}: invalid digest")


def _validate_resource(value: Any, name: str) -> None:
    resource = _validate_instance_fields(value, name, {"schema_version", "resource_type", "identity", "identity_digest", "generation"}, {"schema_version", "resource_type", "identity", "identity_digest", "generation"})
    require(resource["schema_version"] == SCHEMA_VERSION, f"{name}: unknown schema_version")
    _check_enum("resource type", resource.get("resource_type"), RESOURCE_TYPES)
    require(isinstance(resource.get("identity"), str) and resource["identity"], f"{name}: invalid identity")
    _validate_digest(resource.get("identity_digest"), f"{name}.identity_digest")
    require(isinstance(resource.get("generation"), str) and resource["generation"], f"{name}: invalid generation")


def _validate_authority_artifact(value: Any) -> dict[str, Any]:
    authority = _validate_instance_fields(
        value, "authority",
        {"schema_version", "decision", "principal", "action", "canonical_resource", "constraints", "security_domain", "provenance_requirements", "policy_version"},
        {"schema_version", "decision", "principal", "action", "canonical_resource", "constraints", "security_domain", "provenance_requirements", "policy_version", "parent_authority_digest"},
    )
    require(authority["schema_version"] == SCHEMA_VERSION and authority["policy_version"] == SCHEMA_VERSION, "authority: unknown version")
    _check_enum("decision", authority.get("decision"), POLICY_STATES)
    _check_enum("action", authority.get("action"), ACTIONS)
    principal = _validate_instance_fields(authority["principal"], "principal", {"id", "class"}, {"id", "class"})
    require(isinstance(principal["id"], str) and principal["id"], "principal: invalid id")
    _check_enum("principal class", principal.get("class"), PRINCIPAL_CLASSES)
    _validate_resource(authority["canonical_resource"], "authority.canonical_resource")
    constraints = authority["constraints"]
    require(isinstance(constraints, dict), "authority.constraints: object required")
    required_constraints = {"arguments", "working_directory", "environment_allowlist", "network_egress", "time_limit_seconds", "use_limit", "idempotency_key", "fencing_token"}
    require(required_constraints <= set(constraints), "authority.constraints: missing fields")
    allowed_constraints = {"arguments", "executable_digest", "working_directory", "environment_allowlist", "mounts", "network_egress", "secret_handles", "time_limit_seconds", "use_limit", "budget", "idempotency_key", "fencing_token", "pre_state_digest"}
    require(not (set(constraints) - allowed_constraints), "authority.constraints: unknown fields")
    require(isinstance(constraints["arguments"], list) and all(isinstance(item, str) for item in constraints["arguments"]), "authority.constraints: invalid arguments")
    require(isinstance(constraints["working_directory"], str) and constraints["working_directory"], "authority.constraints: invalid working_directory")
    for key in ("environment_allowlist", "network_egress"):
        require(isinstance(constraints[key], list) and all(isinstance(item, str) for item in constraints[key]), f"authority.constraints: invalid {key}")
    for key in ("mounts", "secret_handles"):
        if key in constraints:
            require(isinstance(constraints[key], list) and all(isinstance(item, str) for item in constraints[key]) and len(constraints[key]) == len(set(constraints[key])), f"authority.constraints: invalid {key}")
    for key in ("time_limit_seconds", "use_limit", "budget"):
        if key in constraints:
            minimum = 0 if key == "budget" else 1
            require(isinstance(constraints[key], int) and not isinstance(constraints[key], bool) and constraints[key] >= minimum, f"authority.constraints: invalid {key}")
    for key in ("idempotency_key", "fencing_token"):
        require(isinstance(constraints[key], str) and constraints[key], f"authority.constraints: invalid {key}")
    for key in ("executable_digest", "pre_state_digest"):
        if key in constraints:
            _validate_digest(constraints[key], f"authority.constraints.{key}")
    domain = _validate_instance_fields(authority["security_domain"], "security_domain", {"schema_version", "domain", "parent_domain"}, {"schema_version", "domain", "parent_domain"})
    require(domain["schema_version"] == SCHEMA_VERSION, "security_domain: unknown schema_version")
    _check_enum("security domain", domain.get("domain"), SECURITY_DOMAINS)
    if domain["parent_domain"] is not None:
        _check_enum("parent security domain", domain["parent_domain"], {"research", "coding", "host"})
    provenance = _validate_instance_fields(authority["provenance_requirements"], "provenance_requirements", {"schema_version", "minimum_class", "exposure", "causal_digests", "taint_sticky"}, {"schema_version", "minimum_class", "exposure", "causal_digests", "taint_sticky"})
    require(provenance["schema_version"] == SCHEMA_VERSION and provenance["taint_sticky"] is True, "provenance: unknown or non-sticky value")
    _check_enum("minimum provenance class", provenance.get("minimum_class"), PROVENANCE_CLASSES)
    _check_enum("exposure", provenance.get("exposure"), EXPOSURES)
    require(isinstance(provenance["causal_digests"], list) and all(isinstance(item, str) for item in provenance["causal_digests"]) and len(provenance["causal_digests"]) == len(set(provenance["causal_digests"])), "provenance: invalid causal digests")
    for causal_digest in provenance["causal_digests"]:
        _validate_digest(causal_digest, "provenance.causal_digests")
    if "parent_authority_digest" in authority:
        _validate_digest(authority["parent_authority_digest"], "authority.parent_authority_digest")
    return authority


def _validate_capability_artifact(value: Any) -> dict[str, Any]:
    capability = _validate_instance_fields(value, "capability", {"schema_version", "capability", "domain", "resource", "authority_digest"}, {"schema_version", "capability", "domain", "resource", "authority_digest"})
    require(capability["schema_version"] == SCHEMA_VERSION, "capability: unknown schema_version")
    _check_enum("capability", capability.get("capability"), CAPABILITIES)
    _check_enum("domain", capability.get("domain"), SECURITY_DOMAINS)
    _validate_resource(capability["resource"], "capability.resource")
    _validate_digest(capability.get("authority_digest"), "capability.authority_digest")
    return capability


def _validate_freshness_context(context: Any) -> dict[str, Any]:
    state = _validate_instance_fields(context, "freshness_context", {"trust", "generation", "pre_state_digest"}, {"trust", "generation", "pre_state_digest"})
    require(state["trust"] == "authoritative", "freshness_context: untrusted state")
    require(isinstance(state["generation"], str) and state["generation"] and state["generation"].lower() not in {"unknown", "ambiguous"}, "freshness_context: invalid generation")
    _validate_digest(state["pre_state_digest"], "freshness_context.pre_state_digest")
    return state


def _constraints_are_narrower(parent: dict[str, Any], child: dict[str, Any]) -> bool:
    """Return whether child execution bounds are a subset of parent bounds."""
    if child["arguments"] != parent["arguments"] or child["working_directory"] != parent["working_directory"]:
        return False
    for key in ("environment_allowlist", "network_egress"):
        if not set(child[key]).issubset(parent[key]):
            return False
    for key in ("mounts", "secret_handles"):
        if key in parent:
            if not set(child.get(key, [])).issubset(parent[key]):
                return False
        elif key in child:
            return False
    for key in ("executable_digest", "pre_state_digest"):
        if key in parent and child.get(key) != parent[key]:
            return False
    for key in ("time_limit_seconds", "use_limit"):
        if child[key] > parent[key]:
            return False
    if "budget" in parent and child.get("budget", parent["budget"]) > parent["budget"]:
        return False
    return True


def _action_capability_relation(contract: dict[str, Any], action: str, capability: str, domain: str) -> bool:
    """Use reviewed action effects and capability boundaries as a product relation."""
    actions = {item.get("id"): item.get("effect") for item in contract.get("action_classes", []) if isinstance(item, dict)}
    capabilities = {item.get("id"): item.get("hard_boundary") for item in contract.get("capability_classes", []) if isinstance(item, dict)}
    domains = {item.get("id"): item for item in contract.get("security_domains", []) if isinstance(item, dict)}
    effect = actions.get(action)
    boundary = capabilities.get(capability)
    domain_profile = domains.get(domain)
    if effect is None or boundary is None or domain_profile is None:
        return False
    if effect == "staging_or_production_change":
        return domain_profile.get("execution") == "release_controller"
    if effect == "execute_typed_host_action":
        return boundary in {"typed_host_broker", "separate_privileged_helper"} and domain_profile.get("execution") == "typed_host_broker"
    if effect == "execute_isolated":
        return boundary == "isolation_backend" and domain_profile.get("execution") in {"isolated", "isolation_backend"}
    if effect == "mutate_scoped_workspace":
        return boundary == "pdp_pep" and domain in {"coding", "host"}
    if effect == "send_to_bound_destination":
        return boundary == "destination_egress_policy" and domain_profile.get("network") != "none"
    if effect == "launch_verified_consumer":
        return boundary == "credential_broker" and domain == "credential_consumer"
    if effect == "observe":
        return boundary == "canonical_scoped_reader"
    # The reviewed contract does not define a capability relation for these
    # effects yet. N-110 must not invent one, so they remain fail-closed.
    if effect in {"destructive_mutation", "public_or_registry_write", "identity_bearing_external_write", "brokered_provider_call", "create_exact_verified_claim"}:
        return False
    return False


def _delegation_is_narrower(parent: dict[str, Any], child: dict[str, Any], policy: dict[str, Any]) -> bool:
    parent_authority = parent["authority"]
    child_authority = child["authority"]
    parent_capability = parent["capability"]
    child_capability = child["capability"]
    parent_domain = parent_authority["security_domain"]["domain"]
    child_domain = child_authority["security_domain"]["domain"]
    if (parent_domain, child_domain) not in policy["transitions"]:
        return False
    if child_authority["action"] != parent_authority["action"]:
        return False
    if child_capability["capability"] != parent_capability["capability"]:
        return False
    parent_policy = policy["matrix"].get(parent_domain, {}).get(parent_capability["capability"])
    child_policy = policy["matrix"].get(child_domain, {}).get(child_capability["capability"])
    policy_rank = {"deny": 0, "ask": 1, "allow": 2}
    if parent_policy not in policy_rank or child_policy not in policy_rank or policy_rank[child_policy] > policy_rank[parent_policy]:
        return False
    if stable_json(child_authority["canonical_resource"]) != stable_json(parent_authority["canonical_resource"]):
        return False
    if not _constraints_are_narrower(parent_authority["constraints"], child_authority["constraints"]):
        return False
    # Provenance is sticky. Until the reviewed contract defines a typed
    # declassification/intersection rule, delegation may not rewrite it.
    if stable_json(child_authority["provenance_requirements"]) != stable_json(parent_authority["provenance_requirements"]):
        return False
    parent_digest = authority_digest(parent_authority)
    if child_authority.get("parent_authority_digest") != parent_digest:
        return False
    return True


def _request_from_case(authority: dict[str, Any], capability: dict[str, Any], agent_domain: str, digest: str) -> dict[str, Any]:
    """Derive the evaluator request from authority/capability facts."""
    return {
        "source_contract_digest": digest,
        "authority": authority,
        "capability": capability,
        "agent_domain": agent_domain,
        "capability_name": capability["capability"],
        "resource_type": capability["resource"]["resource_type"],
        "security_domain": capability["domain"],
        "policy_state": authority["decision"],
        "warrant_key": authority["constraints"]["idempotency_key"],
        "fencing_token": authority["constraints"]["fencing_token"],
    }


def evaluate_authority(request: dict[str, Any], *, digest: str, delegated: dict[str, Any] | None = None, replay_state: set[tuple[str, str]] | None = None, freshness_context: dict[str, Any] | None = None, seen_warrants: set[tuple[str, str]] | None = None) -> str:
    """Return allow or deny, failing closed for incomplete authority facts."""
    require(isinstance(request, dict), "request must be an object")
    if request.get("source_contract_digest") != digest:
        return "deny"
    if request.get("communication_grants_authority") is True:
        raise ContractError("communication cannot grant authority")

    if "authority" in request and "capability" in request:
        if replay_state is None:
            replay_state = seen_warrants
        if replay_state is None or not isinstance(replay_state, set) or freshness_context is None:
            return "deny"
        try:
            authority = _validate_authority_artifact(request.get("authority"))
            capability = _validate_capability_artifact(request.get("capability"))
            trusted_state = _validate_freshness_context(freshness_context)
            policy = _load_contract_policy(CONTRACT_PATH, digest)
        except ContractError:
            return "deny"
        domain = authority["security_domain"]["domain"]
        resource = authority["canonical_resource"]
        if request.get("agent_domain") != domain or capability["domain"] != domain:
            return "deny"
        if capability["authority_digest"] != authority_digest(authority):
            return "deny"
        if stable_json(resource) != stable_json(capability["resource"]):
            return "deny"
        matrix = policy["matrix"].get(domain)
        if matrix is None or capability["capability"] not in policy["capability_defaults"] or matrix.get(capability["capability"]) == "deny":
            return "deny"
        contract = load_json(CONTRACT_PATH)
        if not _action_capability_relation(contract, authority["action"], capability["capability"], domain):
            return "deny"
        if authority["provenance_requirements"]["exposure"] == "X4" or resource["generation"] != trusted_state["generation"]:
            return "deny"
        if "pre_state_digest" in authority["constraints"] and authority["constraints"]["pre_state_digest"] != trusted_state["pre_state_digest"]:
            return "deny"
        warrant_keys = {
            ("idempotency", authority["constraints"]["idempotency_key"]),
            ("fencing", authority["constraints"]["fencing_token"]),
        }
        if warrant_keys & replay_state:
            return "deny"
        replay_state.update(warrant_keys)
        if authority["decision"] != "allow":
            return "deny"
        if delegated is not None:
            if not isinstance(delegated, dict) or "authority" not in delegated or "capability" not in delegated:
                return "deny"
            if evaluate_authority(delegated, digest=digest, replay_state=replay_state, freshness_context=freshness_context) != "allow":
                return "deny"
            if not _delegation_is_narrower(delegated, request, policy):
                return "deny"
        return "allow"

    # Incomplete/legacy requests lack digest-bound authority plus trusted
    # freshness and replay state. They are never an enforcement decision.
    return "deny"


def validate_fixtures(fixtures_dir: Path, digest: str) -> None:
    try:
        paths = sorted(fixtures_dir.glob("*.json"))
    except OSError as error:
        raise ContractError(f"cannot inspect fixtures: {error}") from error
    require(paths, "fixtures: no JSON fixtures found")
    seen_ids: set[str] = set()
    for path in paths:
        fixture = load_json(path)
        fixture = _validate_instance_fields(fixture, path.name, {"fixture_version", "agent_domain", "cases"}, {"fixture_version", "agent_domain", "cases"})
        require(fixture["fixture_version"] == SCHEMA_VERSION, f"{path.name}: unknown fixture_version")
        _check_enum("agent domain", fixture.get("agent_domain"), {"research", "coding", "host"})
        require(isinstance(fixture["cases"], list) and fixture["cases"], f"{path.name}: cases must be non-empty")
        seen_warrants: set[tuple[str, str]] = set()
        for index, case in enumerate(fixture["cases"]):
            case = _validate_instance_fields(case, f"{path.name}.cases[{index}]", {"id", "expected", "authority", "capability", "trusted_state"}, {"id", "expected", "authority", "capability", "trusted_state", "note"})
            require(isinstance(case["id"], str) and case["id"] and case["id"] not in seen_ids, f"{path.name}: invalid or duplicate id")
            seen_ids.add(case["id"])
            _check_enum("expected case", case.get("expected"), DECISION_CASES)
            authority = _validate_authority_artifact(case["authority"])
            capability = _validate_capability_artifact(case["capability"])
            request = _request_from_case(authority, capability, fixture["agent_domain"], digest)
            actual = evaluate_authority(request, digest=digest, replay_state=seen_warrants, freshness_context=case["trusted_state"])
            expected_decision = "allow" if case["expected"] == "authorized" else "deny"
            require(actual == expected_decision, f"{path.name}.cases[{index}]: expected {expected_decision}, got {actual}")


def validate_bundle(schemas_dir: Path, fixtures_dir: Path, contract_path: Path) -> None:
    digest = source_contract_digest(contract_path)
    require(digest == CONTRACT_DIGEST, "source contract digest is not the reviewed N-110 digest")
    for name in SCHEMA_NAMES:
        path = schemas_dir / name
        require(path.is_file(), f"missing schema artifact: {path}")
        value = load_json(path)
        require(isinstance(value, dict), f"{name}: root must be an object")
        validate_schema_artifact(value, name, digest)
    validate_fixtures(fixtures_dir, digest)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--schemas", type=Path, default=SCHEMA_DIR)
    parser.add_argument("--fixtures", type=Path, default=FIXTURES_DIR)
    parser.add_argument("--contract", type=Path, default=CONTRACT_PATH)
    args = parser.parse_args()
    try:
        validate_bundle(args.schemas, args.fixtures, args.contract)
    except (ContractError, OSError) as error:
        print(f"authority schema bundle invalid: {error}", file=sys.stderr)
        return 1
    print("authority schema bundle valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
