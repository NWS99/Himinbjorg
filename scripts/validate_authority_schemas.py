#!/usr/bin/env python3
"""Offline, deterministic validator for the N-110 authority schema bundle.

The validator intentionally implements only the small JSON-Schema vocabulary used
by the contract.  It does not import jsonschema: validation must work in the
bootstrap repository and must fail closed when a vocabulary is extended.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

SCHEMA_NAMES = (
    "authority.schema.json",
    "capability.schema.json",
    "canonical-resource.schema.json",
    "constraint.schema.json",
    "security-domain.schema.json",
    "provenance.schema.json",
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
DECISION_CASES = {"authorized", "unauthorized", "stale", "replayed", "ambiguous"}


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


def _check_enum(name: str, value: Any, allowed: set[str]) -> None:
    if value is not None:
        require(isinstance(value, str) and value in allowed, f"unknown {name}: {value!r}")


def _check_schema_keywords(node: Any, location: str) -> None:
    require(isinstance(node, dict), f"{location}: schema node must be an object")
    allowed = {
        "$schema", "$id", "$comment", "title", "description", "type", "properties", "required",
        "additionalProperties", "items", "enum", "const", "pattern", "format",
        "default", "examples", "minLength", "maxLength", "minItems", "maxItems", "uniqueItems",
        "minimum", "maximum", "allOf", "anyOf", "oneOf", "not",
        "$defs", "$ref", "source_contract_digest", "schema_version", "vocabulary",
    }
    require(set(node).issubset(allowed), f"{location}: unknown schema fields")
    if "type" in node:
        require(node["type"] in {"object", "array", "string", "boolean", "integer", "number", "null"}, f"{location}: unknown type")
    if "additionalProperties" in node:
        require(node["additionalProperties"] is False or isinstance(node["additionalProperties"], dict), f"{location}: additionalProperties must be false or a schema")
    if "properties" in node:
        require(isinstance(node["properties"], dict), f"{location}: properties must be an object")
        for key, child in node["properties"].items():
            require(isinstance(key, str) and key, f"{location}: invalid property name")
            _check_schema_keywords(child, f"{location}.properties.{key}")
            if key in {"capability", "capability_id"} and "enum" in child:
                require(set(child["enum"]) == CAPABILITIES, f"{location}: capability vocabulary drift")
            if key in {"resource_type", "resource"} and "enum" in child:
                require(set(child["enum"]) == RESOURCE_TYPES, f"{location}: resource vocabulary drift")
            if key in {"policy_state", "decision"} and "enum" in child:
                require(set(child["enum"]) == POLICY_STATES, f"{location}: policy vocabulary drift")
            if key == "security_domain" and "enum" in child:
                require(set(child["enum"]) == SECURITY_DOMAINS, f"{location}: security-domain vocabulary drift")
            if key == "provenance" and "enum" in child:
                require(set(child["enum"]) == PROVENANCE_CLASSES, f"{location}: provenance vocabulary drift")
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


def evaluate_authority(request: dict[str, Any], *, digest: str, delegated: dict[str, Any] | None = None) -> str:
    """Return allow/ask/deny. Every missing, stale, replayed, or unclear fact denies."""
    require(isinstance(request, dict), "request must be an object")
    if request.get("source_contract_digest") != digest:
        return "deny"
    if request.get("case") in {"stale", "replayed", "ambiguous"}:
        return "deny"
    if request.get("case") not in {None, "authorized", "unauthorized"}:
        return "deny"
    _check_enum("capability", request.get("capability"), CAPABILITIES)
    _check_enum("resource type", request.get("resource_type"), RESOURCE_TYPES)
    _check_enum("security domain", request.get("security_domain"), SECURITY_DOMAINS)
    _check_enum("policy state", request.get("policy_state"), POLICY_STATES)
    require(request.get("communication_grants_authority") is not True, "communication cannot grant authority")
    decision = request.get("policy_state")
    if decision not in POLICY_STATES:
        return "deny"
    if delegated is not None:
        parent = evaluate_authority(delegated, digest=digest)
        if parent != "allow":
            return "deny" if parent == "deny" else "ask"
        if decision != "allow":
            return decision
    return decision


def validate_fixtures(fixtures_dir: Path, digest: str) -> None:
    try:
        paths = sorted(fixtures_dir.glob("*.json"))
    except OSError as error:
        raise ContractError(f"cannot inspect fixtures: {error}") from error
    require(paths, "fixtures: no JSON fixtures found")
    seen: set[str] = set()
    for path in paths:
        fixture = load_json(path)
        require(isinstance(fixture, dict), f"{path.name}: fixture must be an object")
        fixture_id = fixture.get("id")
        require(isinstance(fixture_id, str) and fixture_id and fixture_id not in seen, f"{path.name}: invalid or duplicate id")
        seen.add(fixture_id)
        require(fixture.get("expected_decision") in POLICY_STATES, f"{path.name}: unknown expected_decision")
        request = fixture.get("request")
        require(isinstance(request, dict), f"{path.name}: request must be an object")
        actual = evaluate_authority(request, digest=digest, delegated=fixture.get("delegated_request"))
        require(actual == fixture["expected_decision"], f"{path.name}: expected {fixture['expected_decision']}, got {actual}")
        if request.get("case") is not None:
            require(request["case"] in DECISION_CASES, f"{path.name}: unknown case")


def validate_bundle(schemas_dir: Path, fixtures_dir: Path, contract_path: Path) -> None:
    digest = source_contract_digest(contract_path)
    for name in SCHEMA_NAMES:
        path = schemas_dir / name
        require(path.is_file(), f"missing schema artifact: {path}")
        value = load_json(path)
        require(isinstance(value, dict), f"{name}: root must be an object")
        validate_schema_artifact(value, name, digest)
    validate_fixtures(fixtures_dir, digest)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--schemas", type=Path, default=Path("contracts/security/v1/schemas"))
    parser.add_argument("--fixtures", type=Path, default=Path("contracts/security/v1/fixtures"))
    parser.add_argument("--contract", type=Path, default=Path("contracts/security/v1/security-contract.json"))
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
