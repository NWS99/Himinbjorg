#!/usr/bin/env python3
"""Deterministic, fail-closed validation for the N-110 security artifacts."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts/security/v1/security-contract.json"
SCHEMA_DIR = ROOT / "contracts/security/v1"
VERSION = "1.0.0"
DOMAINS = {"research", "coding", "host", "credential_consumer", "release"}
TRANSITIONS = {("research", "research"), ("coding", "coding"), ("coding", "research"),
               ("host", "host"), ("host", "coding"), ("host", "research")}
CAPS = {"sandbox_shell", "host_exec", "host_read", "user_write", "network_access",
        "credential_activate", "privileged_action", "generic_host_shell"}
ACTIONS = {"read", "workspace_write", "sandbox_execute", "host_execute", "network_request",
           "external_send", "publish", "delete", "credential_activate", "model_request", "attest", "release"}
RESOURCE_TYPES = {"artifact", "filesystem_path", "workspace", "process", "network_destination", "external_identity",
                  "secret_ref", "consumer_profile", "model_provider", "policy", "candidate", "release_target"}
PROVENANCE = {"user_authorized": 0, "tool_verified": 1, "agent_derived": 2, "untrusted_external": 3}


class ArtifactError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ArtifactError(message)


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(text: str, name: str) -> Any:
    try:
        return json.loads(text, object_pairs_hook=reject_duplicate_pairs)
    except json.JSONDecodeError as error:
        raise ArtifactError(f"{name}: invalid JSON: {error}") from error


def obj(value: Any, name: str, required: set[str], allowed: set[str]) -> dict[str, Any]:
    require(isinstance(value, dict), f"{name}: object required")
    unknown = set(value) - allowed
    require(not unknown, f"{name}: unknown fields {sorted(unknown)}")
    require(required <= set(value), f"{name}: missing fields {sorted(required - set(value))}")
    return value


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def validate_resource(value: Any, name: str = "canonical_resource") -> None:
    v = obj(value, name, {"schema_version", "resource_type", "identity", "identity_digest", "generation"},
            {"schema_version", "resource_type", "identity", "identity_digest", "generation"})
    require(v["schema_version"] == VERSION, f"{name}: unknown schema version")
    require(v["resource_type"] in RESOURCE_TYPES and isinstance(v["identity"], str) and v["identity"], f"{name}: invalid identity")
    require(isinstance(v["identity_digest"], str) and len(v["identity_digest"]) == 64 and all(c in '0123456789abcdef' for c in v["identity_digest"]), f"{name}: invalid identity digest")
    require(isinstance(v["generation"], str) and v["generation"], f"{name}: missing generation")


def validate_constraints(value: Any) -> None:
    allowed = {"arguments", "executable_digest", "working_directory", "environment_allowlist", "mounts", "network_egress", "secret_handles", "time_limit_seconds", "use_limit", "budget", "idempotency_key", "fencing_token", "pre_state_digest"}
    v = obj(value, "constraints", {"arguments", "working_directory", "environment_allowlist", "network_egress", "time_limit_seconds", "use_limit", "idempotency_key", "fencing_token"}, allowed)
    require(isinstance(v["arguments"], list) and all(isinstance(x, str) for x in v["arguments"]), "constraints: invalid arguments")
    require(isinstance(v["working_directory"], str) and v["working_directory"], "constraints: invalid working_directory")
    for k in ("environment_allowlist", "mounts", "network_egress", "secret_handles"):
        if k in v:
            require(isinstance(v[k], list) and len(v[k]) == len(set(v[k])) and all(isinstance(x, str) for x in v[k]), f"constraints: invalid {k}")
    for k in ("time_limit_seconds", "use_limit", "budget"):
        if k in v: require(isinstance(v[k], int) and v[k] >= (1 if k != "budget" else 0), f"constraints: invalid {k}")
    for k in ("idempotency_key", "fencing_token"):
        require(isinstance(v[k], str) and v[k], f"constraints: invalid {k}")
    for k in ("executable_digest", "pre_state_digest"):
        if k in v: require(isinstance(v[k], str) and len(v[k]) == 64 and all(c in '0123456789abcdef' for c in v[k]), f"constraints: invalid {k}")


def validate_provenance(value: Any) -> None:
    v = obj(value, "provenance_requirements", {"schema_version", "minimum_class", "exposure", "causal_digests", "taint_sticky"}, {"schema_version", "minimum_class", "exposure", "causal_digests", "taint_sticky"})
    require(v["schema_version"] == VERSION and v["minimum_class"] in PROVENANCE and v["exposure"] in {f"X{i}" for i in range(5)} and v["taint_sticky"] is True, "provenance: unknown or non-sticky value")
    require(isinstance(v["causal_digests"], list) and len(v["causal_digests"]) == len(set(v["causal_digests"])), "provenance: invalid causal digests")


def validate_authority(value: Any) -> None:
    v = obj(value, "authority", {"schema_version", "decision", "principal", "action", "canonical_resource", "constraints", "security_domain", "provenance_requirements", "policy_version"}, {"schema_version", "decision", "principal", "action", "canonical_resource", "constraints", "security_domain", "provenance_requirements", "policy_version", "parent_authority_digest"})
    require(v["schema_version"] == VERSION and v["policy_version"] == VERSION, "authority: unknown version")
    require(v["decision"] in {"allow", "ask", "deny"} and v["action"] in ACTIONS, "authority: unknown decision or action")
    p = obj(v["principal"], "principal", {"id", "class"}, {"id", "class"})
    require(isinstance(p["id"], str) and p["id"] and p["class"] in {"human", "control_plane_service", "cognition_worker", "execution_adapter", "gate_runner", "credential_broker", "release_controller"}, "principal: unknown principal")
    validate_resource(v["canonical_resource"]); validate_constraints(v["constraints"]); validate_provenance(v["provenance_requirements"])
    d = obj(v["security_domain"], "security_domain", {"schema_version", "domain", "parent_domain"}, {"schema_version", "domain", "parent_domain"})
    require(d["schema_version"] == VERSION and d["domain"] in DOMAINS, "security_domain: unknown domain")
    if d["parent_domain"] is not None: require((d["parent_domain"], d["domain"]) in TRANSITIONS, "security_domain: delegation expands authority")
    if "parent_authority_digest" in v: require(len(v["parent_authority_digest"]) == 64 and all(c in '0123456789abcdef' for c in v["parent_authority_digest"]), "authority: invalid parent digest")
    if v["decision"] == "allow":
        require(d["domain"] != "release" or p["class"] == "release_controller", "authority: release is controller-only")


def validate_capability(value: Any, allow_forbidden: bool = False) -> None:
    v = obj(value, "capability", {"schema_version", "capability", "domain", "resource", "authority_digest"}, {"schema_version", "capability", "domain", "resource", "authority_digest"})
    require(v["schema_version"] == VERSION and v["capability"] in CAPS and v["domain"] in DOMAINS, "capability: unknown version, capability, or domain")
    if not allow_forbidden: require(v["capability"] != "generic_host_shell", "capability: generic host shell is forbidden")
    validate_resource(v["resource"]); require(len(v["authority_digest"]) == 64 and all(c in '0123456789abcdef' for c in v["authority_digest"]), "capability: invalid authority digest")


def validate_fixture(path: Path) -> None:
    data = load_json(path.read_text(encoding="utf-8"), str(path)); top = obj(data, str(path), {"fixture_version", "agent_domain", "cases"}, {"fixture_version", "agent_domain", "cases"})
    require(top["fixture_version"] == VERSION and top["agent_domain"] in {"research", "coding", "host"}, f"{path}: invalid fixture header")
    require(isinstance(top["cases"], list) and len(top["cases"]) == 5, f"{path}: must contain five stable cases")
    seen = set()
    seen_warrants: set[tuple[str, str]] = set()
    for case in top["cases"]:
        c = obj(case, "fixture case", {"id", "expected", "authority", "capability", "trusted_state"}, {"id", "expected", "authority", "capability", "trusted_state", "note"})
        require(c["id"] not in seen, f"{path}: duplicate case id"); seen.add(c["id"])
        require(c["expected"] in {"authorized", "unauthorized", "stale", "replayed", "ambiguous"}, f"{path}: unknown expected state")
        state = obj(c["trusted_state"], "trusted_state", {"trust", "generation", "pre_state_digest"}, {"trust", "generation", "pre_state_digest"})
        require(state["trust"] == "authoritative" and isinstance(state["generation"], str) and state["generation"], f"{path}: invalid trusted state")
        require(isinstance(state["pre_state_digest"], str) and len(state["pre_state_digest"]) == 64 and all(ch in "0123456789abcdef" for ch in state["pre_state_digest"]), f"{path}: invalid trusted pre-state digest")
        validate_authority(c["authority"]); validate_capability(c["capability"], c["expected"] == "unauthorized")
        require(c["capability"]["authority_digest"] == digest(c["authority"]), f"{path}: capability authority_digest is not bound to authority")
        authority = c["authority"]
        capability = c["capability"]
        resource = authority["canonical_resource"]
        trusted_state = c["trusted_state"]
        warrant_keys = {
            ("idempotency", authority["constraints"]["idempotency_key"]),
            ("fencing", authority["constraints"]["fencing_token"]),
        }
        is_stale = resource != capability["resource"] or resource["generation"] != trusted_state["generation"]
        is_replayed = bool(warrant_keys & seen_warrants)
        is_ambiguous = resource["generation"].lower() in {"unknown", "ambiguous", "dns-unknown"} or authority["provenance_requirements"]["exposure"] == "X4"
        if c["expected"] == "authorized":
            require(authority["decision"] == "allow" and not is_stale and not is_replayed and not is_ambiguous, f"{path}: authorized case is not executable")
        elif c["expected"] == "unauthorized":
            require(authority["decision"] == "deny", f"{path}: unauthorized case is not denied")
        elif c["expected"] == "stale":
            require(is_stale, f"{path}: stale case has no freshness mismatch")
        elif c["expected"] == "replayed":
            require(is_replayed, f"{path}: replayed case has a fresh warrant")
        elif c["expected"] == "ambiguous":
            require(is_ambiguous, f"{path}: ambiguous case is fully resolved")
        seen_warrants.update(warrant_keys)


def main() -> int:
    try:
        contract = load_json(CONTRACT.read_text(encoding="utf-8"), str(CONTRACT))
        require(contract.get("contract_version") == VERSION, "frozen contract version mismatch")
        files = sorted((ROOT / "tests/fixtures/security/v1").glob("*.json"))
        require(len(files) == 3, "fixtures must cover research, coding, and host")
        for path in files: validate_fixture(path)
        print(f"security artifacts valid: {len(files)} fixtures")
        return 0
    except (OSError, json.JSONDecodeError, ArtifactError) as error:
        print(f"security artifacts invalid: {error}", file=sys.stderr); return 1


if __name__ == "__main__": raise SystemExit(main())
