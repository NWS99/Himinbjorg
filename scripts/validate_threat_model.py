#!/usr/bin/env python3
"""Validate the versioned threat-model projection against the frozen contract."""

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


class ThreatModelError(ValueError):
    pass


EXPECTED_SOURCE = "contracts/security/v1/security-contract.json"
EXPECTED_CONTRACT_RAW_SHA256 = "c1cb5e367886e6b93b3843d6f7806178a9a583e197e6a6d30231997b15854830"
EXPECTED_CONTRACT_SEMANTIC_SHA256 = "407bceef5379989e47bbac872cbc5c3324694c469fffd8daf70a1c44221254c9"
EXPECTED_ENFORCEMENT_BOUNDARY = {
    "model_safety_policy": "advisory_input_only",
    "hard_security_enforcement": "trusted_control_plane_and_dedicated_brokers",
    "cognition_worker_in_tcb": False,
    "unknown_or_ambiguous": "deny",
}
EXPECTED_CAPABILITY_BOUNDARIES = {
    "sandbox_shell": "control_plane_to_execution",
    "host_exec": "control_plane_to_execution",
    "host_read": "control_plane_to_execution",
    "user_write": "control_plane_to_execution",
    "network_access": "control_plane_to_execution",
    "credential_activate": "control_plane_to_credential_broker",
    "privileged_action": "control_plane_to_execution",
    "generic_host_shell": "control_plane_to_execution",
}
EXPECTED_BOUNDARY_DETAILS = {
    "worker_to_control_plane": (["cognition_worker"], ["trusted_control_plane"], "authenticated_ipc_and_policy"),
    "control_plane_to_execution": (["trusted_control_plane"], ["isolation_backend", "typed_host_broker", "privileged_helper"], "pdp_pep_and_exact_warrant"),
    "control_plane_to_model_provider": (["trusted_control_plane"], ["model_provider"], "model_gateway"),
    "control_plane_to_credential_broker": (["trusted_control_plane"], ["credential_broker_workload_api", "verified_consumer"], "credential_broker"),
    "human_to_credential_admin": (["authenticated_human"], ["credential_broker_admin_plane"], "credential_broker_admin_plane"),
    "workspace_to_review": (["mutable_workspace"], ["sealed_candidate", "independent_reviewer"], "immutable_candidate_and_review_gate"),
    "control_plane_to_release": (["trusted_control_plane"], ["release_controller"], "release_controller"),
}
EXPECTED_SCOPE_COVERAGE = {
    "prompt_injection_and_provenance_loss": ["THREAT-001"],
    "confused_deputy_and_capability_composition": ["THREAT-002"],
    "secret_plus_egress": ["THREAT-006"],
    "credential_administration_and_activation": ["THREAT-014", "THREAT-015", "THREAT-016", "THREAT-017"],
    "resource_aliasing_and_toctou": ["THREAT-005"],
    "crash_retry_duplicate_effect": ["THREAT-011"],
    "supply_chain_and_runtime_drift": ["THREAT-012"],
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ThreatModelError(message)


def require_object_list(value: Any, section: str) -> list[dict[str, Any]]:
    require(isinstance(value, list) and value, f"{section} must be a non-empty list")
    require(all(isinstance(item, dict) for item in value), f"{section} entries must be objects")
    return value


def require_unique_ids(items: list[dict[str, Any]], section: str) -> None:
    ids = [item.get("id") for item in items]
    require(all(isinstance(item_id, str) and item_id for item_id in ids), f"{section} ids must be non-empty strings")
    require(len(ids) == len(set(ids)), f"{section} ids must be unique")


def load(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    require(isinstance(value, dict), "artifact root must be an object")
    return value


def semantic_digest(value: dict[str, Any]) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(canonical).hexdigest()


def validate_source_lock(contract_path: Path, lock_path: Path) -> None:
    expected = lock_path.read_text(encoding="ascii").strip().split()[0]
    require(expected == EXPECTED_CONTRACT_RAW_SHA256, "source contract lock does not name the reviewed N-52 digest")
    actual = hashlib.sha256(contract_path.read_bytes()).hexdigest()
    require(actual == expected, "source contract digest does not match reviewed lock")


def validate(artifact: dict[str, Any], contract: dict[str, Any]) -> None:
    require(artifact.get("artifact_version") == "1.0.0", "artifact_version must be 1.0.0")
    require(artifact.get("source_contract") == EXPECTED_SOURCE, "source_contract must name the frozen contract")
    require(artifact.get("source_contract_version") == contract.get("contract_version"), "source contract version mismatch")
    require(artifact.get("source_contract_sha256") == EXPECTED_CONTRACT_RAW_SHA256, "source contract digest binding changed")
    require(semantic_digest(contract) == EXPECTED_CONTRACT_SEMANTIC_SHA256, "frozen contract semantic digest mismatch")
    require(artifact.get("status") == "review_required", "threat model must remain review_required until independently accepted")
    require(isinstance(artifact.get("purpose"), str) and artifact["purpose"], "purpose must be non-empty")

    for section in ("security_goals", "non_goals", "principal_classes", "assets", "input_classes", "attacker_positions"):
        require(artifact.get(section) == contract.get(section), f"{section} disagrees with frozen contract")

    require(artifact.get("enforcement_boundary") == EXPECTED_ENFORCEMENT_BOUNDARY, "model safety and hard enforcement boundary changed")
    unresolved = artifact.get("unresolved_architecture_choices")
    require(isinstance(unresolved, list), "unresolved_architecture_choices must be an explicit list")
    require(all(isinstance(item, str) and item for item in unresolved), "unresolved architecture choices must be non-empty strings")
    require(len(unresolved) == len(set(unresolved)), "unresolved architecture choices must be unique")

    boundaries = require_object_list(artifact.get("trust_boundaries"), "trust_boundaries")
    require_unique_ids(boundaries, "trust_boundaries")
    contract_boundaries = contract.get("trust_boundaries")
    require(isinstance(contract_boundaries, list), "frozen contract trust_boundaries must be a list")
    projected_boundaries = [
        {key: item.get(key) for key in ("id", "protocol", "fail_mode", "owner_issues")}
        for item in boundaries
    ]
    require(projected_boundaries == contract_boundaries, "trust boundary catalog disagrees with frozen contract")
    for item in boundaries:
        require(item.get("from") and item.get("to") and item.get("enforcement_owner"), f"{item.get('id')}: incomplete trust boundary")
        expected_from, expected_to, expected_owner = EXPECTED_BOUNDARY_DETAILS[item["id"]]
        require(item.get("from") == expected_from, f"{item['id']}: source endpoint changed")
        require(item.get("to") == expected_to, f"{item['id']}: destination endpoint changed")
        require(item.get("enforcement_owner") == expected_owner, f"{item['id']}: enforcement owner changed")
    boundary_ids = {item["id"] for item in boundaries}
    require("human_to_credential_admin" in boundary_ids, "credential administration boundary is missing")
    require("control_plane_to_credential_broker" in boundary_ids, "credential workload activation boundary is missing")

    capabilities = require_object_list(artifact.get("capabilities"), "capabilities")
    require_unique_ids(capabilities, "capabilities")
    contract_capabilities = {item["id"]: item for item in contract.get("capability_classes", [])}
    require(set(contract_capabilities) == set(EXPECTED_CAPABILITY_BOUNDARIES), "frozen capability catalog changed")
    require({item["id"] for item in capabilities} == set(contract_capabilities), "capability coverage is incomplete")
    for item in capabilities:
        source = contract_capabilities[item["id"]]
        require(item.get("default_policy") == source.get("default_policy"), f"{item['id']}: default policy disagrees with frozen contract")
        require(item.get("enforcement_owner") == source.get("hard_boundary"), f"{item['id']}: enforcement owner disagrees with frozen contract")
        require(item.get("trust_boundary") == EXPECTED_CAPABILITY_BOUNDARIES[item["id"]], f"{item['id']}: canonical trust boundary changed")
        require(item.get("trust_boundary") in boundary_ids, f"{item['id']}: unknown trust boundary")

    require(artifact.get("capability_matrix") == contract.get("capability_matrix"), "capability matrix disagrees with frozen contract")

    expected_threats = contract.get("attacker_paths")
    require(isinstance(expected_threats, list) and expected_threats, "frozen attacker path catalog must be non-empty")
    expected_threat_names = [item.get("name") for item in expected_threats]
    require(artifact.get("attacker_paths") == expected_threat_names, "attacker path catalog disagrees with frozen contract")
    require(artifact.get("scope_coverage") == EXPECTED_SCOPE_COVERAGE, "required N-109 abuse-case coverage changed")
    threat_ids = {item.get("id") for item in expected_threats}
    require(all(set(refs).issubset(threat_ids) for refs in EXPECTED_SCOPE_COVERAGE.values()), "scope coverage references unknown threats")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", nargs="?", type=Path, default=Path("contracts/security/v1/threat-model.json"))
    parser.add_argument("--contract", type=Path, default=Path("contracts/security/v1/security-contract.json"))
    parser.add_argument("--contract-lock", type=Path)
    args = parser.parse_args()
    try:
        validate_source_lock(args.contract, args.contract_lock or args.contract.with_suffix(".sha256"))
        validate(load(args.artifact), load(args.contract))
    except (OSError, json.JSONDecodeError, ThreatModelError, KeyError, TypeError) as error:
        print(f"threat model invalid: {error}", file=sys.stderr)
        return 1
    print(f"threat model valid: {args.artifact}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
