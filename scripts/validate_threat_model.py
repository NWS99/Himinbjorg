#!/usr/bin/env python3
"""Validate the versioned threat-model projection against the frozen contract."""

import argparse
import json
from pathlib import Path
from typing import Any


class ThreatModelError(ValueError):
    pass


REQUIRED_CAPABILITIES = {
    "sandbox_shell", "host_exec", "host_read", "user_write", "network_access",
    "credential_activate", "privileged_action", "generic_host_shell",
}
REQUIRED_DOMAINS = {"research", "coding", "host", "credential_consumer"}
REQUIRED_THREATS = {
    "prompt_injection_and_provenance_loss", "capability_laundering_and_composition",
    "self_review_or_reviewer_capture", "approval_or_warrant_replay",
    "resource_aliasing_and_toctou", "secret_plus_arbitrary_egress",
    "secret_reference_enumeration", "consumer_binary_or_route_substitution",
    "same_uid_process_or_log_leakage", "direct_worker_to_provider_access",
    "crash_retry_duplicate_external_effect", "dependency_image_policy_or_runtime_drift",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ThreatModelError(message)


def load(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    require(isinstance(value, dict), "artifact root must be an object")
    return value


def validate(artifact: dict[str, Any], contract: dict[str, Any]) -> None:
    require(artifact.get("artifact_version") == "1.0.0", "artifact_version must be 1.0.0")
    require(artifact.get("source_contract_version") == contract.get("contract_version"), "source contract version mismatch")
    require(artifact.get("status") == "review_required", "threat model must remain review_required until independently accepted")

    boundaries = artifact.get("trust_boundaries")
    require(isinstance(boundaries, list) and boundaries, "trust_boundaries must be non-empty")
    boundary_ids = [item.get("id") for item in boundaries]
    require(len(boundary_ids) == len(set(boundary_ids)) and all(boundary_ids), "trust boundary ids must be unique")
    for item in boundaries:
        require(item.get("from") and item.get("to") and item.get("enforcement_owner"), f"{item.get('id')}: incomplete trust boundary")

    capabilities = artifact.get("capabilities")
    require(isinstance(capabilities, list), "capabilities must be a list")
    require({item.get("id") for item in capabilities} == REQUIRED_CAPABILITIES, "capability coverage is incomplete")
    contract_capabilities = {item["id"]: item for item in contract["capability_classes"]}
    for item in capabilities:
        source = contract_capabilities[item["id"]]
        require(item["default_policy"] == source["default_policy"], f"{item['id']}: default policy disagrees with frozen contract")
        require(item["enforcement_owner"], f"{item['id']}: missing enforcement owner")
        require(item["trust_boundary"] in boundary_ids, f"{item['id']}: unknown trust boundary")

    require(artifact.get("capability_matrix") == contract["capability_matrix"], "capability matrix disagrees with frozen contract")
    require(set(item.get("domain") for item in artifact["capability_matrix"]) == REQUIRED_DOMAINS, "capability matrix domains are incomplete")
    require(set(artifact.get("attacker_paths", [])) == REQUIRED_THREATS, "attacker path catalog is incomplete")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", nargs="?", type=Path, default=Path("contracts/security/v1/threat-model.json"))
    parser.add_argument("--contract", type=Path, default=Path("contracts/security/v1/security-contract.json"))
    args = parser.parse_args()
    try:
        validate(load(args.artifact), load(args.contract))
    except (OSError, json.JSONDecodeError, ThreatModelError) as error:
        print(f"threat model invalid: {error}")
        return 1
    print(f"threat model valid: {args.artifact}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
