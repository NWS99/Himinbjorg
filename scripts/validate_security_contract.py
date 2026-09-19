#!/usr/bin/env python3
"""Validate the frozen N-52 security contract without third-party packages."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ISSUE_RE = re.compile(r"^N-[1-9][0-9]*$")
EXPECTED_VECTOR = [
    "principal",
    "action",
    "canonical_resource",
    "constraints",
    "security_domain",
    "provenance_requirements",
    "policy_version",
]


class ContractError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def require_unique(items: list[dict[str, Any]], field: str, section: str) -> None:
    values = [item.get(field) for item in items]
    require(all(isinstance(value, str) and value for value in values), f"{section}: every {field} must be a non-empty string")
    require(len(values) == len(set(values)), f"{section}: duplicate {field}")


def require_owner_issues(items: list[dict[str, Any]], section: str) -> None:
    for item in items:
        owners = item.get("owner_issues")
        require(isinstance(owners, list) and owners, f"{section}/{item.get('id')}: missing owner_issues")
        require(all(isinstance(issue, str) and ISSUE_RE.fullmatch(issue) for issue in owners), f"{section}/{item.get('id')}: invalid owner issue")


def validate_contract(contract: dict[str, Any]) -> None:
    require(contract.get("contract_version") == "1.0.0", "contract_version must be 1.0.0")
    require(contract.get("status") == "frozen", "status must be frozen")
    require(contract.get("owner_issue") == "N-52", "owner_issue must be N-52")
    require(contract.get("authority_vector") == EXPECTED_VECTOR, "authority vector is incomplete or reordered")

    semantics = contract.get("authority_semantics", {})
    require(semantics.get("decision_values") == ["allow", "ask", "deny"], "decision values must be allow/ask/deny")
    require(semantics.get("default_decision") == "deny", "default decision must deny")
    require(semantics.get("unknown_or_ambiguous") == "deny", "ambiguity must deny")
    require(semantics.get("delegation_operator") == "intersection", "delegation must be intersection")
    require(semantics.get("composition_operator") == "intersection", "composition must be intersection")
    for key in ("communication_grants_authority", "capability_is_authority", "approval_is_authority", "secret_ref_is_authority", "risk_class_is_authority"):
        require(semantics.get(key) is False, f"{key} must be false")

    for section in ("principal_classes", "action_classes", "resource_types", "capability_classes", "security_domains", "provenance_classes", "exposure_levels", "consequence_levels", "risk_levels", "trust_boundaries", "hard_invariants", "attacker_paths"):
        items = contract.get(section)
        require(isinstance(items, list) and items, f"{section} must be a non-empty list")
        require_unique(items, "id", section)

    require([item["id"] for item in contract["exposure_levels"]] == [f"X{i}" for i in range(5)], "exposure levels must be X0-X4")
    require([item["id"] for item in contract["consequence_levels"]] == [f"C{i}" for i in range(5)], "consequence levels must be C0-C4")
    require([item["id"] for item in contract["risk_levels"]] == [f"P{i}" for i in range(5)], "risk levels must be P0-P4")

    capability_defaults = {item["id"]: item.get("default_policy") for item in contract["capability_classes"]}
    require(capability_defaults.get("generic_host_shell") == "deny", "generic host shell must default deny")
    require(capability_defaults.get("privileged_action") == "deny", "privileged actions must default deny")
    require(capability_defaults.get("credential_activate") == "deny", "credential activation must default deny")

    for section in ("trust_boundaries", "hard_invariants", "attacker_paths"):
        require_owner_issues(contract[section], section)

    invariant_ids = {item["id"] for item in contract["hard_invariants"]}
    require({"INV-002", "INV-003", "INV-005", "INV-006", "INV-012", "INV-013"}.issubset(invariant_ids), "required authority and credential invariants are missing")
    threat_ids = {item["id"] for item in contract["attacker_paths"]}
    require({f"THREAT-{i:03d}" for i in range(1, 13)}.issubset(threat_ids), "required attacker paths are missing")

    provenance = contract.get("provenance_semantics", {})
    require(provenance.get("llm_may_clear_taint") is False, "LLMs must not clear taint")
    require(provenance.get("review_may_clear_taint") is False, "review must not clear taint")
    require(provenance.get("gate_effect") == "exact_verified_claim_only", "gates may create only exact verified claims")

    for key in ("canonical_resource_requirements", "constraint_classes", "risk_inputs", "security_goals", "non_goals"):
        values = contract.get(key)
        require(isinstance(values, list) and values, f"{key} must be non-empty")
        require(len(values) == len(set(values)), f"{key} contains duplicates")


def load_contract(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    require(isinstance(value, dict), "contract root must be an object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", nargs="?", type=Path, default=Path("contracts/security/v1/security-contract.json"))
    args = parser.parse_args()
    try:
        validate_contract(load_contract(args.path))
    except (OSError, json.JSONDecodeError, ContractError) as error:
        print(f"security contract invalid: {error}", file=sys.stderr)
        return 1
    print(f"security contract valid: {args.path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
