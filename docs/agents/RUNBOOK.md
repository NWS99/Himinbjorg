# Repository runbook

This is the canonical record of verified repository commands. A command is listed as verified only after it exists in this repository or environment and has been successfully run. Each entry records the command, purpose, scope, prerequisites, last verified date and revision, expected result, and known side effects.

The inspected baseline for bootstrap issue N-107 contains no Rust workspace, build script, package manifest, or CI workflow. N-52 adds a standard-library-only validator and unit tests for the frozen security contract; no Rust build commands are verified yet.

## Prerequisites

No repository-specific prerequisites are verified.

## Repository inspection

No command is recorded as verified.

## Build

No command is verified.

## Formatting

No command is verified.

## Linting

No command is verified.

## Unit tests

### Security-contract unit and negative tests

- **Command:** `python3 -m unittest discover -s tests/security -p 'test_*.py' -v`
- **Purpose:** Validate the golden N-52 contract and fail-closed mutations for authority, delegation, provenance and ownership.
- **Scope:** `contracts/security/v1/security-contract.json`, `scripts/validate_security_contract.py`, `tests/security/`.
- **Prerequisites:** Python 3 standard library.
- **Last verified:** 2026-09-19 on N-52 working tree based at `ec3831f`.
- **Expected result:** Fourteen tests pass.
- **Known side effects:** Python may create ignored `__pycache__` directories.

## Integration tests

No command is verified.

## Negative-security tests

The security-contract unit-test command above includes negative cases for capability-as-authority, SecretRef-as-authority, union delegation, fail-open ambiguity, reviewer declassification, missing or unknown traceability ownership, removed required vocabulary, weakened release semantics and incomplete capability-matrix cells.

## Fault/recovery tests

No command is verified.

## Documentation checks

### Security-contract structural validation

- **Command:** `python3 scripts/validate_security_contract.py`
- **Purpose:** Validate the frozen machine-readable security vocabulary and issue ownership.
- **Scope:** `contracts/security/v1/security-contract.json`.
- **Prerequisites:** Python 3 standard library.
- **Last verified:** 2026-09-19 on N-52 working tree based at `ec3831f`.
- **Expected result:** Prints `security contract valid` and exits zero.
- **Known side effects:** None.

### JSON syntax validation

- **Command:** `python3 -m json.tool contracts/security/v1/security-contract.json >/dev/null`
- **Purpose:** Independently verify that the contract is valid JSON.
- **Scope:** `contracts/security/v1/security-contract.json`.
- **Prerequisites:** Python 3 standard library and a POSIX-compatible shell.
- **Last verified:** 2026-09-19 on N-52 working tree based at `ec3831f`.
- **Expected result:** Exits zero without output.
- **Known side effects:** None.

## Local services or containers

No command is verified.

## Cleanup

No command is verified.

## Known environment constraints

- This bootstrap was performed against the repository revision recorded in Linear issue N-107's claim comment.
- No build or test tooling is inferred from the intended Rust architecture.
- Future entries must use the full command-entry evidence fields above and must not turn an intended command into a verified command without a successful run.
