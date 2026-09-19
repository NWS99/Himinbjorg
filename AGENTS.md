# Secure Agent Runtime operating contract

## Mission and product boundary

This repository implements a local, security-focused trusted control plane for coding agents. Cognition workers, coding harnesses, and model providers are replaceable. The Rust control plane owns durable state, identity, policy, scheduling, capability, credential use, isolation, immutable review, and release decisions. This is not another generic prompt-loop or agent-persona framework.

## Sources of truth

- **Notion** holds accepted product intent, architecture decisions, trust boundaries, and invariants. The [Architecture Overview](https://app.notion.com/p/3de35e9a89fe8176ad5def4cf950eef8) is the canonical entry point; the [Autonomous Backlog Execution & Model Routing Playbook](https://app.notion.com/p/3e0351a89fe813f83e6e61cfd2ca9da) defines execution and routing practice.
- **Linear** is the mutable work queue for scope, dependencies, claims, status, blockers, and review hand-offs.
- **Git** is the implementation record for code, schemas, tests, fixtures, documentation, and immutable evidence.
- **AGENTS.md** is the persistent operating contract for agents.
- **docs/agents/LEARNINGS.md** contains verified operational observations.
- **docs/agents/RUNBOOK.md** contains verified local build, test, lint, and development commands.

Linear may not silently override an accepted Notion decision. Repository behavior may show that a plan is outdated, but it does not automatically replace architecture intent. A material conflict between Notion, Linear, and repository behavior fails closed and must be reported as **Blocked**. Ordinary implementation treats Notion as read-only. Architecture changes require a dedicated Linear issue and independent review; the governed architecture process may then update Notion.

LEARNINGS.md and RUNBOOK.md are operational records, not alternative architecture sources. Evidence requirements in those files do not authorize a product or security-policy change.

## Non-negotiable invariants

- Security enforcement lives outside the LLM.
- Communication transfers information, not capability.
- Delegated authority can only narrow.
- No actor may approve its own work.
- Privileged actions require exact, bounded authority.
- Agents may reference secrets but may never reveal or administer them.
- Review, integration, and release bind to an immutable candidate.
- Ambiguity at a trust boundary fails closed.
- Cognition workers remain replaceable and outside the trusted computing base.
- Process boundaries follow trust boundaries.
- Deterministic policy and verification outrank model confidence.

## Linear work-selection protocol

An agent may claim an issue only when it has **Agent Ready**, is **Backlog** or **Todo**, every blocked-by dependency is **Done**, it does not have **Blocked**, it is not a **Tracking** issue, and its capability lane suits the active model. Tracking issues summarize work and are never implemented directly.

On claim, move the issue to **In Progress** and publish the model/harness, capability lane, repository and base revision, intended deliverable, and assumptions. Work on one issue at a time unless explicit orchestration authorizes otherwise.

## Capability lanes

- **Implement: Luna-class** — bounded, explicit work with deterministic verification.
- **Implement: Sonnet-class** — cross-component, security-sensitive, context-heavy, or recovery-sensitive work.
- **Review: Standard** — independent review by a non-implementing model.
- **Review: Frontier** — adversarial Sol- or Opus-class review.
- **Review: Dual Frontier** — two independent frontier reviews.
- **Overflow: OpenRouter** — allowed only under the policy recorded in Notion and Linear.

These labels describe capability contracts, not vendor identities. A calibrated open model may execute a lane when it meets the same acceptance and review contract.

## Implementation and verification contract

Agents must implement permanent interfaces rather than placeholders, inspect existing contracts before editing, keep changes scoped to the claimed issue, and add tests for intended behavior and plausible failure modes. When a trust boundary is affected, include negative-security and fault/recovery tests. Update affected schemas, fixtures, generated artifacts, and documentation. Run every verified relevant command in `docs/agents/RUNBOOK.md`, record commands and results, and create an immutable commit or other accepted candidate before review. Never alter the candidate being reviewed. Happy-path behavior alone is insufficient for security-sensitive work.

## Review and blocked behavior

Implementers cannot approve their own candidate. **APPROVE** leads to integration or **Done** according to repository policy. **REQUEST REVISION** returns the issue to **In Progress** and requires a new immutable candidate. An ADR or accepted-architecture conflict, or missing authority, moves the issue to **Todo** with **Blocked**.

A blocked comment must contain the exact blocker, evidence and attempts, required decision or access, affected issues, and remaining safe work. After submitting work for review, an agent may select another eligible issue but must not alter the submitted candidate.

## Git and destructive-operation boundaries

Preserve unrelated and pre-existing user changes. Do not use destructive Git commands. Do not force-push, merge, publish, release, purchase, register, or delete external resources without explicit authority. Do not create additional worktrees unless an accepted task or concurrency policy requires them. Use issue-scoped branches and focused commits. Never commit secrets, credentials, session data, or sensitive logs. Stop when an action is irreversible or outside the issue's authority.

## Persistent learning policy

AGENTS.md is governed. Agents must not edit it merely because they discovered a preference or workaround. Changing it requires an explicit Linear issue and independent review. This bootstrap issue is the explicit authorization for its initial creation. Architecture and security changes additionally require the appropriate architecture review.

Ordinary agents may update LEARNINGS.md or RUNBOOK.md only with reproducible evidence and within their ticket. Recurring verified knowledge may be proposed for promotion into AGENTS.md through a separate Linear issue. Do not store task progress, temporary failures, speculative advice, or model-specific chatter in AGENTS.md.

## Starting and finishing a run

1. Read applicable AGENTS.md.
2. Read the selected Linear issue and dependencies.
3. Read the linked Notion decisions.
4. Inspect repository state and existing contracts.
5. Claim the issue.
6. Implement the smallest complete vertical increment.
7. Run verified gates.
8. Produce an immutable candidate.
9. Update Linear and request the required review.
10. Record only durable, evidenced operational learning.
