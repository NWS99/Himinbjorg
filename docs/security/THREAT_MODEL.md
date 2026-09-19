# Security contract and threat model

Status: **Frozen for version 1.0.0 by N-52**

This document defines the vocabulary that later enforcement work must implement. The machine-consumable source is [`contracts/security/v1/security-contract.json`](../../contracts/security/v1/security-contract.json). If prose and the contract disagree, implementation fails closed and N-52 must be revised through review; downstream code must not guess.

## Scope and system boundary

Secure Agent Runtime is a local-first trusted control plane for replaceable coding-agent workers. The trusted Rust services own identity, policy, model access, scheduling, credentials, isolation, immutable verification, recovery and release decisions. Cognition workers, prompts, tool servers, external content and executed project code are untrusted inputs or components. “Himinbjorg” is the approved public repository/product name; Secure Agent Runtime remains the canonical internal architecture name.

The initial deployment assumes one local administrative domain. It does not claim protection from a compromised kernel or root administrator, malicious human-approved raw-secret consumer, or multi-tenant adversary.

## Assets

| Asset | Required property |
| --- | --- |
| Runtime authority | Cannot be created or expanded by worker text, messages or reviews |
| Human intent and approvals | Authenticated, exact-action bound and subordinate to hard policy |
| Policy and run constitution | Versioned, digest-bound and immutable for an active run |
| Secrets and provider credentials | Never revealed to workers; used only by the owning broker or verified consumer |
| Workspaces and candidates | Mutable ownership is private; review targets are sealed and immutable |
| Provenance and attestations | Causal provenance remains sticky; claims bind exact subjects and properties |
| Audit and recovery state | Durable, append-only, reconcilable without an LLM |
| Release authority | Separate from coding workers and ordinary control-plane execution |

## Principal model

- **Human:** owns goals and can provide exact authenticated approvals, but cannot override hard runtime policy.
- **Control-plane service:** authoritative only for its narrow deterministic responsibility.
- **Cognition worker:** proposes plans, code, evidence and requests; has no security authority.
- **Execution adapter:** performs only a valid decision or warrant and cannot broaden it.
- **Gate runner:** may attest only the exact claim it independently verified.
- **Credential Use Broker:** owns secret custody, grants and verified consumer launch.
- **Release Controller:** owns validated staging or production effects.

Runtime identity and role are separate. A role name, model, tool list, message author or operating profile is not authority.

## Authority algebra

An authority decision is defined over the complete tuple:

```text
Principal × Action × CanonicalResource × Constraints
× SecurityDomain × ProvenanceRequirements × PolicyVersion
```

An action is allowed only when every dimension is present, canonical and accepted by current policy. Missing or ambiguous dimensions deny.

Delegation and multi-party composition use intersection:

```text
EffectiveChildAuthority =
    ParentDelegableAuthority
    ∩ RequestedAuthority
    ∩ RuntimePolicy
```

No union is permitted. Two individually limited agents cannot combine their rights into a stronger workflow. Information may be relayed; authority cannot.

Security-domain delegation also follows an explicit partial order in the machine contract. Research remains Research; Coding may narrow to Coding or Research; Host may narrow to Host, Coding or Research. Credential-consumer and Release domains are non-delegable. This domain relation never replaces the full authority intersection.

The following are inputs or evidence and are never sufficient authority alone:

- capability or tool name;
- registry role or task assignment;
- P0–P4 risk class;
- human approval;
- reviewer recommendation;
- SecretRef or binding handle;
- message, artifact, prompt or model output;
- gate result that does not bind the exact subject and property.

## Canonical resources and constraints

A resource resolver must produce stable typed identity. Filesystem resources resolve path components and symlinks; network resources bind normalized URLs, destination and DNS identity where relevant; mutable resources bind pre-state or generation. Unknown aliases deny.

Constraints are first-class parts of authority, including exact arguments, executable or image digest, working directory, environment allowlist, mounts, network egress, secret handles, time/use/budget limits, idempotency key, fencing token and pre-state digest. An executor cannot silently discard a constraint.

### Versioned enforcement artifacts (N-110)

The v1 implementation vocabulary is split into strict, closed-world schemas under
`contracts/security/v1/`: `authority`, `capability`, `canonical-resource`,
`constraints`, `security-domain`, `provenance`, and `principal`. Every schema
artifact binds version metadata to `1.0.0`; version-bearing instances use a closed
`schema_version` field, while `principal` and `constraints` are bound by their
enclosing versioned authority. Unknown fields and declared versions are rejected.
Canonical resources carry a typed identity digest and generation.
Constraints carry exact arguments, working directory, egress, limits, idempotency
and fencing data. Provenance is sticky and communication never grants authority.

The stable fixtures in `tests/fixtures/security/v1/` cover Research, Coding and
Host agents. Each domain includes authorized, unauthorized, stale, replayed and
ambiguous cases. Ambiguous or unknown runtime state is represented by a deny
decision; it is never interpreted as an implicit allow.

The action vocabulary distinguishes reads, scoped workspace writes, sandbox and host execution, network requests, external sends, publish, delete, credential activation, model calls, attestations and releases. These actions are not interchangeable. In particular, `send`, `publish`, `delete` and `release` cannot inherit permission from a generic network or write capability.

The initial capability vocabulary includes `sandbox_shell`, structured `host_exec`, scoped `host_read`, `user_write`, network access, credential activation and privileged actions. All except isolated sandbox execution default deny. A generic host shell is explicitly forbidden; a denylist around an unrestricted shell is safety guidance, not a security boundary.

## Exposure, consequence and risk

X0–X4 summarize exposure, C0–C4 summarize potential consequence, and P0–P4 summarize contextual risk. These scales support routing and gates but never replace the structured authority vector.

Risk is computed by the runtime from action, canonical-resource sensitivity, provenance, data classification, secrets, destination and egress, blast radius, reversibility and causal workflow history. A requester may provide evidence but cannot lower the class. Classifiers and LLM reviewers may raise concern; they cannot clear taint, grant authority or override a deny.

## Provenance and verification

Untrusted provenance is sticky through copying, summarization and agent-to-agent communication. A typed deterministic declassification rule may narrow a specific property. Compilation, tests or review do not broadly make an artifact trusted.

A controlled gate runner may create an exact verified claim over subject digest, property, environment, toolchain, policy, gate definition, attester and result. The original artifact provenance remains attached. Acceptance review and integration consume a sealed candidate, never a live workspace.

## Credentials

Human administration and workload activation are separate trust boundaries. A SecretRef is an opaque pointer and never authority. Activation requires all of:

1. an authenticated workload identity;
2. an active human-issued SecretGrant;
3. an exact verified ConsumerProfile;
4. matching binary/image digest, execution identity and isolation profile;
5. matching credential slot, destination, action, scope and approval mode;
6. destination-bound egress and a short-lived revocable BindingLease.

The agent-accessible plane cannot reveal, create, mutate, delete, enumerate or export secrets. Missing, unknown and unauthorized references are indistinguishable. Raw secret material never enters worker, relay or `swarmd` arguments, environment, files, events or logs.

## Execution and recovery

Host and privileged effects cross PDP and PEP mediation. A complete warrant binds request and policy digests, principal and lineage, canonical resources, pre-state, executable/image, arguments, environment, mounts, secrets, egress, sandbox profile, expiry, idempotency and fencing.

The execution lifecycle is:

```text
ISSUED → CLAIMED → DISPATCHED → EXECUTED
                         └────→ UNKNOWN
```

An ambiguous failure after dispatch becomes `UNKNOWN`. It is reconciled from durable evidence and is never blindly retried. Rollback is modeled as capability-specific compensation with explicit limits.

## Attacker positions and abuse cases

The machine-readable catalog defines seventeen required paths:

1. cross-agent prompt injection and provenance loss;
2. capability laundering and composition;
3. self-review or requester-controlled reviewer capture;
4. approval or warrant replay;
5. resource aliasing and TOCTOU;
6. secret plus arbitrary egress;
7. SecretRef enumeration;
8. consumer, binary or route substitution;
9. same-UID, `/proc`, environment, file, log or crash leakage;
10. direct worker-to-provider access;
11. crash/retry duplicate external effects;
12. dependency, image, policy or runtime drift;
13. requester manipulation of runtime-owned risk classification;
14. an agent-visible secret-administration surface;
15. credential-broker socket discovery or relay substitution;
16. binding-lease replay or transfer;
17. weak TTY or human authentication.

Each path has named controls and owning Linear issues in the contract. The versioned
[`threat-model.json`](../../contracts/security/v1/threat-model.json) projection preserves
the complete catalog, canonical trust boundaries and capability matrix for downstream
implementation. N-53 will bind these identifiers to executable CI evidence; missing
ownership must fail validation.

The N-52 validator checks owner references against the frozen reviewed owner catalog. Live Linear existence, current status and stale-reference detection require connector access and deliberately belong to N-53; N-52 does not claim that an internally listed issue has been live-resolved during an offline validation run.

## Trust/data flow

```text
Untrusted inputs ──> cognition worker ──authenticated IPC──> trusted control plane
                                                              │
                     ┌────────────────────────────────────────┼───────────────────────┐
                     ▼                                        ▼                       ▼
              IsolationBackend                       Credential Broker         Model Gateway
              typed execution                        verified consumer         provider call
                     │                                        │                       │
                     └──────── exact evidence / durable audit / reconciliation ───────┘
                                                              │
                                                              ▼
                                                sealed candidate + exact claims
                                                              │
                                                              ▼
                                               independent review / integration
```

Data crossing from an untrusted component remains untrusted unless a narrow deterministic claim says otherwise. No arrow in this diagram implicitly transfers authority.

## Security goals

- least authority for every principal and run;
- deterministic fail-closed authorization and recovery;
- causal provenance without authority amplification;
- exact-effect review, warrants and auditability;
- non-reveal of secrets to confined agents;
- immutable review and integration targets;
- replacement of cognition, harnesses and providers without changing the trust boundary.

## Explicit non-goals

- proving that content contains no prompt injection;
- using model confidence or reviewer confidence as authorization;
- universal rollback of external effects;
- protecting against compromised kernel/root or the broker itself;
- protecting a raw credential from a malicious human-approved consumer;
- claiming multi-tenant isolation in the initial local product.

## Normative sources

- [Architecture Overview](https://app.notion.com/p/3de35e9a89fe8176ad5def4cf950eef8)
- [Agent Security — Capability Broker & Tiered Isolation](https://app.notion.com/p/3de35e9a89fe81518099d6620ac6f2c2)
- [Security Review & Hardening Plan](https://app.notion.com/p/3de35e9a89fe817b8ef3ee3dd814528c)
- [Trusted Control Plane](https://app.notion.com/p/3df35e9a89fe8167bb29fec6e1294a00)
- [Execution Authority](https://app.notion.com/p/3de35e9a89fe81eeab0dfe2753d502d3)
- [Human-Owned Credential Use Broker](https://app.notion.com/p/3df35e9a89fe81929c41e2853a06eb75)

## Change control

Version 1.0.0 is the N-52 contract consumed by N-51 and N-53. Any change that adds a trust boundary, changes authority algebra, weakens fail-closed behavior or alters secret guarantees requires a dedicated architecture issue and independent review. Backward-compatible vocabulary additions require a version increment and a traceable owner.
