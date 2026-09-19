# N-102 — Naming, namespace and launch-identity report

**Report version:** 1.0.0
**Issue:** [N-102](https://linear.app/n-digital-solutions/issue/N-102/validate-product-name-namespaces-and-launch-identity)
**Research snapshot:** 2026-09-19 (Europe/Berlin)
**Status:** Human decision recorded: ACCEPT Himinbjorg as the public repository/product name.

> **Decision addendum (2026-09-19):** The repository owner selected **Himinbjorg** after the initial finalist screen. This addendum supersedes the earlier “BLOCKED FOR HUMAN CHOICE” outcome for the public name. It does not constitute trademark clearance, domain availability, or package-name reservation.

## Decision

The initial finalist screen found that the three proposed names were not materially clear enough for autonomous acceptance:

- **Wardline** has direct software collisions in the same problem space, including a published PyPI package, `wardline.dev`, and an AI-agent control-plane repository. The exact primary domain `wardline.com` is listed for sale, not shown as an unregistered domain.
- **Cordon** has direct and substantial collisions in agent security, credential containment and MCP policy, as well as an occupied PyPI package and several public GitHub projects.
- **Ironweave** has a credible existing technology/project identity and the `ironweave.io` domain footprint. The available evidence is less directly adjacent than the Wardline and Cordon collisions, but it is not a clean slate.

This is a collision screen, not legal clearance. The human owner has now selected **Himinbjorg**, a new Norse-mythology-based umbrella name outside the initial finalist set. The internal architecture name remains **Secure Agent Runtime**. No package reservation, trademark filing, domain purchase or production DNS change is implied.

The Himinbjorg naming family is:

| Scope | Name |
|---|---|
| Public repository/product | `Himinbjorg` |
| Identity and ingress | `Heimdall` |
| Authenticated IPC/transport | `Bifrost` |
| Knowledge/evidence | `Mimisbrunnr` |
| Provenance/state | `Urdarbrunnr` |
| Alerts and irreversible events | `Gjallarhorn` |
| Privileged control services | `Asgard` |
| Workspaces and project execution | `Midgard` |

Subsystem names are descriptive proposals only; they are not namespace reservations.

The initial Himinbjorg screen found no direct product/category collision comparable to Wardline or Cordon. It did find a public `NorseArchitecture/Glitnir` planning repository that uses `Himinbjorg` for an identity component, plus non-software company/name references. Himinbjorg is therefore a materially better working name, not legally cleared or proven available. See [the repository search result](https://github.com/NorseArchitecture/Glitnir/blob/master/docs/Platform/plans/2026-06-28-migrations-framework-identity-schema.md).

## Method and evidence rules

The screen used exact-name web searches, official package pages where indexed, public GitHub pages, official IP-office search entry points, and public domain pages. Results are timestamped at the report snapshot. A missing search result is recorded as **not established**, never as “available”. Search-engine results are discovery evidence; registry and IP-office pages are the authoritative follow-up locations.

The positioning source says Wardline is only a working name and requires namespace, domain, trademark and pronunciation checks before a rename: [Product Positioning, Naming & Launch Foundation](https://app.notion.com/p/3e0351a89fe8118a2edfa4a3ad43c16).

## Collision findings

### Wardline

| Surface | Result | Evidence |
|---|---|---|
| GitHub / software | **High-risk collision.** `kabirnarang39/wardline` describes an open-source control-plane proxy for AI agents with identity, policy, budget and audit. | [GitHub repository](https://github.com/kabirnarang39/wardline) |
| GitHub / software | **High-risk collision.** `wardline.dev` presents Wardline as a Python trust-boundary/static-analysis framework with install instructions and a release candidate. | [wardline.dev](https://www.wardline.dev/) |
| PyPI | **Occupied.** `wardline` is published, with release 1.5.0 shown by PyPI. | [PyPI project](https://pypi.org/project/wardline/) |
| Domain | **Not clear.** `wardline.com` is explicitly listed for sale for USD 5,000. | [GoDaddy listing](https://forsale.godaddy.com/forsale/www.wardline.com?traffic_id=binns&traffic_type=TDFS_BINNS) |
| Domain / software | **Additional collision.** `wardline.app` resolves to a public Wardline site. | [wardline.app](https://wardline.app/) |
| Corporate/product identity | **Additional collision.** `Wardline LLC` operates `thewardline.com` and publishes legal terms. | [terms of service](https://thewardline.com/terms-of-service) |
| npm, crates.io, OCI, executable namespace | **Not established in this snapshot.** The web research tool did not return a reproducible exact-name result for these surfaces; this is not an availability claim. | [npm package search](https://www.npmjs.com/search?q=wardline), [crates.io search](https://crates.io/search?q=wardline), [Docker Hub search](https://hub.docker.com/search?q=wardline) |

### Ironweave

| Surface | Result | Evidence |
|---|---|---|
| Technology/product identity | **Credible existing identity.** “IronWeave” is used for a blockchain/data platform and has an `ironweave.io` publication footprint. | [IronWeave publication](https://archive-blog.ironweave.io/you-know-your-data-isnt-safe-traditional-blockchain-wont-save-you-but-this-will/) |
| GitHub / exact software | **Not established in this snapshot.** Exact-name search did not produce a primary GitHub project comparable to the Wardline or Cordon findings. | [GitHub search](https://github.com/search?q=ironweave&type=repositories) |
| PyPI, npm, crates.io, OCI, executable namespace | **Not established in this snapshot.** No exact-name result was captured from the indexed public pages; this is not an availability claim. | [PyPI search](https://pypi.org/search/?q=ironweave), [npm search](https://www.npmjs.com/search?q=ironweave), [crates.io search](https://crates.io/search?q=ironweave), [Docker Hub search](https://hub.docker.com/search?q=ironweave) |
| Domain | **Collision/ownership risk.** `ironweave.io` is part of the existing project footprint above. | [ironweave.io](https://ironweave.io/) |

### Cordon

| Surface | Result | Evidence |
|---|---|---|
| Agent security | **Very high-risk collision.** Cordon is marketed as entitlement policy for coding agents and explicitly lists Codex, Claude Code, Cursor, Gemini and OpenCode. | [cordon.sh](https://cordon.sh/) |
| Agent/MCP security | **Very high-risk collision.** Cordon for MCP is a security gateway for agent tool calls with policy, approvals, drift detection and audit. | [getcordon.com](https://getcordon.com/), [GitHub repository](https://github.com/marras0914/cordon) |
| Credential containment | **Very high-risk collision.** Codezero markets Cordon as a credential-containment layer for AI coding agents. | [Codezero Cordon](https://www.codezero.io/) |
| GitHub | **Occupied/crowded.** Public projects include MCP security, PII-redacting LLM compliance, credential brokerage and other security tooling. | [Cordon GitHub search](https://github.com/search?q=cordon+agent+security&type=repositories) |
| PyPI | **Occupied.** `cordon` is published; the indexed project page shows release 1.1.1. | [PyPI project](https://pypi.org/project/cordon/) |
| npm, crates.io, OCI, executable namespace | **Not established in this snapshot.** The exact namespaces were not treated as clear based on search omission. | [npm search](https://www.npmjs.com/search?q=cordon), [crates.io search](https://crates.io/search?q=cordon), [Docker Hub search](https://hub.docker.com/search?q=cordon) |
| Academic/product language | **Additional collision.** “Cordon” is also used for a recent semantic-transactions system for tool-using LLM agents. | [arXiv paper](https://arxiv.org/abs/2606.17573) |

## Trademark and IP search

The following official systems were identified and their search entry points were checked. The connected research surface did not provide a reproducible, query-specific result export for all three names, so this report does **not** claim that any mark is clear or unavailable.

| Office | Result at snapshot | Source |
|---|---|---|
| EUIPO | Search system identified; query-specific result capture was not available in this run. **No clearance conclusion.** | [EUIPO search](https://www.euipo.europa.eu/en/search) |
| DPMA | Official register identified; it states that current legal/procedural status is available and updated daily. Query-specific result capture was not available in this run. **No clearance conclusion.** | [DPMAregister](https://www.dpma.de/english/search/dpmaregister/) |
| USPTO | Official trademark search identified. USPTO warns that clearance requires analysis of confusing similarity and related goods/services; query-specific result capture was not available in this run. **No clearance conclusion.** | [USPTO search](https://www.uspto.gov/trademarks/search/search), [USPTO clearance guidance](https://www.uspto.gov/trademarks/search/federal-trademark-searching) |

The USPTO guidance expressly recommends professional help for a comprehensive clearance search. This report therefore treats trademark risk as unresolved rather than making a legal claim.

## Namespace and domain matrix

| Candidate | GitHub | PyPI | npm | crates.io | OCI/container | Primary domain | Overall screen |
|---|---|---|---|---|---|---|---|
| Wardline | Direct collisions | Occupied | Not established | Not established | Not established | `wardline.com` for sale; `.dev` and `.app` used | **Reject absent explicit coexistence decision** |
| Ironweave | No exact collision established | Not established | Not established | Not established | Not established | `ironweave.io` existing footprint | **Human/legal review required** |
| Cordon | Crowded/direct collisions | Occupied | Not established | Not established | Not established | Multiple Cordon products/domains | **Reject for category collision** |

An exact registry API check should be rerun immediately before any package reservation or publication. Package-name availability is not inferred from a web search result.

## Scored comparison

Scores are 1 (weak) to 5 (strong), except collision risk and namespace availability where 5 means low risk / favorable. The scores are a screening aid, not a legal or market decision.

| Criterion | Weight | Wardline | Ironweave | Cordon |
|---|---:|---:|---:|---:|
| Memorability | 20% | 4 | 4 | 4 |
| Category fit | 20% | 5 | 3 | 5 |
| Collision risk | 25% | 1 | 2 | 1 |
| International usability | 15% | 4 | 3 | 4 |
| Namespace availability | 20% | 1 | 2 | 1 |
| **Weighted screen** | **100%** | **2.75** | **2.80** | **2.75** |

Ironweave narrowly leads the mechanical screen only because the captured collisions are less directly adjacent. That is not enough to authorize acceptance: the existing `ironweave.io` identity and any trademark findings must be reviewed by a human.

## Pronunciation and spelling

| Name | English | German | Failure modes |
|---|---|---|---|
| Wardline | Usually “word-line” or “ward-line” | Likely “Wort-lein” or English “word-line” | Ambiguous vowel, `ward` may be heard as `word`; “line” is generic and produces many compounds. |
| Ironweave | “eye-urn-weev” / sometimes “iron-weave” | Likely “Eisen-weef” or English approximation | `iron` pronunciation is irregular for learners; `weave` is often spelled/heard as “weev/weave”. |
| Cordon | “kor-don” | Usually understandable as “Kor-don” | Existing common noun in English/German contexts; pronunciation is stable but semantic distinctiveness is weak. |

All three pass a basic speakability screen, but none passes a high-confidence collision screen.

## Exact rename inventory (not executed)

The repository now contains the approved public label `Himinbjorg` and the internal architecture label `Secure Agent Runtime`. Historical Wardline findings remain in this report to preserve the evidence behind the rejected candidate.

| Surface | Current evidence / target after approval | Action only after human decision |
|---|---|---|
| Linear | Project `Secure Agent Runtime`; issues and branches use N- identifiers and the project name. | Rename project/display labels only; preserve issue history and identifiers. |
| Notion | Architecture and positioning pages use `Secure Agent Runtime`; positioning page marks Wardline as working name. | Update canonical naming decision and linked pages through governed architecture/product process. |
| Repository | `README.md` begins `# Himinbjorg`; `docs/security/THREAT_MODEL.md` retains `Secure Agent Runtime` as the canonical internal architecture name. | Keep the public name and internal architecture name intentionally distinct; do not alter frozen security vocabulary casually. |
| Rust package/workspace | No Cargo manifest exists in the current repository. | Reserve and publish only the human-approved namespace; update future `Cargo.toml` package/workspace names. |
| Binaries/services | No runtime implementation or binary manifest exists. | Rename future `swarmd`, broker and helper display names only if the approved naming plan requires it; keep protocol identifiers versioned. |
| Containers/OCI | No container configuration or image namespace exists. | Select approved image/repository namespace; do not reserve or publish during N-102. |
| Python/npm/docs examples | No package manifests exist; future examples may inherit the approved name. | Update examples, install commands and package metadata after decision; avoid claiming namespace availability now. |
| Website/domains | No website source exists in this repository. | Select a human-approved domain; do not purchase/configure DNS in N-102. |

## Reproducibility checklist

Rerun these exact checks before approval and append a new report version:

1. Search exact names in GitHub, PyPI, npm, crates.io and Docker Hub using the linked search pages.
2. Query the package registries directly with authenticated/read-only registry APIs where available and record HTTP status plus canonical project URL.
3. Search Himinbjorg in EUIPO eSearch/TMview, DPMAregister and USPTO Trademark Search; export or screenshot exact hits.
4. Check candidate domains and sensible fallbacks with a registrar/RDAP source; do not infer availability from a parked or for-sale page.
5. Repeat English/German spoken tests with target developers and record the exact prompt and responses.

## Conclusion

The initial evidence rejects autonomous acceptance of Wardline, Cordon and Ironweave. The human owner selected **Himinbjorg** as the new umbrella name. The repository rename can proceed locally and at the Git remote, while trademark, registry and domain checks remain a separate non-legal clearance step.
