# apim-assess

Read-only Azure API Management assessment CLI. **Iterations 1-3**: core
configuration, Azure Monitor metrics, sanitized sub-resource inventory,
effective XML policies, forty deterministic core rules, validated rule
waivers/thresholds, and a self-contained HTML deck and deep-dive explorer
with effective policy and partial MCSB coverage matrices.

## Install

Python 3.11+:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\apim-assess --help
```

Only `collect` and `assess` require Azure credentials. Authenticate using a
method supported by `DefaultAzureCredential` (for example `az login`).
This iteration supports Azure public cloud only. Supply authorized targets;
the tool never enumerates all subscriptions in an account.

## Run

```powershell
.\.venv\Scripts\apim-assess assess --resource-id "/subscriptions/<subscription-uuid>/resourceGroups/<group>/providers/Microsoft.ApiManagement/service/<name>" --env prod --output-dir output
.\.venv\Scripts\apim-assess collect --subscriptions "<subscription-uuid>" --resource-groups "<group>" --output output\snapshot.json
.\.venv\Scripts\apim-assess analyze --snapshot output\snapshot.json --output output\findings.json
.\.venv\Scripts\apim-assess report --snapshot output\snapshot.json --findings output\findings.json --output output\apim-assessment-report.html
```

Pass `--config assessment.yaml` to `assess` or `analyze` to apply the
implemented `rules` settings (see `assessment.example.yaml`). Offline
analysis uses the environment classification saved during collection; it
does not rediscover tags or reinterpret targets. Configuration used for
analysis is saved in `findings.json`, so reporting needs no config file.

Repeat `--resource-id`, `--subscriptions`, or `--resource-groups` for multiple
values. Explicit IDs and discovered services are combined case-insensitively.
Resource-group filters apply to discovery, not explicit IDs. Discovery uses
paginated ARM service list operations (the plan's ARM fallback), without a
Resource Graph dependency. All Azure resource operations are HTTP GET.

`--config assessment.example.yaml` accepts only implemented options.
Explicit CLI lists replace their corresponding configured lists; omitted
options preserve configuration. Per-instance environment overrides take
precedence over the global profile. `auto` checks recognized environment
tags, name tokens, then SKU; ambiguous instances default to production.
The source of the classification is recorded. Use explicit `--env prod`
for a production gateway regardless of its SKU.

`--no-metrics` records disabled telemetry; it never creates healthy zeroes.
`--lookback-days` accepts 1-30 (default 14). Collection ends at the previous
complete UTC hour. Requests use Total; Duration uses Average/Maximum;
Capacity uses Average; v2 CPU/memory use Average/Maximum. Regional metrics
are split by Location. Policy XML is structurally sanitized before saving.
Named Value contents (including non-secret values), backend credentials,
certificate payloads, subscription keys, publisher contacts, arbitrary tags
and raw response bodies are never persisted. URL values are classified, not
stored. Safe typed metadata is projected before persistence. Errors retain
stable codes, never raw response bodies or credential exception text.

Collection warnings distinguish permission failures, empty telemetry and
disabled signals. Partial collection saves usable instances and warning
records. A run with no readable instance saves its partial snapshot and
exits 2 before analysis/reporting; input/configuration errors also exit 2.
Findings, including critical findings, do not themselves make the CLI fail.
Rerunning a stage replaces its output atomically. Do not commit live outputs.

## Offline example

No Azure access is required:

```powershell
.\.venv\Scripts\apim-assess analyze --snapshot tests\fixtures\sample_multi_apim_snapshot.json --output output\findings.json
.\.venv\Scripts\apim-assess report --snapshot tests\fixtures\sample_multi_apim_snapshot.json --findings output\findings.json --output output\apim-assessment-report.html
```

The fixture intentionally contains unavailable/partial telemetry. N/A and
unknown results are meaningful, not missing demo functionality. Open the
HTML file locally; its portfolio/instance selector, six slides, keyboard
navigation, explorer and theme toggle need no external runtime assets. Learn reference
links are optional outbound navigation, not runtime dependencies.

## Assessment decisions and limits

Iteration 1 preserved the five named seed IDs despite the plan's "one per
pillar" wording (two REL rules, no OPS rule). Iteration 2 adds exactly six
policy rules, including the first OPS rule. Iteration 3 adds 29 core checks
for 40 total, without enabling adjacent-signal or AI rules. No complete MCSB
compliance or overall health score is claimed.

| Rule | Decision and evidence boundary |
| --- | --- |
| APIM-REL-001 | Developer is a Critical production finding, Advisory in non-production. Other known SKUs pass this specific check. |
| APIM-REL-002 | Classic Premium with an explicitly single-zone region fails; all collected regions explicitly selecting multiple zones with consistent unit counts pass the configuration check. Empty/missing zone lists are unknown because current Microsoft guidance supports automatic placement. Unsupported SKUs are distinct from passes; v2 zone state remains unknown with this ARM projection. |
| APIM-SEC-001 | Classic VNet injection or an approved inbound private endpoint satisfies this configuration check. External classic injection does not prove private-only access. Outbound-only v2 integration is not inbound isolation. Missing mode/connection evidence is unknown. NS-1/NS-2 mappings describe partial evidence, not control certification. |
| APIM-COST-001 | Peak hourly average Capacity below 25% triggers a review, only with at least 14 complete days of hourly evidence for every region. At 25% the trigger does not fire. Classic Basic/Standard/Premium only; Developer/Consumption not applicable; v2 unsupported. |
| APIM-PERF-001 | Nearest-rank p95 of hourly averages above 70%, or a v2 CPU/memory maximum above 85%, triggers investigation. Threshold equality does not fail. Incomplete evidence can establish a high-load finding but cannot establish a healthy pass. Classic Capacity Maximum is not used. |
| APIM-SEC-019 | Explicit child policy sections without a direct base discard inherited controls. Evidence identifies affected scope/section; intentional replacements need review. |
| APIM-SEC-017 | API or open-product contexts without subscription requirements need a configured unconditional JWT, Entra-token or client-certificate validator. Portal OAuth settings and gateway-to-backend authentication do not validate callers. |
| APIM-SEC-018 | Subscription-required contexts need JWT/Entra caller validation; a configured certificate validator is an alternative, not a keys-only failure. |
| APIM-COST-004 | Positive fixed rate limits or concurrency limits enclosing forwarding satisfy the configuration check. Subscription limits require a key and a product/API/operation scope. Consumption does not support rate-limit-by-key. Dynamic limits and conditional increments are unknown. |
| APIM-SEC-020 | Review wildcard origins with credentials or configured caller protection, using the first effective CORS policy. This is not a browser exploit claim. Missing CORS is not applicable; dynamic origins and explicit OPTIONS operations are unknown. |
| APIM-OPS-002 | Evaluate ordered routing overrides: a literal effective URL fails; a collected backend-entity reference passes. Named-value/expression routes and unresolved references are unknown. |

### Iteration 3 decisions

The YAML catalog records each rule's required signals, applicability,
business impact, remediation and current Microsoft Learn grounding.

| Rules | Configuration decision and limit |
| --- | --- |
| REL-003, REL-006 | Review units in every region and production regional redundancy. Native multi-region is classic Premium only. Unit counts do not prove an SLA or zone distribution. |
| REL-007, REL-008 | Check configured breaker rules and referenced multi-member pools. Consumption breakers are unsupported; different conditional routes do not prove interchangeable backends. Ordered routing honors forwarding boundaries and declaration namespaces. |
| REL-009, REL-010 | Check effective error handling and explicit positive forwarding timeouts or bounded retry configuration. These do not prove safe idempotency, recovery or suitable time budgets. |
| REL-011 | External backup schedules, APIOps and restore exercises remain unknown. No write operation or secret access is used to infer DR readiness. |
| SEC-006, SEC-007, SEC-008 | Inspect explicit legacy protocol/cipher flags and API transports. Omitted flags remain unknown; v2/Consumption cipher customization is unsupported. Retirement guidance is not runtime negotiation evidence. |
| SEC-009, SEC-010, SEC-011 | Inspect secret-free direct management access metadata, the configured historical management API security floor and service identity. Missing metadata is unknown. |
| SEC-012, SEC-013, SEC-014 | Inspect secret/non-secret Key Vault linkage and custom-domain certificate rotation/expiry. Workspace Key Vault limits are explicit. Platform-managed certificates are an accepted rotation alternative. Expiry at the configured day boundary fails. |
| SEC-015, SEC-016, SEC-021, SEC-022 | Surface redacted inline-secret pattern flags, all-API subscription scopes, disabled backend TLS validation and developer-portal sign-in/registration settings. No secret values, debug tokens or certificate payloads are requested. |
| SEC-023, SEC-024 | Current tracing uses short-lived debug tokens, not diagnostic `enableTrace`; that planned persistent-flag check is unsupported. APIM cannot delete `Server`, so header suppression checks only final effective deletion of `X-Powered-By` and `X-AspNet-Version`. |
| COST-002, COST-005 | Review higher-cost non-production tiers and confirmed API-empty workspaces/products. Dynamic references and automatic backend matching prevent claims that unreferenced backends/named values are unused. Nothing is deleted. |
| OPS-003, OPS-004 | Compare only fully inspectable inline blocks (never equal redaction placeholders) and exact hashed API routes without version sets. Shared fragments/inherited blocks and revisions are not duplicate APIs. |
| PERF-002, PERF-003, PERF-004 | Review linked Application Insights sampling/body budgets and preventing request-size limits on POST/PUT/PATCH. An uncached GET stays unknown without cacheability/high-read evidence. Consumption internal response caching is unsupported. |

All IDs above have the `APIM-` prefix. Defaults such as 100 KiB payloads,
50% sampling and two scale units are assessment review heuristics, not
universal Azure limits or mandatory architecture prescriptions.

The explorer combines text search with pillar, severity, MCSB, affected API
and outcome filters. Scope selection switches portfolio/instance views;
evidence/remediation drawers and policy/MCSB tabs remain entirely offline.
Filters never change stored scores. MCSB rows aggregate **once per control
per instance**, fail for any unwaived failure, and warn for unknown,
unsupported or waived checks. The assessed-mapping rate uses known pass/fail
rows only; warnings and omitted future controls must accompany that rate.
The APIM MCSB v1 baseline itself is flagged by Microsoft as potentially outdated.

Waivers require a justification and optionally an exact APIM resource ID.
They retain original outcomes/evidence but are excluded from pillar scoring;
resource-specific waivers override global ones. Severity overrides take
precedence over environment defaults. Unknown/deferred rule IDs, unmatched
resource waivers, invalid thresholds and duplicate waivers are errors.
Threshold equality does not fail utilization/sampling checks; certificate
expiry at the warning boundary does fail. Saved settings make offline
analysis replay deterministic.

### Policy collection and interpretation

Collection uses APIM REST `2024-05-01` GET operations for APIs, operations,
products and API memberships, subscriptions, backends, named values,
certificates, diagnostics (including API diagnostics), self-hosted gateway
inventory, workspaces, loggers, policies and fragments. Workspace inventories and
policies are collected separately. Metadata is deliberately allowlisted:
operation methods, not request/response examples or parameter payloads;
Key Vault linkage flags, not secret identifiers/values; gateway identities,
not node health. Service projection also retains minimum API version and
custom-domain certificate source/expiry, never host names or private payloads.
Secret-free Tenant Access GET and portal configuration/sign-up/identity-provider
metadata support the service checks. Missing settings generate structured warnings.
Unimplemented future signals are not inferred from inventory.
`listSecrets`, credential/key retrieval actions and external XML links are
never invoked. Permission, malformed-response and pagination gaps are
structured warnings; a failed list is not an empty inventory. A policy GET
404 after discovering its parent means no local policy, not a failed list.

The resolver preserves section order and base placement across
global/workspace/product/API/operation scopes. Fragment references resolve
in the namespace where the including policy was declared, even when inherited
by a workspace. Product policies are not unioned: API/all-API subscription
contexts are separate, and open products can create anonymous request
contexts even for APIs requiring keys. These are configuration execution
contexts, not proof of active callers or traffic. Each rule contributes only
once per instance; per-context coverage does not multiply scores.

All policy literals, attributes, text, comments and expressions are removed
or replaced with safe semantic markers except an allowlist of structural
booleans/numbers and the CORS wildcard. Fragment/backend references are hashed.
DTD/entities and linked XML are refused. XML-encoded export (`format=xml`)
preserves valid XML even for C# expressions with quotes or ampersands;
both ARM JSON envelopes and XML media responses are accepted.
XML is bounded to 512 KiB, 10,000
elements and depth 64; effective expansion is bounded to 20,000 nodes per
context. Missing/invalid fragments (including currently unsupported nested
fragments), incomplete inventory and ambiguous control flow remain unknown.
Branches are not executed: a validator in one conditional branch is not
unconditional protection. Token-value expressions, dynamic limits/routes,
missing protocol metadata and explicit non-HTTP/SOAP API types cannot produce a
healthy policy pass. Validators establish configured controls, not correct
issuers/claims, certificate negotiation, network exposure or runtime behavior.
An effective cache lookup can return before later authentication policies;
those later validators cannot establish unconditional caller protection.

The stable API commonly omits API type even on detail GETs. When the type
is absent but explicit HTTP(S) transport metadata is present, the matrix
labels the assessment as HTTP gateway policies only. The type stays null:
no API type or protocol-specific GraphQL resolver coverage is invented.

New artifacts use schema `1.2`. Schema `1.0`/`1.1` snapshots still analyze
offline using available evidence. Their original digest contracts and
five-/eleven-rule findings remain reportable without reinterpreting scores.

These are assessment heuristics, not autoscale actions. Hourly averages can
hide shorter peaks; their p95 is not a request latency percentile. Right-sizing
requires representative workload tests and redundancy planning. A full
history is necessary to disprove observed low utilization or saturation.
Unknown, unsupported, waived and not-applicable results are excluded from weighted
scores and counted separately. No applicable evaluated controls means a
null score, not 100. Weights: Critical=5, High=4, Medium=3, Low=2, Advisory=1.

Current authoritative grounding (reviewed 2026-11-10):

- [APIM reliability and tier/zone capabilities](https://learn.microsoft.com/en-us/azure/reliability/reliability-api-management)
- [Capacity and scaling guidance](https://learn.microsoft.com/en-us/azure/api-management/api-management-capacity)
- [Supported metric REST names and aggregations](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-metrics/microsoft-apimanagement-service-metrics)
- [Networking capabilities by tier](https://learn.microsoft.com/en-us/azure/api-management/virtual-network-concepts)
- [Core ARM resource contract, 2024-05-01](https://learn.microsoft.com/en-us/rest/api/apimanagement/api-management-service/get?view=rest-apimanagement-2024-05-01)
- [MCSB APIM baseline](https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/api-management-security-baseline) (Microsoft flags this v1 baseline as potentially outdated; current service networking guidance governs capability decisions).
- [Policy scope, inheritance and execution order](https://learn.microsoft.com/en-us/azure/api-management/api-management-howto-policies)
- [Subscription and open-product execution contexts](https://learn.microsoft.com/en-us/azure/api-management/api-management-subscriptions)
- [Fragment structure and current nesting limitations](https://learn.microsoft.com/en-us/azure/api-management/policy-fragments)
- [JWT validation](https://learn.microsoft.com/en-us/azure/api-management/validate-jwt-policy), [Entra token validation](https://learn.microsoft.com/en-us/azure/api-management/validate-azure-ad-token-policy), [client certificate validation](https://learn.microsoft.com/en-us/azure/api-management/validate-client-certificate-policy)
- [Rate limiting by subscription](https://learn.microsoft.com/en-us/azure/api-management/rate-limit-policy), [by key](https://learn.microsoft.com/en-us/azure/api-management/rate-limit-by-key-policy), and [concurrency limits](https://learn.microsoft.com/en-us/azure/api-management/limit-concurrency-policy)
- [CORS ordering and preflight](https://learn.microsoft.com/en-us/azure/api-management/cors-policy)
- [Backend entity routing](https://learn.microsoft.com/en-us/azure/api-management/set-backend-service-policy)
- [Named-value metadata without secret retrieval](https://learn.microsoft.com/en-us/rest/api/apimanagement/named-value/list-by-service?view=rest-apimanagement-2024-05-01)
- [Five-pillar service guidance](https://learn.microsoft.com/en-us/azure/well-architected/service-guides/azure-api-management)
- [Current tracing contract](https://learn.microsoft.com/en-us/azure/api-management/api-management-howto-api-inspector) and [header limitations](https://learn.microsoft.com/en-us/azure/api-management/set-header-policy)
- [Protocols/ciphers and tier constraints](https://learn.microsoft.com/en-us/azure/api-management/api-management-howto-manage-protocols-ciphers)
- [Application Insights overhead and sampling](https://learn.microsoft.com/en-us/azure/api-management/api-management-howto-app-insights)
- [Content-validation limits and performance](https://learn.microsoft.com/en-us/azure/api-management/validate-content-policy)

Iteration 4 retains adjacent networking, governance, autoscale and
dimensioned/KQL telemetry checks (REL-004/005, SEC-003/025, COST-003,
OPS-001/005 and PERF-005). Gateway node-health evidence (OPS-006) also remains
deferred rather than inferred from inventory. Iteration 5 retains upstream
WAF-dependent SEC-002/004/005, AI Gateway rules, narrative enrichment, roadmap
and Docker. These modules/rules are not stubbed or silently accepted.

## Development and verification

CI runs the same checks on Python 3.11/3.13, Windows/Linux:

```powershell
.\.venv\Scripts\python -m ruff check .
.\.venv\Scripts\python -m ruff format --check .
.\.venv\Scripts\python -m mypy
.\.venv\Scripts\python -m pytest -q
.\.venv\Scripts\python -m build
```

Tests use synthetic data, fake credentials and mocked HTTP; they do not
access Azure. An explicit live smoke test requires an authorized resource ID
and credentials: run `assess` above, review `collection_warnings`, and inspect
the three local artifacts. Reader plus permission to read Azure Monitor
metrics is the intended access level. Do not retrieve keys or change resource
configuration to unblock collection. Live verification is a separate
acceptance gate; a PR without it stays draft.
