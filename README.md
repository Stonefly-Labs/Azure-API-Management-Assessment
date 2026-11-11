# apim-assess

Read-only Azure API Management assessment CLI. **Iterations 1-9**: core
configuration, Azure Monitor metrics, sanitized sub-resource inventory,
effective XML policies, 55 deterministic rules, linked networking/governance
metadata, optional aggregate Log Analytics queries, validated rule
waivers/thresholds, and a self-contained HTML deck and deep-dive explorer
with effective policy and partial MCSB coverage matrices, optional upstream
WAF probes, LLM/GraphQL checks, a remediation roadmap and container packaging,
focused report navigation, deep sanitized policy scans, and dimensional telemetry
with inline SVG trend charts, native MCP/A2A inventories and MCP OAuth posture.

## Install

Python 3.11+:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\apim-assess --help
```

Only collection and explicitly requested AI enrichment use remote services. Authenticate using a
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
Resource Graph dependency. Azure resource reads are HTTP GET except the
documented, read-only Policy Insights `latest/queryResults` POST and the
opt-in, scoped Resource Graph query POST. The reader
does not expose a general resource-write operation.

`--config assessment.example.yaml` accepts only implemented options.
Explicit CLI lists replace their corresponding configured lists; omitted
options preserve configuration. Per-instance environment overrides take
precedence over the global profile. `auto` checks recognized environment
tags, name tokens, then SKU; ambiguous instances default to production.
The source of the classification is recorded. Use explicit `--env prod`
for a production gateway regardless of its SKU.

`--no-metrics` records disabled telemetry; it never creates healthy zeroes.
`--lookback-days` accepts 1-30 (default 30). Collection ends at the previous
complete UTC hour. Requests use Total; Duration/BackendDuration use
Average/Maximum; Capacity uses Average (also Maximum on classic Premium);
v2 CPU/memory use Average/Maximum. Regional baseline metrics are split by
Location; additional Requests queries split by status category and API, and
BackendDuration by API. Policy XML is structurally sanitized before saving.
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
HTML file locally; its portfolio/instance selector, seven focused tabs, optional
presentation navigation, filters and theme toggle need no external runtime assets. Learn reference
links are optional outbound navigation, not runtime dependencies.

### Iteration 8: dimensional telemetry and trend charts

The Overview includes four inline SVG panels for gateway utilization, request
volume by HTTP status code category, request volume by top APIs, and backend
latency by API. Scope switching, keyboard-accessible legend toggles, light/dark
themes, exact-value tables and print/PDF work without external runtime assets.
The heading and UTC dates reflect the saved window, including shorter overrides
and legacy artifacts; an old 14-day snapshot is never labeled as 30 days.

Collection preserves the regional baseline series and adds separate dimensional
queries. Request API series are bounded to the top five per instance by Total
descending; backend latency series are bounded to five by Maximum descending.
API dimension values are hashed before persistence and matched to known service
API inventory paths for display when unambiguous. These bounded selections do
not represent all API traffic, and the request and latency top-five sets can
differ. No raw log rows, URLs or policy contents are added to telemetry.

Charts use daily UTC sums of hourly request Totals, means of hourly utilization
or latency Averages, and peaks of hourly Maxima. The means are not
request-weighted or request-level p95. Portfolio views overlay per-instance
series; they do not add overlapping Location, status and API splits. Missing days
break lines; partial days retain observed values and hourly sample counts,
never fabricated zeroes. Unavailable, unsupported, denied, disabled and legacy
missing-dimensional evidence remains explicit. The reference lines use saved
review thresholds (defaults 70% / 85% and 2,000 ms); charts do not change rules,
findings or scores. Classic Capacity Maximum remains display-only.

With `modules.log_analytics_kql: true`, an additional bounded per-API window
aggregate provides logged backend latency sample counts, average, maximum and
p95. It stays separate from Monitor trends and from other workspace/table
samples. Missing log evidence is not a zero or an inferred metric datapoint.
Snapshots `1.0`-`1.4` remain readable; absent optional additions preserve
historical serialized fields and snapshot digests.

Microsoft grounding: [APIM monitoring reference](https://learn.microsoft.com/en-us/azure/api-management/monitor-api-management-reference),
[Monitor Metrics List API](https://learn.microsoft.com/en-us/rest/api/monitor/metrics/list),
and [gateway log columns](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/apimanagementgatewaylogs).

### Iteration 9: MCP/A2A inventory and incoming OAuth

Collection pins `2025-09-01-preview` for native API discovery, MCP tool resources
and MCP/A2A metadata/policies. Native `mcp` and `a2a` types come from ARM metadata,
never API names. REST-backed MCP tools retain their backing API-operation path;
passthrough servers retain safe transport/endpoint counts. Agent identifiers,
agent-card/runtime paths and backend references are hashed, and URLs are only
classified. No MCP invocation, A2A task, agent-card fetch, tool schema or secret
read is performed.

Overview and API policy coverage show per-instance native counts, discovery
status, safe metadata, tool bindings and independent policy/tool coverage.
A failed preview read falls back to ordinary API inventory without claiming
complete native discovery. Partial pages, unknown API types and unresolved
bindings remain explicit gaps. New artifacts use schema `1.5`; historical
`1.0`-`1.4` snapshots, digests and saved findings remain replayable. Historical
snapshots say native coverage was not collected, not that no servers exist.

`APIM-AIGW-006` requires effective incoming `validate-jwt` or
`validate-azure-ad-token` at each MCP server entry point. The sanitizer preserves
a secret-free configuration marker for issuer/tenant, signature/expiry and
audience/client restrictions. Effective inheritance, fragments and every
conditional path must establish protection. Confirmed absence fails High in
production and Medium in non-production, with **"MCP should be secured using
OAuth 2.0."** Missing evidence or unverified configuration is unknown.
Waivers/severity overrides retain the same evidence; tools never multiply
this rule's score.

This is a stricter assessment baseline than APIM's supported key-only option.
Keys, client certificates, portal OAuth settings, forwarded tokens, backend
identity and validation on a backing REST operation do not satisfy it. Generic
`APIM-SEC-017`/`018` findings remain separate, broader caller-authentication
checks; passing one is not an MCP OAuth pass. No OAuth discovery, PKCE or runtime
enforcement certification is claimed, and no new MCSB mapping is inferred.

MCP/A2A global/API policies are inspected. Collected A2A operation policies are
retained but do not establish protection at the agent entry point without
verified operation-scope execution semantics. Workspace execution is unsupported;
product execution is unresolved
rather than assumed to follow REST semantics. REST request-body/cache/forwarding
checks are unsupported for these protocols, and native typing alone never
establishes an LLM workload. Management-plane passthrough tool inventory is not
data-plane tool discovery.

Microsoft grounding: [MCP management](https://learn.microsoft.com/en-us/azure/api-management/manage-mcp-servers-rest-api),
[MCP security](https://learn.microsoft.com/en-us/azure/api-management/secure-mcp-servers),
[A2A policies](https://learn.microsoft.com/en-us/azure/api-management/agent-to-agent-api),
and [Microsoft's A2A ARM sample](https://github.com/Azure/apiops-cli/blob/main/tests/integration/all-resource-types/bicep/source-apim.bicep).

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

The Findings view combines text search with pillar, severity, MCSB, affected API
and outcome filters. Scope selection switches portfolio/instance views;
evidence/remediation drawers and policy/MCSB tabs remain entirely offline.
Filters never change stored scores. MCSB rows aggregate **once per control
per instance**, fail for any unwaived failure, and warn for unknown,
unsupported or waived checks. The assessed-mapping rate uses known pass/fail
rows only; warnings and omitted future controls must accompany that rate.
The APIM MCSB v1 baseline itself is flagged by Microsoft as potentially outdated.

### Iteration 6: focused HTML readout

The default report follows a compact, seven-tab layout: **Overview, Findings,
Verification gaps, Roadmap, MCSB controls, API policy coverage, Method & scope**.
Overview separates confirmed issues, passing checks and missing evidence, shows
coverage beside pillar scores, and calls out non-production failures whose rule
defaults are High/Critical in production.

Findings are grouped by rule with per-instance results and exact evidence
patterns. Expand a pattern to inspect every source/API reference; nothing is
truncated. Combined filters must match the same instance result. Presets select
confirmed issues, verification gaps, passes, or all results (including waivers).
Gaps remain visible even when the same rule fails on another instance. Waivers
are excluded from priorities, the roadmap and applicable score denominators.

API summaries expand to operation/product execution contexts. Topology, metrics,
collection coverage, upstream observations and AI limits remain inspectable.
Presentation mode retains Previous/Next, arrow/Space navigation and fullscreen.
Tab lists also support arrow keys and Home/End. Print/PDF includes all sections
and evidence for the selected scope, independent of filters, then restores the
interactive view. No new collection, analysis rules or artifact schema is added.

Waivers require a justification and optionally an exact APIM resource ID.
They retain original outcomes/evidence but are excluded from pillar scoring;
resource-specific waivers override global ones. Severity overrides take
precedence over environment defaults. Unknown/deferred rule IDs, unmatched
resource waivers, invalid thresholds and duplicate waivers are errors.
Threshold equality does not fail utilization/sampling checks; certificate
expiry at the warning boundary does fail. Saved settings make offline
analysis replay deterministic.

### Iteration 4: adjacent signals

`modules.networking` and `modules.defender_policy` default to `true`.
`modules.log_analytics_kql` is opt-in and requires diagnostic linkage from
`defender_policy`. Configure these in `assessment.yaml`; CLI target/profile
and metric overrides retain their existing precedence. Disabled, denied,
unsupported and partially collected signals remain explicit coverage gaps.

| Rules / signals | Decision and evidence boundary |
| --- | --- |
| SEC-003 | Inspect only linked injected subnets and attached NSGs, including custom/default inbound rules in priority order. Confirmed missing NSGs, broad public TCP 80/443 allowances, or explicit blocked classic management/load-balancer ports fail. Specific CIDR/ASG/destination exceptions remain conservative unknowns. V2 injection does not inherit classic 3443/6390 requirements; outbound integration is not inbound isolation. No routing/reachability or WAF bypass claim is made. |
| Private endpoints / DDoS | Inspect explicitly linked private endpoint target/approval/subnet metadata and customer public IP DDoS mode, including linked VNet inheritance where available. Hash adjacent resource references; retain no raw IPs/CIDRs. No customer public IP link does not prove DDoS protection absent. These are report context, not additional rules. |
| REL-004 / COST-003 | Read subscription autoscale settings, retaining only exact APIM targets. Review enabled elastic profiles and positive increase/decrease actions. Scale-in is not applicable without enabled elastic profiles. Developer unsupported; Consumption automatically scales. Profiles and triggers require workload validation; native autoscale covers primary-region units only. |
| OPS-001 | Require an enabled resource `GatewayLogs` category or `allLogs` group with a destination. APIM Application Insights diagnostics are separate. A confirmed setting is not ingestion or retention proof. Consumption resource logs are unsupported. |
| SEC-025 | Require both the Defender `Api` subscription plan and successfully provisioned explicit REST API onboarding. Current documented classic tier/region limits apply. Unknown API types are not assumed REST; workspace/self-hosted runtime coverage is not established. |
| OPS-005 | Query latest policy evaluations for the exact resource without starting an evaluation or remediation. Keep initiative references separate and retain conflicting latest-timestamp states. Fresh NonCompliant fails; Compliant passes the observed-state check; Exempt is N/A. Empty, stale, future, conflict and error states cannot pass. Default maximum age is two days (review heuristic). Assignment/definition/initiative references are hashed. |
| SEC-006 / PERF-005 | Optional aggregate KQL adds positive legacy TLS observations, request-level backend latency p95, gateway/backend 5xx counts and bounded hashed API hotspots. Default review thresholds are strictly above 2000 ms / 1% gateway errors; equality does not fail. Missing/empty/partial samples cannot establish a healthy runtime pass. Positive TLS evidence overrides disabled service flags. |

KQL uses only enabled GatewayLogs diagnostic workspace links, not arbitrary
workspace discovery. It queries the configured `ApiManagementGatewayLogs` or
`AzureDiagnostics` destination with an exact APIM resource filter and the
same UTC telemetry window as metrics. Legacy optional columns (including
`AdditionalFields`) retain known-value counts rather than inventing zeroes.
Each workspace/table sample is assessed separately; duplicated destinations
are deduplicated and samples/percentiles are never summed or averaged across
destinations. Historic logs routed to a different destination/table are not
discovered. Sampling, retention and logging exclusions can limit the sample;
these results are not a population-wide traffic guarantee.

Only numeric aggregates and bounded API hotspot hashes are saved, never
raw log rows, caller IPs, URLs, headers or request/response bodies.
`telemetry.kql_max_rows` bounds hotspot rows to 1-100 (default 5), and
`kql_timeout_seconds` bounds query execution to 1-180 seconds (default 30).
Cache hit/miss counts and ratios are report context, not a claim that every
API should cache. A query error, including partial results, saves an explicit
warning rather than returned raw content.

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

New artifacts use schema `1.4`. Schema `1.0`/`1.1`/`1.2`/`1.3` snapshots still analyze
offline using available evidence. Their original digest contracts and
historical 5-, 11-, 40-, and 47-rule findings remain reportable without reinterpreting scores.

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

Iteration 4 adds seven rules (REL-004, SEC-003/025, COST-003, OPS-001/005 and
PERF-005), extends SEC-006 runtime evidence, and retains the existing report
and deterministic scoring contracts. Secondary-region custom alerting
(REL-005) and gateway node health (OPS-006) remain deferred: neither is
included in Iteration 4's collector acceptance list, and neither is inferred
from inventory. SEC-002 remains deferred rather than duplicating SEC-004/005
or claiming that WAF existence proves every direct public path restricted.

### Iteration 5: upstream WAF and modern workloads

Both `modules.afd` and `modules.appgw` are disabled by default. When enabled,
`auto_discover: true` queries **only assessment subscriptions** for AFD
Standard/Premium profiles or Application Gateways. `resource_ids` adds
explicit targets, including authorized cross-subscription targets; set
`auto_discover: false` for explicit-only probing. No subscription enumeration,
DNS traversal, external origin requests, inference calls or configuration
changes occur. Resource Graph reads use `2024-04-01`; AFD routes/associations
use `2025-04-15`, Front Door WAF `2022-05-01`, and AppGW `2026-01-01`.

Matching uses APIM gateway/custom Proxy hostnames and reported public/private
IP addresses in memory; saved artifacts contain hashed edge/route references,
not those endpoints, IPs, rule match conditions or raw response bodies.
AFD probes bind active origins to routes and WAF domain associations covering
all paths. AppGW probes resolve basic and path routing, honoring path-policy
over listener-policy over gateway-policy precedence, including legacy WAF
configuration. Unresolved AFD rule-set/AppGW rewrite routing and partial
path associations cannot establish complete protection. HTTPS forwarding, explicit health probes, bot rules and
rate-limiting presence are report context, not independent enforcement claims.
AFD Classic and other CDN profile kinds are not supported.

| Rules | Configuration decision and limit |
| --- | --- |
| SEC-004 | Every observed matched route/domain needs an enabled Prevention WAF with a blocking managed ruleset. Exclusions, rule-group overrides and custom bypass/log rules remain unknown. No observed match never proves WAF absence: permissions, DNS indirection and cross-subscription topology may hide paths. |
| SEC-005 | Require regional APIM NSGs permitting only the observed AppGW subnet or `AzureFrontDoor.Backend` on TCP 443 before broad denials for both 80/443. AFD also requires an exact literal, hashed `X-Azure-FDID` check in every effective API context with a rejecting HTTP code. Conditional/dynamic or named-value headers, ip-filter, mTLS and other unproven alternatives remain unknown, not passes. Internal/public-disabled ingress is N/A for this public-origin check; private callers still need review. |
| AIGW-001 | Recognized LLM endpoints require effective fixed positive token-rate or quota budgets, a counter key and explicit estimation behavior. Gateway-local counters, concurrency and provider/schema support limit runtime conclusions. Consumption token limits are unsupported. |
| AIGW-002 | Azure OpenAI routes require unconditional system-assigned managed identity for the Cognitive Services audience without static API-key credentials, including URL/query bindings. Custom token-variable handling, user-assigned identity linkage, header/query rewrites and workspace capability gaps stay unknown/unsupported. No Azure identity requirement is imposed on third-party LLM providers. |
| AIGW-003 | Every Azure OpenAI route must select a pool with at least two distinct collected members, each with a positive-duration/threshold 429 breaker accepting Retry-After. Cycles, missing members and dynamic routing cannot pass; Consumption breakers are unsupported. This does not establish model equivalence, usable deployment capacity or successful failover. |
| AIGW-004 | Require effective token metric emission with a literal namespace and an Application Insights logger. This does not prove custom metrics enablement, ingestion, token accuracy or billing/chargeback completeness. |
| AIGW-005 | Explicit GraphQL APIs need effective inbound validation with positive size (at most 100 KiB) and depth limits; omitted depth uses the documented default 6. Operation-scoped placement cannot pass. Microsoft policy-reference and gateway-matrix workspace support claims conflict, so that boundary is unsupported rather than assumed healthy. Resolver field authorization is not inspected. |

Endpoint detection recognizes documented Azure OpenAI/Foundry and selected
LLM provider hostnames, not API names. Generic custom endpoints without a
recognized model URL are not positively classified as AI workloads; dynamic
or missing evidence stays unknown. Pool membership and final route overrides
are resolved within declaration namespaces. Old snapshots without endpoint
classifications can be replayed but cannot manufacture AI coverage.

The roadmap groups unwaived confirmed failures deterministically by severity:
Critical/High in 0-30 days, Medium in 30-60, Low/Advisory in 60-90+. These are
planning heuristics, not effort estimates, assigned owners or delivery
commitments. Unknown/unsupported evidence remains visible in the explorer.

### Optional executive commentary

`analyze --enrich-ai --config assessment.yaml` and `assess --enrich-ai` opt in
to a remote narrative. Configuration alone never enables it. Azure OpenAI
uses the configured public-cloud endpoint/deployment and chat completions
`2024-10-21`; provide an API key through the named environment variable or
use `DefaultAzureCredential` with inference access. An `openai_compatible`
base endpoint (typically ending in `/v1`) requires the named key environment
variable. Never place keys in YAML, arguments or committed files. Use a
compatible non-reasoning chat deployment supporting JSON mode, temperature
and max_tokens; model feature differences surface as explicit errors.

Only aggregate counts grouped by public rule ID, pillar, severity, outcome
and waiver presence are transmitted. No identifiers, API paths, policies,
evidence, waiver text or customer data are sent. The bounded plain-text
response is saved separately as **unverified portfolio commentary**;
it cannot change findings, evidence, applicability, severity or scores.
No automatic retry incurs extra inference requests. Failed/refused/truncated
enrichment records a safe error, saves deterministic artifacts, and exits 2
(`assess` also renders the report). Offline `report` never calls AI.

### Container

```powershell
docker build --tag apim-assess:local .
docker run --rm --network none apim-assess:local --help
docker run --rm --network none -v "${PWD}\tests\fixtures:/input:ro" -v "${PWD}\output:/output" apim-assess:local analyze --snapshot /input/sample_multi_apim_snapshot.json --output /output/findings.json
docker run --rm --network none -v "${PWD}\tests\fixtures:/input:ro" -v "${PWD}\output:/output" apim-assess:local report --snapshot /input/sample_multi_apim_snapshot.json --findings /output/findings.json --output /output/report.html
```

The multi-stage image runs as non-root UID/GID 10001, with no build tools,
source fixtures or credentials copied into the runtime. Grant the output
mount appropriate host permissions. Collection can use workload identity or
service-principal environment variables supported by DefaultAzureCredential;
do not bake credentials into images. A host Azure CLI token-cache mount
alone is insufficient: this minimal image deliberately does not install
Azure CLI. Relative default outputs are `output/...` under the container's
`/output` working directory; use explicit absolute output paths as above.
CI builds the image and replays analysis/reporting with networking disabled.

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
the three local artifacts. In addition to APIM read access, enabled modules
need read access to linked networking, diagnostic settings, subscription
autoscale/Defender plan, service API collections and Policy Insights states.
Optional KQL requires query access to linked workspaces. Optional upstream
discovery/probing needs scoped Resource Graph access and read permission on
AFD/AppGW, their linked WAF policies and any inspected NSGs/subnets.
Optional AI enrichment needs inference permission on the explicitly
configured deployment. Permission gaps
are expected structured evidence, not a reason to grant write access.
Do not retrieve keys or change resource
configuration to unblock collection. Live verification is a separate
acceptance gate; a PR without it stays draft.
