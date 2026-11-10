# apim-assess

Read-only Azure API Management assessment CLI. **Iteration 1 only**: core
service configuration, baseline Azure Monitor metrics, five deterministic
seed rules, and a self-contained HTML slide deck.

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
are split by Location. No raw policy, named value, backend credential,
certificate, publisher contact, arbitrary tag or raw response body is saved.
Safe typed metadata is projected before persistence. Errors retain stable
codes, never raw response bodies or credential exception text.

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
HTML file locally; its portfolio/instance selector, four slides, keyboard
navigation and theme toggle need no external runtime assets. Learn reference
links are optional outbound navigation, not runtime dependencies.

## Assessment decisions and limits

The plan says "one per pillar" but names **two REL rules and no OPS rule**.
This iteration preserves exactly the five named stable IDs; OPS is shown
as not assessed. No full MCSB compliance, policy coverage or overall health
score is claimed.

| Rule | Decision and evidence boundary |
| --- | --- |
| APIM-REL-001 | Developer is a Critical production finding, Advisory in non-production. Other known SKUs pass this specific check. |
| APIM-REL-002 | Classic Premium with an explicitly single-zone region fails; all collected regions explicitly selecting multiple zones with consistent unit counts pass the configuration check. Empty/missing zone lists are unknown because current Microsoft guidance supports automatic placement. Unsupported SKUs are distinct from passes; v2 zone state remains unknown with this ARM projection. |
| APIM-SEC-001 | Classic VNet injection or an approved inbound private endpoint satisfies this configuration check. External classic injection does not prove private-only access. Outbound-only v2 integration is not inbound isolation. Missing mode/connection evidence is unknown. NS-1/NS-2 mappings describe partial evidence, not control certification. |
| APIM-COST-001 | Peak hourly average Capacity below 25% triggers a review, only with at least 14 complete days of hourly evidence for every region. At 25% the trigger does not fire. Classic Basic/Standard/Premium only; Developer/Consumption not applicable; v2 unsupported. |
| APIM-PERF-001 | Nearest-rank p95 of hourly averages above 70%, or a v2 CPU/memory maximum above 85%, triggers investigation. Threshold equality does not fail. Incomplete evidence can establish a high-load finding but cannot establish a healthy pass. Classic Capacity Maximum is not used. |

These are assessment heuristics, not autoscale actions. Hourly averages can
hide shorter peaks; their p95 is not a request latency percentile. Right-sizing
requires representative workload tests and redundancy planning. A full
history is necessary to disprove observed low utilization or saturation.
Unknown, unsupported and not-applicable results are excluded from weighted
scores and counted separately. No applicable evaluated controls means a
null score, not 100. Weights: Critical=5, High=4, Medium=3, Low=2, Advisory=1.

Current authoritative grounding (reviewed 2026-11-10):

- [APIM reliability and tier/zone capabilities](https://learn.microsoft.com/en-us/azure/reliability/reliability-api-management)
- [Capacity and scaling guidance](https://learn.microsoft.com/en-us/azure/api-management/api-management-capacity)
- [Supported metric REST names and aggregations](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-metrics/microsoft-apimanagement-service-metrics)
- [Networking capabilities by tier](https://learn.microsoft.com/en-us/azure/api-management/virtual-network-concepts)
- [Core ARM resource contract, 2024-05-01](https://learn.microsoft.com/en-us/rest/api/apimanagement/api-management-service/get?view=rest-apimanagement-2024-05-01)
- [MCSB APIM baseline](https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/api-management-security-baseline) (Microsoft flags this v1 baseline as potentially outdated; current service networking guidance governs capability decisions).

Future iterations add XML/sub-resources, the rest of the catalog, rule
waivers/threshold overrides, adjacent signals, richer reporting, AI gateway
analysis and Docker. These options are not stubbed or silently accepted.

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
