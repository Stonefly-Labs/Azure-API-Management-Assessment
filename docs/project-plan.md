# Azure API Management Assessment & Inspection Tool (`apim-assess`) — Project Plan

## 1. Repository Structure & Module Layout

```text
Apim-AssessmentV2/
├── docs/
│   ├── project-scope.md              # Architecture, requirements & scope specification
│   └── project-plan.md               # Implementation roadmap, rule catalog & verification plan
├── pyproject.toml                    # Python package metadata, dependencies & CLI entrypoint
├── Dockerfile                        # Containerized CLI packaging (supports mounted ~/.azure)
├── assessment.example.yaml           # Annotated sample configuration file
├── src/
│   └── apim_assess/
│       ├── __init__.py
│       ├── cli.py                    # Typer CLI: collect, analyze, report, assess, demo
│       ├── config.py                 # Pydantic config models (CLI flags + assessment.yaml merge)
│       ├── models/
│       │   ├── __init__.py
│       │   ├── snapshot.py           # Typed data models for 1-N APIM instances & adjacent signals
│       │   ├── policy.py             # XML Policy AST & Effective Policy resolution models
│       │   └── findings.py           # Rule metadata, Finding, PillarScore, PortfolioAssessment
│       ├── collector/
│       │   ├── __init__.py
│       │   ├── discovery.py          # 1-N Subscription/RG Resource Graph & ARM discovery
│       │   ├── apim_core.py          # Async ARM & REST collector for APIM + child resources
│       │   ├── networking.py         # VNet, Subnet, NSG, Private Endpoint & Public IP collector
│       │   ├── telemetry.py          # Azure Monitor Metrics + optional Log Analytics KQL queries
│       │   ├── governance.py         # Defender for APIs, Azure Policy & Autoscale collector
│       │   ├── upstream_afd.py       # Optional Azure Front Door auto-discovery & route/WAF probe
│       │   ├── upstream_appgw.py     # Optional Application Gateway auto-discovery & pool/WAF probe
│       │   └── sanitizer.py          # Default-on secret masking & XML inline-secret scrubber
│       ├── analyzer/
│       │   ├── __init__.py
│       │   ├── policy_resolver.py    # Global -> Workspace -> Product -> API -> Operation + fragments
│       │   ├── engine.py             # Hybrid YAML catalog loader, waiver/profile handler & scorer
│       │   ├── evaluators/
│       │   │   ├── __init__.py
│       │   │   ├── reliability.py    # WAF Reliability rule evaluators
│       │   │   ├── security.py       # WAF Security & MCSB control evaluators
│       │   │   ├── cost.py           # WAF Cost Optimization evaluators
│       │   │   ├── operations.py     # WAF Operational Excellence evaluators
│       │   │   ├── performance.py    # WAF Performance Efficiency evaluators
│       │   │   ├── policy_checks.py  # Effective XML policy & OWASP API Top 10 evaluators
│       │   │   └── ai_gateway.py     # GenAI / Azure OpenAI / LLM workload evaluators
│       │   └── ai_narrator.py        # Deterministic executive synthesis + optional LLM enrichment
│       ├── rules/
│       │   ├── reliability.yaml
│       │   ├── security_mcsb.yaml
│       │   ├── cost_optimization.yaml
│       │   ├── operational_excellence.yaml
│       │   ├── performance_efficiency.yaml
│       │   └── ai_gateway_modern.yaml
│       └── reporting/
│           ├── __init__.py
│           ├── generator.py          # Renders PortfolioAssessment + Snapshot into single-file HTML
│           └── templates/
│               └── report_deck.html.j2  # Zero-CDN Dual-Mode Slide Deck + Deep-Dive Explorer
└── tests/
    ├── fixtures/
    │   └── sample_multi_apim_snapshot.json  # Realistic multi-instance snapshot (Prod + Non-Prod + AI GW)
    ├── test_sanitizer.py
    ├── test_policy_resolver.py
    ├── test_rule_engine.py
    ├── test_reporting.py
    └── test_cli.py
```

---

## 2. Initial Rule Catalog Specification (WAF + MCSB + Modern APIM)

The hybrid rule engine ships with **45+ rules** mapped across the 5 WAF Pillars and MCSB controls:

### 2.1 Reliability (`REL`) & MCSB `BR-1`
| Rule ID | Title | WAF / MCSB | Prod Severity | Non-Prod Behavior | Signal Source |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `APIM-REL-001` | Production workload running on SLA-less Developer tier | REL | Critical | Advisory | Service SKU |
| `APIM-REL-002` | Zone redundancy disabled in primary or secondary regions | REL | High | Downgrade / SKU-Aware | `sku` + `zones` + `additionalLocations` |
| `APIM-REL-003` | Single scale unit deployed without high-availability redundancy | REL | High | Advisory | `sku.capacity` |
| `APIM-REL-004` | Autoscale not configured for gateway scale units | REL / PERF | High | Low | `Microsoft.Insights/autoscalesettings` |
| `APIM-REL-005` | Multi-region secondary location lacks custom autoscale alerting | REL | Medium | N/A | `additionalLocations` + Monitor Alerts |
| `APIM-REL-006` | Single-region topology for critical production gateway | REL | Medium | N/A | `additionalLocations` |
| `APIM-REL-007` | Backend resources lack circuit breaker configuration | REL | Medium | Low | `backends[].properties.circuitBreaker` |
| `APIM-REL-008` | Multi-endpoint backend calls not using load-balanced Backend Pools | REL / OPS | Medium | Low | `backends` (`type == pool`) + policies |
| `APIM-REL-009` | APIs missing resilient `<on-error>` error handling policy | REL | Low | Low | Effective Policy (`on-error`) |
| `APIM-REL-010` | No transient fault `<retry>` or explicit backend timeout policy | REL | Low | Low | Effective Policy (`backend`/`inbound`) |
| `APIM-REL-011` | Backup / DR automation and APIOps indicators missing | REL / BR-1 | Medium | Low | Backup signals / Storage / Tags |

### 2.2 Security (`SEC`) & Microsoft Cloud Security Benchmark (`MCSB`)
| Rule ID | Title | WAF / MCSB | Prod Severity | Signal Source |
| :--- | :--- | :--- | :--- | :--- |
| `APIM-SEC-001` | APIM not deployed in a VNet and lacks Private Endpoints | SEC / NS-1, NS-2 | High | `virtualNetworkType`, `privateEndpointConnections` |
| `APIM-SEC-002` | Public network access enabled without upstream WAF or IP restriction | SEC / NS-2, NS-6 | High | `publicNetworkAccess`, AFD/AppGW probe |
| `APIM-SEC-003` | Subnet missing Network Security Group (NSG) or allows unrestricted inbound `0.0.0.0/0` | SEC / NS-1 | High | `networking` (Subnet + NSG rules) |
| `APIM-SEC-004` | Internet-facing APIM lacks upstream WAF (Front Door or App Gateway WAF in Prevention mode) | SEC / NS-6 | High | `upstream_afd` / `upstream_appgw` |
| `APIM-SEC-005` | Upstream WAF bypass possible (APIM accepts direct traffic not originating from AFD/AppGW) | SEC / NS-1, NS-6 | Critical | NSG service tags / `ip-filter` / mTLS |
| `APIM-SEC-006` | Weak TLS protocols enabled (Client or Backend TLS 1.0 / 1.1 or SSL 3.0) | SEC / DP-3 | Critical | `customProperties` + KQL runtime logs |
| `APIM-SEC-007` | Weak or deprecated TLS cipher suites enabled (3DES / RC4 / CBC) | SEC / DP-3 | High | `customProperties` |
| `APIM-SEC-008` | APIs allow unencrypted `http` or `ws` protocols | SEC / DP-3 | Critical | `apis[].properties.protocols` |
| `APIM-SEC-009` | Deprecated Direct Management REST API enabled | SEC / PA-1 | High | Management API configuration |
| `APIM-SEC-010` | Control plane `minApiVersion` below `2019-12-01` (exposes secrets to Reader role) | SEC / IM-8, PA-7 | High | `apiVersionConstraint.minApiVersion` |
| `APIM-SEC-011` | Managed Identity (System or User Assigned) not enabled on APIM | SEC / IM-3 | High | `identity` |
| `APIM-SEC-012` | Secret Named Values stored as plain APIM secrets instead of Azure Key Vault | SEC / IM-8, DP-6 | High | `namedValues` (`secret: true` without `keyVault`) |
| `APIM-SEC-013` | Non-secret configuration stored in Key Vault (unnecessary KV dependency/throttling risk) | SEC / REL | Low | `namedValues` (`secret: false` with `keyVault`) |
| `APIM-SEC-014` | Custom domain certificates not managed in Azure Key Vault or expiring within 30 days | SEC / DP-7 | High | `certificates` + `hostnameConfigurations` |
| `APIM-SEC-015` | Hardcoded secret, token, or API key detected inline within XML policy | SEC / IM-8 | Critical | Sanitizer & Policy AST scanner |
| `APIM-SEC-016` | Subscriptions scoped to All APIs (`/apis`) instead of specific Product or API | SEC / PA-7 | High | `subscriptions[].properties.scope` |
| `APIM-SEC-017` | APIs allow anonymous access (`subscriptionRequired: false` and no OAuth2/JWT/Client Cert policy) | SEC / IM-1 | Critical | `apis` + Effective Policy |
| `APIM-SEC-018` | APIs rely solely on subscription keys without OAuth 2.0 / Entra ID (`validate-jwt` / `validate-azure-ad-token`) | SEC / IM-1 | Medium | Effective Policy (`inbound`) |
| `APIM-SEC-019` | Broken policy inheritance (`<base />` omitted in API or Operation scope, bypassing Global security) | SEC / OPS | Critical | Effective Policy Resolver |
| `APIM-SEC-020` | Effective CORS policy permits wildcard origins (`<origin>*</origin>`), regardless of authentication or `allow-credentials` | SEC | High | Effective Policy (`inbound` CORS) |
| `APIM-SEC-021` | Backend TLS certificate chain/name validation disabled (`validateCertificateChain: false`) | SEC / DP-3 | High | `backends[].properties.tls` |
| `APIM-SEC-022` | Developer Portal has anonymous access or open self-service sign-up enabled without Entra ID SSO | SEC / IM-1, IM-5 | Medium | `portalsettings` / `signUp` / `identityProviders` |
| `APIM-SEC-023` | API Inspector tracing (`enableTrace`) left enabled in production diagnostics | SEC / LT-4 | Medium | `diagnostics` |
| `APIM-SEC-024` | Implementation headers (`Server`, `X-Powered-By`, `X-AspNet-Version`) not stripped in outbound policy | SEC | Low | Effective Policy (`outbound`) |
| `APIM-SEC-025` | Microsoft Defender for APIs not enabled or APIs not onboarded | SEC / LT-1 | High | `defender_policy` |

### 2.3 Cost Optimization (`COST`)
| Rule ID | Title | WAF / MCSB | Severity | Signal Source |
| :--- | :--- | :--- | :--- | :--- |
| `APIM-COST-001` | Over-provisioned SKU or scale units relative to 14-day peak capacity (< 25% peak utilization) | COST | Medium | `sku` + Monitor Metrics (`Capacity`) |
| `APIM-COST-002` | Non-production instance running on expensive Production tier (`Premium` / `Standard`) | COST | Medium | `env == non-prod` + `sku` |
| `APIM-COST-003` | Autoscale profile lacks scale-in rules for off-peak demand | COST | Medium | `autoscalesettings` |
| `APIM-COST-004` | APIs lack rate-limiting (`rate-limit` / `rate-limit-by-key`) or concurrency limits to prevent runaway load | COST / REL | High | Effective Policy (`inbound`) |
| `APIM-COST-005` | Orphaned or unused Backends, Products, Named Values, or empty Workspaces | COST / OPS | Low | Sub-resource cross-reference graph |

### 2.4 Operational Excellence (`OPS`) & MCSB `LT-4`, `AM-2`
| Rule ID | Title | WAF / MCSB | Severity | Signal Source |
| :--- | :--- | :--- | :--- | :--- |
| `APIM-OPS-001` | Azure Monitor Resource Diagnostic Settings missing or `GatewayLogs` not enabled | OPS / LT-4 | High | `Microsoft.Insights/diagnosticSettings` |
| `APIM-OPS-002` | APIs hardcode backend URLs (`set-backend-service base-url="..."` or `serviceUrl`) instead of referencing APIM Backend entities | OPS | Medium | `apis` + `backends` + Effective Policy |
| `APIM-OPS-003` | Duplicated inline policy blocks across APIs instead of reusable Policy Fragments (`<include-fragment>`) | OPS | Low | Policy AST similarity check |
| `APIM-OPS-004` | Unversioned API sprawl (multiple related APIs deployed without API Version Sets) | OPS | Low | `apis` (`apiVersionSetId`) |
| `APIM-OPS-005` | Non-compliant Azure Policy assignments detected on APIM resource | OPS / AM-2 | Medium | `defender_policy` (Policy States) |
| `APIM-OPS-006` | Self-Hosted Gateway nodes out of sync, unhealthy heartbeat, or running outdated image version | OPS / REL | High | `gateways` |

### 2.5 Performance Efficiency (`PERF`)
| Rule ID | Title | WAF / MCSB | Severity | Signal Source |
| :--- | :--- | :--- | :--- | :--- |
| `APIM-PERF-001` | High gateway capacity, CPU, or memory saturation (> 70% p95 or > 85% max) | PERF / REL | Critical | Monitor Metrics (`Capacity`, `CpuPercentage`, `MemoryPercentage`) |
| `APIM-PERF-002` | Application Insights diagnostic sampling set to 100% or `alwaysLog: allErrors` with large body logging in production | PERF / OPS | High | `diagnostics` (`sampling.percentage`, `dataMasking`/`body.bytes`) |
| `APIM-PERF-003` | `validate-content` policy buffers oversized payloads (> 100 KB) or lacks size limits on POST/PUT APIs | PERF / SEC | Medium | Effective Policy (`validate-content`) |
| `APIM-PERF-004` | High-read GET endpoints do not leverage APIM response caching (`cache-lookup` / `cache-store`) | PERF / COST | Low | Effective Policy + Operations |
| `APIM-PERF-005` | Elevated backend latency (p95 > 2,000 ms) or high 5xx gateway error rate (> 1%) | PERF / REL | High | Monitor Metrics + KQL Logs |

### 2.6 Modern Workloads & AI Gateway (`AIGW` / `MOD`)
| Rule ID | Title | WAF / MCSB | Severity | Signal Source |
| :--- | :--- | :--- | :--- | :--- |
| `APIM-AIGW-001` | Azure OpenAI / LLM API lacks token rate limiting (`azure-openai-token-limit` or `llm-token-limit`) | COST / REL / PERF | High | AI Backend detection + Effective Policy |
| `APIM-AIGW-002` | Azure OpenAI / LLM API uses static API keys instead of Managed Identity (`authentication-managed-identity`) | SEC / IM-3 | High | AI Backend + Effective Policy |
| `APIM-AIGW-003` | Single Azure OpenAI backend without load-balanced Backend Pool & 429 Circuit Breaker | REL / PERF | High | AI Backend + Backend Pool config |
| `APIM-AIGW-004` | Azure OpenAI / LLM API lacks token metric emission (`azure-openai-emit-token-metric` / `llm-emit-token-metric`) for chargeback/observability | OPS / COST | Medium | Effective Policy |
| `APIM-AIGW-005` | GraphQL API missing `<validate-graphql-request>` policy with `max-size` and `max-depth` protections | SEC / PERF | High | GraphQL API (`type == graphql`) + Effective Policy |

**Iteration 9 addition (55 implemented rules total):**

| Rule ID | Title | WAF | Prod Severity | Non-Prod Severity | Signal Source |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `APIM-AIGW-006` | MCP endpoint lacks effective OAuth token validation | SEC | High | Medium | Explicit MCP inventory + effective inbound `validate-jwt` / `validate-azure-ad-token` + policy collection coverage |

---

## 3. Incremental "Steel-Thread" Delivery Plan (Strict Phase-Gated Execution)

> **CRITICAL EXECUTION RULE — NO ONE-SHOT IMPLEMENTATION:**
> Only **ONE Iteration** may be implemented at a time. At the end of each Iteration, the agent MUST:
> 1. Verify that the CLI runs end-to-end and tests pass for that Iteration's scope only,
> 2. Commit and push the Iteration's `feature/*` branch,
> 3. Open a Pull Request to `main`, and
> 4. **STOP IMMEDIATELY** and wait for human review, testing, and merge before starting the next Iteration.

Rather than building all collectors, all rules, and the report generator horizontally in isolation, execution follows a **vertical-slice (tracer-bullet) approach** across 9 distinct PR-gated phases:

```text
Phase / PR 1 (`feature/iter-1-steel-thread`)            ──► Live Auth + Basic APIM Config & Metrics + 5 Seed Rules + Minimal HTML Deck        [STOP & PR]
Phase / PR 2 (`feature/iter-2-policy-engine`)           ──► Sub-Resources + Sanitizer + Effective XML Policy Resolver + Core Policy Rules       [STOP & PR]
Phase / PR 3 (`feature/iter-3-waf-mcsb-catalog`)        ──► Full 5-Pillar WAF & MCSB Rule Catalog + Deep-Dive Explorer & Policy Matrix        [STOP & PR]
Phase / PR 4 (`feature/iter-4-adjacent-signals`)        ──► VNet/NSG/PE + Log Analytics KQL + Defender/Policy/Autoscale Collectors            [STOP & PR]
Phase / PR 5 (`feature/iter-5-waf-ai-gateway`)          ──► Optional AFD & AppGW Probes + AI Gateway Rules + LLM Narrative + Dockerfile       [STOP & PR]
Phase / PR 6 (`feature/iter-6-focused-report`)          ──► Focused HTML Readout + Grouped Evidence + Verification Gaps + Accessible Navigation [STOP & PR]
Phase / PR 7 (`feature/iter-7-policy-secrets-and-urls`) ──► Deep Policy URL Scan + Key Vault Named Value Cross-Ref + AST Secret Scanner      [STOP & PR]
Phase / PR 8 (`feature/iter-8-telemetry-trend-charts`)  ──► 30-Day Dimensional Metric Collector + Inline SVG Trend Charts in HTML Readout     [STOP & PR]
Phase / PR 9 (`feature/iter-9-agent-gateway`)          ──► MCP & A2A Inventory + Effective Policy Inspection + MCP OAuth Security Finding     [STOP & PR]
```

### Iteration 1: End-to-End "Steel Thread" MVP (Connect, Read Config/Metrics, Render HTML)
**Goal:** Get a working CLI connecting to live Azure APIM and producing the HTML slide deck on Day 1.
1. **Scaffold & CLI (`pyproject.toml`, `cli.py`, `config.py`):**
   - Implement `apim-assess collect`, `analyze`, `report`, and `assess` commands using `DefaultAzureCredential`.
   - Support targeting 1–N APIM instances (by resource ID or Subscription/RG discovery).
2. **Minimal Live Collector (`apim_core.py`, `telemetry.py`):**
   - Fetch core APIM ARM resource properties (`sku`, `capacity`, `zones`, `additionalLocations`, `virtualNetworkType`, `customProperties`, `identity`, `publicNetworkAccess`).
   - Fetch baseline Azure Monitor Metrics (`Capacity`, `CpuPercentage`, `MemoryPercentage`, `Requests`, `Duration`).
   - Save portable `snapshot.json`.
3. **Rule Engine Skeleton + 5 Seed Rules (`engine.py`):**
   - Wire YAML rule loader + Python evaluator dispatch + Pillar Score calculator.
   - Include 5 starter service-level rules (one per WAF pillar: e.g., `APIM-REL-001` Developer SKU check, `APIM-REL-002` Zone redundancy, `APIM-SEC-001` VNet/Network posture, `APIM-COST-001` Capacity utilization, `APIM-PERF-001` Capacity/CPU saturation).
   - Output `findings.json`.
4. **Initial Self-Contained HTML Slide Deck (`report_deck.html.j2`):**
   - Render the zero-CDN HTML slide deck shell with Portfolio/Instance switcher, Cover slide, Executive Scorecard, Topology & Metrics overview, and initial Findings list.

### Iteration 2: APIM Sub-Resources, Secret Sanitizer & Effective XML Policy Engine
**Goal:** Inspect APIs, Operations, Backends, Named Values, and hierarchical XML policies safely.
1. **Sub-Resource Collection & Sanitization (`apim_core.py`, `sanitizer.py`):**
   - Collect `apis`, `operations`, `products`, `subscriptions`, `backends`, `namedValues`, `certificates`, `diagnostics`, `gateways`, `workspaces`, and all policy XMLs (`global`, `product`, `api`, `operation`, `fragments`).
   - Enable default-on secret redaction (masking Named Value secrets, backend credentials, and inline tokens in policy XML).
2. **Effective Policy Resolver (`policy_resolver.py`):**
   - Reconstruct `Global → Workspace → Product → API → Operation` policy inheritance, expand `<include-fragment>`, and detect missing `<base />`.
3. **Core Policy & API Rules + Policy Matrix Slide:**
   - Add rules for `<base />` inheritance (`APIM-SEC-019`), JWT/OAuth validation (`APIM-SEC-017`/`018`), rate limiting (`APIM-COST-004`), CORS (`APIM-SEC-020`), and hardcoded backend URLs (`APIM-OPS-002`).
   - Light up the **Effective Policy Coverage Slide & Matrix** in the HTML report.

### Iteration 3: Full WAF 5-Pillar & MCSB Rule Catalog + Deep-Dive Explorer Mode
**Goal:** Complete the core APIM rule catalog and interactive technical workbench in the HTML report.
1. **Expand Rule Catalog (`src/apim_assess/rules/*.yaml`):**
   - Add remaining APIM service and policy rules across Reliability, Security (with MCSB control mappings), Cost Optimization, Operational Excellence, and Performance Efficiency.
   - Implement `prod` vs. `non-prod` (`auto`) profile grading, rule waivers, and custom threshold overrides.
2. **HTML Deep-Dive Explorer & MCSB Matrix:**
   - Add the toggleable **Deep-Dive Explorer Mode** (instant search/filter by Pillar, MCSB Control, Severity, API, with expandable evidence & remediation drawers) and the **MCSB Compliance Matrix** slide.

### Iteration 4: Adjacent Azure Signals (Networking, Log Analytics KQL & Governance)
**Goal:** Enrich assessment accuracy with surrounding network, governance, and live log telemetry.
1. **Networking Collector (`networking.py`):**
   - Inspect VNet Subnets, NSG rules (`APIM-SEC-003`), Private Endpoints, and Public IP DDoS protection.
2. **Optional Log Analytics KQL Module (`telemetry.py`):**
   - Query `ApiManagementGatewayLogs` / `AzureDiagnostics` for live TLS 1.0/1.1 callers (`APIM-SEC-006`), 5xx backend hotspots (`APIM-PERF-005`), and cache hit ratios.
3. **Governance Collector (`governance.py`):**
   - Inspect Resource Diagnostic Settings (`APIM-OPS-001`), Autoscale rules (`APIM-REL-004`, `APIM-COST-003`), Defender for APIs (`APIM-SEC-025`), and Azure Policy compliance (`APIM-OPS-005`).

### Iteration 5: Upstream WAF Modules (`AFD` & `AppGW`), AI Gateway & Container Packaging
**Goal:** Complete upstream WAF probing, GenAI/AI Gateway workload rules, optional LLM narrative synthesis, and Docker packaging.
1. **Optional AFD & AppGW Collector Modules (`upstream_afd.py`, `upstream_appgw.py`):**
   - Auto-discover via Azure Resource Graph (or probe explicit IDs) to verify WAF Prevention mode, managed rulesets, and origin lockdown (`APIM-SEC-004`, `APIM-SEC-005`).
2. **AI Gateway & Modern Workload Rules (`ai_gateway.py`):**
   - Evaluate Azure OpenAI / LLM APIs for token rate limits (`APIM-AIGW-001`), Managed Identity (`APIM-AIGW-002`), backend pool circuit breakers (`APIM-AIGW-003`), token metrics (`APIM-AIGW-004`), and GraphQL validation (`APIM-AIGW-005`).
3. **Executive Roadmap, Optional `--enrich-ai` Narrative & `Dockerfile`:**
   - Light up the Prioritized 30/60/90-Day Remediation Roadmap slide, optional Azure OpenAI narrative enrichment, and container image build.

---

### Iteration 6: Focused HTML Readout & Report Polish
**Goal:** Adopt the layout and information hierarchy of the user-supplied
`apim-assessment-focused.html` design reference after the human merge of
Iteration 5 (#7). The reference is design input only: its embedded assessment
data must not be copied into source, fixtures, or committed artifacts.

1. **Focused default readout (`reporting/generator.py`, `report_deck.html.j2`):**
   - Replace the slide-first default with seven tabs: Overview, Findings,
     Verification gaps, Roadmap, MCSB controls, API policy coverage, and Method
     & scope. Retain optional presentation navigation, fullscreen, and theme
     switching; use the existing self-contained theme and system fonts.
   - Show a bottom-line summary, outcome/confidence bar, severity-ranked
     priorities, pillar health with explicit denominators, production-readiness
     cautions, and compact instance inventory/topology/metric cards.
2. **Rule-first findings & traceable evidence:**
   - Group results by rule, retain each instance's assessed severity, outcome,
     waiver, summary, references and evidence, and provide instance drill-down.
   - Group identical evidence details without losing source/API provenance or
     truncating affected items. Do not infer pass/fail from text tokens.
   - Combine search, pillar, severity, MCSB, affected API and outcome filters;
     match combined filters against the same instance result. Include presets,
     visible counts, empty states and links from priorities/matrices to findings.
3. **Honest verification & planning views:**
   - Surface unknown/unsupported results even when another instance fails the
     same rule. Show relevant collection warnings and no false green states.
   - Exclude waivers from confirmed-issue priorities, roadmap and score
     denominators; preserve waived outcomes and evidence for inspection.
   - Summarize API policy coverage while preserving operation/product execution
     contexts; retain MCSB mapping denominators and upstream/AI evidence limits.
4. **Acceptance & boundaries:**
   - Verify `analyze -> report` offline and mocked multi-instance `assess` replay,
     including schema 1.0-1.4 compatibility, unchanged scores and artifacts.
   - Add focused grouping/waiver/gap/escaping regressions and execute browser
     checks for tab/preset/filter drill-down, scope changes, theme, presentation,
     keyboard accessibility, narrow screens and print of the selected scope.
   - Run configured lint, formatting, typing, tests and package build. Keep all
     CSS/JS/SVG inline with no external runtime requests or unsafe HTML insertion.
   - Report-only iteration: no new rules, collectors, AI calls, schema migration,
     release, package publish, or live Azure collection is required.

---

### Iteration 7: Deep Policy URL Scanning, Key Vault Named Value Cross-Reference & Structural Secret Detection
**Goal:** Deepen policy AST and sub-resource analysis for hardcoded backend/callout URLs (`APIM-OPS-002`), unbacked secret Named Values (`APIM-SEC-012`), and inline policy secrets (`APIM-SEC-015`) while preserving strict secret sanitization and offline artifact compatibility.

1. **Hardcoded URLs in Policy Code (`APIM-OPS-002` Enhancement — `sanitizer.py`, `policy.py`, `policy_checks.py`):**
   - Add `set-url` to `sanitizer.py` `TAGS` and detect literal `http://` / `https://` URLs both in plain attributes/text and embedded inside `@(...)` / `@{...}` C# policy expressions on `<set-backend-service base-url="...">`, `<send-request>` / `<send-one-way-request>` `<set-url>`, and `<rewrite-uri>`.
   - Fix `backend_routes()` in `analyzer/evaluators/policy.py` so non-routing `OPAQUE` policies (`cache-lookup`, `ip-filter`, `check-header`, `retry`, `send-request`) do not overwrite a known `LITERAL_URL` route with `DYNAMIC`/`unknown`.
   - Scan policy and fragment ASTs directly so hardcoded backend and callout URLs in any scope (`global`, `workspace`, `product`, `api`, `operation`, `fragment`) are surfaced with exact scope, section, and policy element evidence.
2. **Secret Named Values Not Backed by Key Vault (`APIM-SEC-012` Enhancement — `subresources.py`, `sanitizer.py`, `service_checks.py`):**
   - Record hashed Named Value identifiers and capture `{{named-value}}` token references across collected policies and fragments during sanitization.
   - Enhance `named_secrets` (`APIM-SEC-012`) to emit focused failure evidence for each `secret: true, keyVault: null` Named Value (including resource path, service vs. workspace scope, and how many policies/APIs reference it) without retrieving secret values.
3. **Structural + Pattern Secret Scanner in Policy Code (`APIM-SEC-015` Enhancement — `sanitizer.py`, `models/policy.py`, `policy_checks.py`):**
   - Before scrubbing attributes and text to `<REDACTED_SECRET>`, inspect both regex patterns (`SECRET_PATTERN`) and structural XML context for literal secrets (excluding `{{named-value}}` references):
     - `<authentication-basic>` with a literal `password` attribute.
     - `<set-header>` for sensitive headers (`Authorization`, `Ocp-Apim-Subscription-Key`, `x-api-key`, `api-key`, `x-functions-key`, `Proxy-Authorization`) with a literal `<value>`.
     - `<set-query-parameter>` for sensitive query keys (`key`, `api-key`, `api_key`, `code`, `sig`, `token`, `client_secret`) with a literal `<value>`.
     - `<validate-jwt>` with inline `<issuer-signing-keys><key>` or `<decryption-keys><key>` literals instead of `certificate-id` or `{{named-value}}`.
     - Inline Bearer tokens, JWTs (`eyJ...`), SAS tokens (`sig=`), connection strings, and credential assignments inside `<set-variable>`, `<set-body>`, or C# expressions.
   - Persist secret-free location breadcrumbs on `PolicyDocument` (e.g., `inbound/set-header[name=authorization]: literal secret value`) so `APIM-SEC-015` pinpoints the exact policy, section, and XML element to remediate.
4. **Acceptance & boundaries:**
   - Maintain backward compatibility with existing `snapshot.json` schemas (`1.0`–`1.4`).
   - Add unit tests in `tests/test_sanitizer.py`, `tests/test_policy_resolver.py`, and `tests/test_rule_engine.py` covering new URL/secret AST patterns, `{{named-value}}` false-positive guards, and `OPAQUE` policy route resolution.

---

### Iteration 8: 30-Day Dimensional Telemetry & Interactive SVG Trend Charts
**Goal:** Collect 30-day dimensional Azure Monitor metrics and render self-contained, zero-CDN inline SVG trend charts in the HTML assessment readout.

1. **30-Day Dimensional Metric Collection (`config.py`, `collector/telemetry.py`, `models/snapshot.py`):**
   - Update `Telemetry.lookback_days` default from `14` to `30` days.
   - Extend `collect_metrics()` against `Microsoft.Insights/metrics` to collect 30-day time-series data for:
     - **Gateway Utilization:** `Capacity` (`Average`, plus `Maximum` on Premium, split by `Location`) for Classic tiers (`Developer`, `Basic`, `Standard`, `Premium`), or `CpuPercent_Gateway` and `MemoryPercent_Gateway` (`Average, Maximum`) for v2 tiers (`BasicV2`, `StandardV2`, `PremiumV2`).
     - **Request Volume by Status Code:** `Requests` (`Total`) split by `$filter="GatewayResponseCodeCategory eq '*'"` (`2xx`, `3xx`, `4xx`, `5xx`).
     - **Request Volume by API:** `Requests` (`Total`) split by `$filter="ApiId eq '*'"` (bounded to top APIs).
     - **Backend Latency by API:** `BackendDuration` (`Average, Maximum` in milliseconds) split by `$filter="ApiId eq '*'"` (supplemented by `log_analytics` per-API latency when KQL is enabled).
   - Extend `MetricSeries` with optional dimension metadata while preserving compatibility with existing `1.0`–`1.4` snapshots.
2. **Self-Contained Inline SVG Trend Charts (`reporting/generator.py`, `templates/report_deck.html.j2`):**
   - Roll up 30-day time-series points in `generator.py` and render a 4-panel **30-Day Telemetry & Trends** visual grid using zero-CDN inline SVG charts:
     1. **Gateway Capacity (Classic) or CPU & Memory (v2) 30-Day Trend** (with `70%` warning and `85%` saturation reference lines).
     2. **Request Volume by HTTP Status Code Category (`2xx` / `3xx` / `4xx` / `5xx`)**.
     3. **Request Volume by Top APIs**.
     4. **Backend Latency (`BackendDuration` Avg / Max ms) by API** (with the `2,000 ms` threshold reference line).
   - Support portfolio vs. per-instance scope switching, dark/light themes, accessible labels/tables, and clean print rendering.
3. **Acceptance & boundaries:**
   - Verify offline `analyze -> report` and mocked `assess` replay across Classic and v2 instances, partial/unavailable metric states, and legacy snapshots without dimensional series.
   - Keep all CSS, JS, and SVG inline with zero external runtime requests.

---

### Iteration 9: MCP & A2A AI Gateway Capabilities, Policies & OAuth Posture
**Goal:** Surface native MCP servers and A2A agent APIs as first-class assessment
resources, inspect their effective policies with the same evidence discipline as
REST APIs, and flag MCP endpoints without configured OAuth token validation.

**Status and gate:** Implemented after the human merge of Iteration 8 and explicit
advancement request. Delivery remains subject to the verification checklist
below and human review/merge; this iteration does not authorize another phase.

**Implemented contract and limits:** Native discovery, metadata and policies use
`2025-09-01-preview`; ordinary resource reads retain `2024-05-01`. The A2A
discriminator/projection follows Microsoft's APIOps ARM sample linked below
because the published REST schema does not yet expose the full A2A shape.
Snapshots/findings advance to `1.5`, preserving historical `1.0`-`1.4` replay.
MCP server and A2A entry points use verified global/API inheritance. A2A operation
policies are retained separately, not credited as entry-point protection without
verified execution semantics. Workspace execution is unsupported; product execution remains
unresolved instead of inheriting REST assumptions. Passthrough tool lists are
management-plane metadata, not data-plane discovery. Generic caller-auth rules
remain separate from the stricter MCP OAuth rule and each rule scores once per
instance, not once per tool. No new MCSB mapping is inferred.

1. **Capability-aware discovery and sanitized collection:**
   - Pin an authoritative management API contract that exposes MCP resources
     (`2025-09-01-preview` or a verified later version). Confirm the published A2A
     resource discriminator and API version before implementing its projection.
     Do not infer native MCP/A2A types from API names, URL substrings or AI backends.
   - Discover both REST-backed and passthrough MCP servers; collect their tool
     sub-resources, backing API/operation references and safe transport metadata.
     Collect A2A agent APIs and safe agent-card/runtime linkage metadata exposed
     by the management plane. Do not treat MCP tools as ordinary API operations.
   - Keep ordinary API collection intact and track modern inventory and policy
     coverage separately. Preview denial, unsupported scopes, malformed metadata,
     pagination gaps or older API-version fallback must not become "zero MCP/A2A
     resources" or complete coverage. Preserve unrecognized resource types as an
     explicit coverage gap rather than silently dropping them.
   - Verify SKU, gateway and workspace support from current documentation at
     implementation time. The documented MCP workspace limitation is unsupported,
     not evidence of an unprotected or absent server.
   - Use read-only management operations only. Never invoke MCP tools, perform
     A2A tasks, follow arbitrary agent-card URLs, retrieve assessed subscription
     keys or backend/user tokens, or persist raw credentials, backend URLs,
     tool schemas/descriptions or agent-card payloads.

2. **Effective policy inspection and existing rule integration:**
   - Collect MCP server and A2A API XML policies and inspect applicable inherited
     global/product/workspace policies only where those scopes are documented as
     supported. Honor actual execution order, `<base />` placement, fragments and
     conditional paths; do not assume REST scope semantics automatically apply.
   - For REST-backed MCP tools, retain the link to the backing REST API/operation
     and inspect that boundary separately. A validator on one backing operation
     is not proof that every MCP entry point or tool is protected.
   - Reuse existing caller-authentication, rate/concurrency, secret/URL, transport
     and inheritance checks where protocol support and evidence justify them.
     Unsupported request/body/streaming behavior must not cause false REST-based
     passes or failures. Do not apply LLM token policies solely because an API is
     MCP/A2A. A2A policy inspection is required, not just an inventory label.

3. **New rule `APIM-AIGW-006`: MCP OAuth token validation:**
   - **Decision:** Every assessed MCP entry point requires effective incoming
     token validation using the correctly named `validate-jwt` or
     `validate-azure-ad-token` policy. Check a meaningful validator configuration,
     not tag presence, with issuer/tenant, signature/expiry and audience/client
     restrictions as appropriate to the selected policy and issuer.
   - A configured, unconditional validator covering every applicable known
     execution context establishes a configuration pass. Inherited or
     fragment-provided validation may count if it remains effective. Merely
     placing validation inside one branch cannot establish complete protection.
   - With complete applicable policy evidence, a confirmed unprotected MCP path
     yields `fail`: High in production and Medium in non-production. The report
     must display the security warning/error and remediation, for example:
     **"MCP should be secured using OAuth 2.0. No effective validate-jwt or
     validate-azure-ad-token policy was found for this MCP endpoint."**
   - Missing permissions, unresolved fragments/conditions, incomplete inventory
     or unavailable policy evidence yield `unknown` with a collection/coverage
     warning, never a pass or a claim that validation is absent. Unsupported
     capabilities and non-MCP contexts remain distinct from that result.
   - Subscription keys, client-certificate validation, developer-portal OAuth
     settings, forwarded Authorization headers, backend OAuth credentials and
     `authentication-managed-identity` do not satisfy this incoming OAuth check.
     They can be additional controls, not proof of caller token validation.
   - This is the requested assessment baseline, stronger than Microsoft's
     supported key-only option. Recommend provider-appropriate OAuth 2.0 token
     validation and the current MCP OAuth 2.1 flow where applicable; do not claim
     to certify OAuth discovery, PKCE, consent or authorization-server behavior.
     Backend-enforced authentication remains separate, unverified evidence.
   - Emit sanitized server/tool-context evidence, business impact, remediation
     and Microsoft references. Honor waivers and severity overrides. Reuse
     existing scoring, avoid scoring the same rule repeatedly per tool, and
     explain overlap with generic authentication findings. Use WAF SEC; add an
     MCSB mapping only if separately grounded.

4. **Readout and portable artifacts:**
   - Show distinct MCP/A2A counts, resource types, tools/backing relationships,
     transports where collected, policy controls and verification gaps in the
     existing portfolio/per-instance views. Surface OAuth findings in Findings,
     Roadmap and policy coverage, with precise resource evidence.
   - Preserve zero-CDN rendering, escaping, accessibility, themes and print
     behavior. No report redesign, AI call or external runtime dependency.
   - Extend snapshot/findings contracts explicitly and minimally. Keep saved
     historical schemas `1.0`-`1.4`, digests and historical rule interpretations
     replayable; old snapshots without MCP/A2A collection show "not collected."

5. **Acceptance and boundaries:**
   - Add synthetic mixed REST/MCP/A2A, Classic/v2 and multi-instance fixtures.
     Cover pagination, denied/unsupported preview reads, unknown types, actual
     tool bindings, and A2A policy collection without invoking data-plane APIs.
   - Through the real catalog/dispatch path, test both token-validation policies,
     inherited/fragment validators, confirmed absence, subscription-key-only and
     backend-managed-identity-only cases, branch gaps, broken inheritance,
     unavailable policies, non-MCP applicability, waivers and severity overrides.
   - Exercise offline `analyze -> report` and mocked `assess` replay; confirm
     identities, policy evidence, findings, scores and report coverage agree.
     Run configured lint, formatting, typing, tests, package and container checks.
   - Run a separately identified live smoke test only on authorized targets;
     report unavailable A2A examples honestly rather than synthesizing live
     evidence. Never commit live artifacts or create/modify assessed resources.
   - No release, resource remediation, general MCP client, A2A task runner,
     prompt-injection scanner or unrelated catalog expansion.

**Microsoft grounding (verified for implementation):**
- [MCP resource model and management API](https://learn.microsoft.com/en-us/azure/api-management/manage-mcp-servers-rest-api)
- [MCP capabilities and limitations](https://learn.microsoft.com/en-us/azure/api-management/mcp-server-overview)
- [Secure inbound and outbound MCP access](https://learn.microsoft.com/en-us/azure/api-management/secure-mcp-servers)
- [A2A API capabilities and policy scope](https://learn.microsoft.com/en-us/azure/api-management/agent-to-agent-api)
- [Microsoft APIOps A2A ARM contract example](https://github.com/Azure/apiops-cli/blob/main/tests/integration/all-resource-types/bicep/source-apim.bicep)
- [Validate JWT policy](https://learn.microsoft.com/en-us/azure/api-management/validate-jwt-policy)
- [Validate Microsoft Entra token policy](https://learn.microsoft.com/en-us/azure/api-management/validate-azure-ad-token-policy)

---

### Iteration 10 — Repeatable Azure Validation Lab & Lifecycle Automation

**Goal:** Deliver an end-to-end, repeatable Azure validation lab (`westus3`) with paired APIM instances (Internal VNet Developer + Public Basic v2), Microsoft Foundry model deployments, Entra-authenticated Python Container Apps (REST, MCP, A2A), automated OIDC bootstrap, and GitHub Actions deploy/validate/destroy workflows that exercise and verify all 55 `apim-assess` rules.

1. **Identity & OIDC Bootstrap (`infra\lab\bootstrap.bicep`, `scripts\lab\bootstrap.py`):**
   - Provision persistent `rg-apv-bootstrap-wus3-001` with user-assigned managed identities (`id-apv-gh-deploy-wus3-001`, `id-apv-gh-assess-wus3-001`), GitHub Actions OIDC federated credentials scoped to `azure-lab`, and least-privilege RBAC on `rg-apv-bootstrap-wus3-001` and `rg-apv-lab-wus3-001`.
   - Provision or update Microsoft Entra ID application registrations (`app-apv-mcp-api`, `app-apv-a2a-api`, `app-apv-lab-client`) with app roles and service principals for client-credentials JWT acquisition.
   - Sync non-secret configuration variables to the GitHub `azure-lab` environment.
2. **Paired APIM, Foundry, and Container Apps Infrastructure (`infra\lab\`, Azure Verified Modules):**
   - Author Bicep templates using pinned Azure Verified Modules (`br/public:avm/res/...`) wherever available, falling back to direct ARM resources only where AVM does not expose required preview schemas (such as `Microsoft.ApiManagement/service/apis@2025-09-01-preview` for native MCP/A2A and `/tools` or `Microsoft.CognitiveServices/accounts/projects`).
   - Deploy VNet (`vnet-apv-lab-wus3-001`) with `snet-apim-dev` (NSG satisfying `APIM-SEC-003`), `snet-aca`, and private DNS (`azure-api.net` scoped record for the internal Developer gateway).

   - Deploy Internal VNet `Developer` APIM (`apim-apv-dev-wus3-001`) and public `BasicV2` APIM (`apim-apv-bv2-wus3-001`), Log Analytics, Application Insights, ACR, private Storage Account (`assessment-runs`), and purge-capable Key Vault.
   - Deploy Microsoft Foundry account (`ais-apv-lab-wus3-001`), project (`proj-apv-lab-wus3-001`), and `GlobalStandard` deployments (`gpt-5.6-sol`, `gpt-5.4-mini`, `text-embedding-3-small`).
   - Build and deploy Python Container Apps (`samples\validation_lab\`) for the Orders REST API (with OpenAPI 3.0 spec), Streamable HTTP MCP server (with Entra JWT auth), and JSON-RPC A2A agent (with Entra JWT auth), plus VNet-connected smoke and assessment Container Apps Jobs.
3. **Paired APIM Configuration Profiles (`infra\lab\modules\apim-config-*.bicep`):**
   - Configure both APIM instances with the Orders REST API, REST-backed MCP API, passthrough MCP API, A2A Agent API, and Foundry Responses API (`/openai/v1/responses`), alongside backends, backend pools, Named Values, and policy fragments.
   - Apply the intentional negative profile on `apim-apv-dev-wus3-001` and the healthy baseline profile on `apim-apv-bv2-wus3-001` so all 55 catalog rules are deterministically exercised and verified against `samples\validation_lab\expectations.yaml`.
4. **Validation, Scoped Teardown & Workflows (`scripts\lab\`, `.github\workflows\lab-*.yml`):**
   - Execute VNet-internal smoke traffic and `apim-assess collect -> analyze -> report` inside Container Apps Jobs, upload sanitized artifacts (`snapshot.json`, `findings.json`, `apim-assessment-report.html`) to private Blob Storage, and assert all 55 rule outcomes per instance without exposing sensitive identifiers in public GitHub logs.
   - Provide `scripts\lab\destroy.py` and `lab-destroy.yml` to delete all billable lab resources inside `rg-apv-lab-wus3-001` and purge Key Vault, Foundry, and APIM soft-delete tombstones while preserving `rg-apv-bootstrap-wus3-001` for zero-touch redeployment.

---

## 4. Development & Git / PR Workflow


All development on `apim-assess` strictly follows a branch-and-PR workflow with human-gated merges:

1. **No Direct Work on `main`:**
   - Never commit directly to `main` (beyond initial repository bootstrap if required).
   - All changes must happen on dedicated branches named by category:
     - `feature/<short-name>` (e.g., `feature/iteration-1-steel-thread`, `feature/effective-policy-resolver`)
     - `bugfix/<short-name>` (e.g., `bugfix/xml-fragment-recursion`)
     - `chore/<short-name>` (e.g., `chore/project-docs-and-plan`)
2. **Frequent, Runnable/Buildable Commits:**
   - The coding agent commits logically cohesive, runnable, and buildable increments frequently on the active branch.
   - Each Iteration in Section 3 is delivered on its own feature branch with passing tests and a verified runnable CLI before opening a PR.
3. **Pull Requests Opened by Agent — Strict Human Merge & Phase Gate:**
   - When a single Iteration/Phase is ready, the coding agent pushes the branch, opens a Pull Request (`gh pr create`) summarizing the changes and verification steps, and **STOPS**.
   - **Never implement multiple Iterations in one shot.** The agent must wait until the current Iteration's PR is reviewed and merged by a human (and the human prompts to begin the next Iteration).
   - **The coding agent MUST NEVER merge a Pull Request.** All PR merges require human review and explicit human merge action.

