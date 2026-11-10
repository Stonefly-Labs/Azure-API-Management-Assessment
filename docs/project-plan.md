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
| `APIM-SEC-020` | Overly permissive CORS policy (`<origin>*</origin>` combined with `allow-credentials="true"` or on authenticated APIs) | SEC | High | Effective Policy (`inbound` CORS) |
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

---

## 3. Incremental "Steel-Thread" Delivery Plan (Strict Phase-Gated Execution)

> **CRITICAL EXECUTION RULE — NO ONE-SHOT IMPLEMENTATION:**
> Only **ONE Iteration** may be implemented at a time. At the end of each Iteration, the agent MUST:
> 1. Verify that the CLI runs end-to-end and tests pass for that Iteration's scope only,
> 2. Commit and push the Iteration's `feature/*` branch,
> 3. Open a Pull Request to `main`, and
> 4. **STOP IMMEDIATELY** and wait for human review, testing, and merge before starting the next Iteration.

Rather than building all collectors, all 46 rules, and the report generator horizontally in isolation, execution follows a **vertical-slice (tracer-bullet) approach** across 5 distinct PR-gated phases:

```text
Phase / PR 1 (`feature/iter-1-steel-thread`)     ──► Live Auth + Basic APIM Config & Metrics + 5 Seed Rules + Minimal HTML Deck  [STOP & PR]
Phase / PR 2 (`feature/iter-2-policy-engine`)    ──► Sub-Resources + Sanitizer + Effective XML Policy Resolver + Core Policy Rules [STOP & PR]
Phase / PR 3 (`feature/iter-3-waf-mcsb-catalog`) ──► Full 5-Pillar WAF & MCSB Rule Catalog + Deep-Dive Explorer & Policy Matrix  [STOP & PR]
Phase / PR 4 (`feature/iter-4-adjacent-signals`) ──► VNet/NSG/PE + Log Analytics KQL + Defender/Policy/Autoscale Collectors      [STOP & PR]
Phase / PR 5 (`feature/iter-5-waf-ai-gateway`)   ──► Optional AFD & AppGW Probes + AI Gateway Rules + LLM Narrative + Dockerfile [STOP & PR]
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

