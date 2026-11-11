# Azure API Management Well-Architected & Security Assessment Tool (`apim-assess`) — Project Scope

## 1. Executive Summary & Vision

`apim-assess` is an automated live inspection, analysis, and executive readout tool for **Azure API Management (APIM)**—grounded across **all five Azure Well-Architected Framework (WAF) pillars** and the **Microsoft Cloud Security Benchmark (MCSB)** baseline for APIM.

The tool inspects **1 to N live APIM instances** (along with surrounding networking, telemetry, policy compliance, and upstream WAF infrastructure), evaluates both control-plane configuration and **effective XML policy trees**, and produces a **self-contained, AI-era interactive HTML slide deck and findings explorer** alongside structured JSON artifacts.

---

## 2. Best-Practice Grounding & Standards

All assessment rules and recommendations are grounded in authoritative Microsoft documentation:

1. **Azure Well-Architected Framework (WAF) Service Guide for APIM**
   - **Reliability (`REL`):** Zone redundancy, multi-unit & multi-region topologies, autoscale, backend pools & circuit breakers, retry/timeout policies, `<on-error>` resilience, backup/restore & APIOps readiness.
   - **Security (`SEC`):** Network isolation (VNet injection/integration, Private Link, NSGs), upstream WAF (Azure Front Door / Application Gateway), TLS 1.2/1.3 & cipher suites, Managed Identity, Key Vault-backed Named Values & Certificates, OAuth2/JWT validation (`validate-jwt`), subscription scoping, disabling direct management API & anonymous developer portal access, production tracing disabled, header suppression, OWASP API Top 10 mitigations.
   - **Cost Optimization (`COST`):** SKU/tier right-sizing (Classic vs. v2, Prod vs. Non-Prod), scale-in rules, built-in caching utilization, early malicious traffic filtering (WAF/DDoS/rate limits), unused workspace/API cleanup.
   - **Operational Excellence (`OPS`):** Azure Monitor diagnostic settings (`GatewayLogs`, `WebSocketConnectionLogs`), Application Insights sampling balance, backend abstraction (`set-backend-service` vs. hardcoded URLs), API versioning/revisions, Azure Policy governance, Event Grid lifecycle automation, Self-Hosted Gateway sync/version health.
   - **Performance Efficiency (`PERF`):** Capacity/CPU/Memory headroom, autoscale elasticity, response/semantic caching, payload validation size caps (`validate-content`), connection pooling, App Insights sampling overhead.
2. **Microsoft Cloud Security Benchmark (MCSB) for APIM**
   - Explicit mapping to MCSB controls: `NS-1` (VNet & NSG segmentation), `NS-2` (Private Link & public access restriction), `NS-6` (WAF integration), `IM-1` (Entra ID authentication), `IM-3` (Managed Identities), `IM-5` (Developer Portal SSO), `IM-8` (Key Vault secret storage & minimum API version), `PA-1` (Local admin/user account restriction), `PA-7` (RBAC & subscription scoping), `DP-3` (HTTPS/WSS encryption in transit & TLS hardening), `DP-6` (Key management in Key Vault), `DP-7` (Certificate management in Key Vault), `AM-2` (Azure Policy enforcement), `LT-1` (Microsoft Defender for APIs), `LT-4` (Resource diagnostic logs), and `BR-1` (Service backup/DR).
3. **Modern APIM & AI Gateway Workloads**
   - **v2 Tiers (`Basic v2`, `Standard v2`, `Premium v2`):** VNet integration vs. injection semantics, feature parity checks, and scaling characteristics.
   - **AI Gateway / GenAI Patterns (`AIGW`):** Detection of Azure OpenAI / LLM backends and validation of `azure-openai-token-limit` / `llm-token-limit`, `azure-openai-emit-token-metric`, semantic caching, Managed Identity backend auth, and load-balanced backend pools with circuit breakers for 429 resiliency.
   - **MCP & Agent-to-Agent (`A2A`) APIs (planned Iteration 9):** First-class inventory of native MCP servers, tools and backing API-operation bindings, passthrough transports, and A2A agent APIs with sanitized agent-card/runtime metadata. Inspect effective policies at the documented protocol-specific scopes, not just ordinary REST API policies. MCP endpoints must have effective incoming OAuth token validation using `validate-jwt` or `validate-azure-ad-token`; missing validation produces an actionable security finding recommending OAuth 2.0. This is the assessment's required baseline, not a claim that Microsoft disallows subscription-key authentication.
   - **Workspaces & Self-Hosted Gateways (`SHGW`):** Team isolation boundaries, gateway heartbeat/version currency, and config sync status.
   - **GraphQL, WebSocket & gRPC APIs:** Protocol-specific security (`validate-graphql-request`, max depth/size, WSS enforcement).

---

## 3. Target Scope & Discovery Modes (1–N Architecture)

A single execution can evaluate **1 to N APIM instances** across **1 to N Azure Subscriptions** and **1 to N Resource Groups**:

- **Explicit Instance Mode:** One or more APIM resource IDs (via `--resource-id` or configuration file).
- **Discovery Mode:** One or more Subscription IDs (`--subscriptions`) and/or Resource Group filters (`--resource-groups`). Uses Azure Resource Graph (with ARM fallback) to discover all target `Microsoft.ApiManagement/service` resources.
- **Environment Profile Awareness (`prod` | `non-prod` | `auto`):**
  - Supports global `--env` flag and per-instance overrides in the YAML config.
  - In `auto` mode, infers environment from SKU (`Developer`, `Consumption`, `Basic`), tags (`env`, `environment`), or naming conventions.
  - Adjusts severity/applicability on SKU-constrained rules (e.g., Availability Zones or Multi-Region on `Developer` tier are marked as SKU-constrained/Non-Prod Advisory rather than false-positive Critical failures, unless `--env prod` is enforced).

---

## 4. Pipeline Architecture & Execution Stages

The CLI supports both decoupled pipeline stages and a single-command workflow:

```text
┌───────────────────┐     snapshot.json     ┌───────────────────┐     findings.json     ┌───────────────────┐
│   1. COLLECT      │ ────────────────────► │   2. ANALYZE      │ ────────────────────► │   3. REPORT       │
│ (Live Azure Probe │   (Sanitized Bundle)  │ (Effective Policy │   (Scored Findings,   │ (Self-Contained   │
│  + Sanitization)  │                       │  + Rule Engine)   │    Pillar Rollups)    │  HTML Slide Deck) │
└───────────────────┘                       └───────────────────┘                       └───────────────────┘
         │                                                                                        ▲
         └──────────────────────────────────  4. ASSESS (All-in-One)  ────────────────────────────┘
```

1. **`apim-assess collect`**: Authenticates via `DefaultAzureCredential`, discovers 1–N APIM instances, runs core and optional collector modules asynchronously, sanitizes sensitive data by default, and writes a portable `snapshot.json`.
2. **`apim-assess analyze`**: Loads `snapshot.json`, builds the Effective Policy AST for every API and Operation, runs the hybrid YAML + Python rule catalog (applying environment profiles, waivers, and threshold overrides), optionally enriches executive narratives via LLM (`--enrich-ai`), and writes `findings.json`.
3. **`apim-assess report`**: Renders `findings.json` (and topology metadata from `snapshot.json`) into a single-file, zero-CDN interactive HTML readout deck (`apim-assessment-report.html`).
4. **`apim-assess assess`**: Executes `collect` → `analyze` → `report` end-to-end in one command.

---

## 5. Collector Modules & Data Sanitization

### 5.1 Core APIM Collector
- **Service & Topology:** SKU/tier, capacity units, `zones`, `additionalLocations`, `virtualNetworkType`, `virtualNetworkConfiguration`, `publicIpAddresses`, `privateEndpointConnections`, `publicNetworkAccess`, `natGatewayState`, `customProperties` (TLS 1.0/1.1/1.2/1.3, ciphers, HTTP2), `hostnameConfigurations`, `identity` (SystemAssigned / UserAssigned), `apiVersionConstraint`, `restore` / backup indicators, developer portal status.
- **APIM Sub-Resources:**
  - `apis` (protocols, path, serviceUrl, subscriptionRequired, apiVersionSetId, type: http/graphql/websocket/soap, authenticationSettings, diagnostic traces)
  - `operations` (method, urlTemplate, parameter/request/response definitions)
  - `products` (subscriptionRequired, approvalRequired, state, linked APIs)
  - `subscriptions` (scope—flagging `/apis` all-APIs scope, state)
  - `backends` (url, protocol, tls validation, credentials, circuitBreaker rules, pool services)
  - `namedValues` (secret flag, Key Vault linkage & identity, tags)
  - `certificates` (expiry, thumbprint, Key Vault linkage)
  - `policies` & `policyFragments` (Global policy, Workspace policies, Product policies, API policies, Operation policies, and all `<include-fragment>` definitions)
  - `diagnostics` & `loggers` (Application Insights / Azure Monitor logger linkage, sampling percentage, verbosity, alwaysLog, header logging)
  - `gateways` & `workspaces` (Self-hosted gateway nodes, heartbeat/version status, workspace isolation)
  - `portalsettings` / `signUp` / `signIn` / `identityProviders` (Anonymous access, self-service sign-up, Entra ID SSO)

### 5.2 Adjacent Azure Signal Collectors
- **Networking (`networking_vnet_nsg`):** Inspects linked VNet subnet, NSG security rules (validating mandatory APIM management/load-balancer ports and checking for overly permissive `0.0.0.0/0` inbound gateway exposure), Private Endpoints, and Public IP DDoS protection state.
- **Telemetry — Azure Monitor Metrics (`azure_monitor_metrics`):** Queries configurable lookback window (default `30d` in Iteration 8; configurable `1..30d`) for `Capacity` (Classic tiers), `CpuPercent_Gateway` & `MemoryPercent_Gateway` (v2 tiers), `Requests` (overall and split by `GatewayResponseCodeCategory` and `ApiId`), `Duration`, `BackendDuration` (split by `ApiId`), and `NetworkConnectivity`.
- **Telemetry — Optional Log Analytics KQL Module (`log_analytics_kql`):** When enabled and linked to a Log Analytics Workspace, executes read-only KQL queries against `ApiManagementGatewayLogs` / `AzureDiagnostics` to surface runtime evidence:
  - Actual client TLS 1.0 / 1.1 traffic volume
  - Top 5xx failing APIs / backends and timeout hotspots
  - Cache hit vs. miss ratios
  - Unauthenticated or subscription-key-only traffic patterns
- **Governance & Threat Detection (`defender_policy`):** Checks Microsoft Defender for APIs subscription/API onboarding status, Azure Policy compliance state for `Microsoft.ApiManagement`, and Azure Monitor Autoscale settings (`Microsoft.Insights/autoscalesettings`).

### 5.3 Optional Upstream WAF Collector Modules (`AFD` & `AppGW`)
- **Discovery Strategy:**
  - **Auto-Discovery Mode:** Queries Azure Resource Graph across probed subscriptions to identify Azure Front Door (`Microsoft.Cdn/profiles`) origins and Application Gateway (`Microsoft.Network/applicationGateways`) backend pools matching any target APIM hostname, custom domain, public IP, or internal VNet IP.
  - **Explicit Mode:** Probes specific AFD Profile or Application Gateway resource IDs supplied via CLI flags or `assessment.yaml`.
- **Inspection Checks:**
  - Verifies WAF policy attachment, mode (`Prevention` vs. `Detection`), managed ruleset enabled (DRS/OWASP), bot protection, rate-limiting rules, HTTPS-only forwarding, health probe configuration, and whether APIM restricts direct bypass traffic exclusively to the upstream WAF (via NSG service tags `AzureFrontDoor.Backend` / subnet rules or `check-header` / mTLS).

### 5.4 Default-On Snapshot Sanitization
- Never persists raw Named Value secret strings, backend authorization headers/passwords, or certificate private payloads.
- Runs an XML & string sanitizer across all collected policy XML documents to mask inline bearer tokens, API keys, SAS tokens, and connection strings with `<REDACTED_SECRET>` while preserving structural metadata (`has_inline_secret_pattern: true`, secret-free location breadcrumbs for inline secrets, literal URL indicators across `set-backend-service`, `set-url`, `rewrite-uri`, and C# expressions, and hashed `{{named-value}}` token references) so the analyzer can flag hardcoded secrets, hardcoded URLs, and unbacked secret Named Value usage in policies without leaking sensitive values in `snapshot.json`.
- Gracefully records RBAC permission gaps per module as structured `collection_warnings` rather than aborting the run.

### 5.5 Planned Iteration 9: MCP & A2A Collection
- Use explicitly pinned, documented management API contracts that expose native MCP and A2A resources. MCP management requires `2025-09-01-preview` or a verified later version; an older API returning no MCP entries does not establish that none exist.
- Collect MCP server/tool inventory, safe transport metadata and backing-operation references, plus A2A agent API metadata and their configured XML policies. Track inventory and policy coverage independently, including unsupported SKU/gateway/workspace combinations.
- Treat MCP entry-point policies and any backing REST API/operation policies as distinct execution boundaries. Reuse the effective-policy resolver only where its scope/inheritance rules match the documented protocol behavior.
- Do not invoke MCP tools, execute A2A tasks, fetch arbitrary agent-card URLs, retrieve secret values, or retain unredacted backend URLs, tool schemas/descriptions, agent-card payloads or credentials merely to establish inventory.
- Preserve offline analysis/reporting and compatibility with historical artifacts; snapshots without these signals must show MCP/A2A coverage as not collected, not zero servers or a security pass.

---

## 6. Analyzer & Effective Policy Resolution Engine

### 6.1 Effective Policy Resolver
APIM policies execute hierarchically across scopes: `Global` → `Workspace` (if applicable) → `Product` → `API` → `Operation`, with `<base />` controlling parent inheritance and `<include-fragment fragment-id="..." />` splicing reusable policy XML.

For each API and Operation, the analyzer constructs an **Effective Policy Model**:
- Expands all `<include-fragment>` references in `inbound`, `backend`, `outbound`, and `on-error` sections.
- Detects missing `<base />` elements that inadvertently bypass parent/global security or logging controls.
- Evaluates effective policy posture across the inheritance chain:
  - **Authentication & Authorization:** `validate-jwt`, `validate-azure-ad-token`, `validate-client-certificate`, `authentication-managed-identity`.
  - **Traffic Control & DoS Protection:** `rate-limit`, `rate-limit-by-key`, `quota`, `quota-by-key`, `limit-concurrency`, `azure-openai-token-limit` / `llm-token-limit`.
  - **Input & Protocol Security:** `validate-content`, `validate-parameters`, `validate-headers`, `validate-graphql-request`, `cors` (flagging wildcard `*` with credentials), `ip-filter`, `check-header`.
  - **Resiliency & Routing:** `retry`, `forward-request` timeout settings, `set-backend-service` (abstracted backend vs. hardcoded URL), `<on-error>` custom error handling.
  - **Information Disclosure & Hardening:** Outbound `set-header` removing `X-Powered-By`, `X-AspNet-Version`, `Server`; absence of hardcoded secrets in policy expressions.

### 6.2 Hybrid Rule Engine (YAML Catalog + Python Evaluators)
- **Declarative YAML Rule Catalog (`rules/*.yaml`):** Defines rule ID, title, WAF pillar, MCSB control ID(s), severity (`Critical`, `High`, `Medium`, `Low`, `Advisory`), applicability (`prod`, `non-prod`, SKUs), description, business impact, remediation steps, Microsoft Learn reference URLs, and evaluator binding.
- **Python Evaluator Plugins:** Execute deterministic checks against the APIM instance model, Effective Policy AST, adjacent networking/telemetry data, and upstream WAF findings.
- **Scoring & Maturity Calculation:**
  - Computes 0–100 health scores per WAF Pillar, an overall MCSB Compliance score, and an API Policy Coverage score per APIM instance and across the 1–N portfolio.

---

## 7. Interactive HTML Slide Deck & Deep-Dive Readout

The `report` stage produces a **single, 100% self-contained `.html` artifact** (zero external CDNs, inline CSS/JS/SVG, air-gap safe):

Iteration 6 updates the default presentation below to a focused, seven-tab
readout based on the supplied HTML design reference: Overview, Findings,
Verification gaps, Roadmap, MCSB controls, API policy coverage, and Method &
scope. The same saved assessment powers every view; presentation navigation
remains optional. This supersedes the slide-first default, not the evidence,
coverage, sanitization, offline, or scoring requirements.

Iteration 8 extends the focused HTML readout with self-contained, zero-CDN
inline SVG 30-day trend charts for gateway utilization (`Capacity` on Classic
tiers or `CpuPercent_Gateway` + `MemoryPercent_Gateway` on v2 tiers), request
volume by HTTP status code category, request volume by API, and backend latency
(`BackendDuration`) by API.

Iteration 9 is planned to surface MCP/A2A capability inventories and policy
coverage in the existing focused readout. MCP OAuth findings must identify the
affected server/context, the effective token-validation evidence or confirmed
gap, and remediation. A subscription key, backend managed identity, forwarded
Authorization header, or developer-portal OAuth setting alone cannot satisfy
the MCP incoming-token check. Unavailable policies remain verification gaps.

1. **Portfolio Rollup + 1–N APIM Instance Switcher**
   - Top navigation bar lets presenters view the **Portfolio Executive Rollup** across all scanned APIM instances or switch instantaneously to any individual APIM instance.
2. **Mode 1: Interactive Slide Presentation Mode (Readout Deck)**
   - Keyboard (`←`/`→`, `Space`, `F` fullscreen, `N` speaker notes) and touch/click navigable slide deck:
     - **Slide 1 — Cover & Assessment Scope:** Assessed subscriptions, APIM instances, environment profiles, timestamp, and collection coverage.
     - **Slide 2 — Executive Scorecard:** Overall health score, 5 WAF Pillar maturity gauges, MCSB compliance rate, and finding severity breakdown.
     - **Slide 3 — Architecture, Topology & Upstream WAF Posture:** Visual topology summary (SKU/Units/Zones/Regions, VNet Mode, Private Link, AFD/AppGW WAF protection status, Self-Hosted Gateways).
     - **Slide 4 — Reliability & Resiliency Readout:** Zone/Region HA, Autoscale, Backend Pools & Circuit Breakers, Backup/DR readiness.
     - **Slide 5 — Security & MCSB Baseline Readout:** Network boundaries, TLS/Ciphers, Identity/Key Vault posture, Auth (`validate-jwt`), Developer Portal & Control Plane hardening.
     - **Slide 6 — Effective Policy Coverage & AI Gateway Posture:** Cross-API heatmap of effective policy controls (`<base />` integrity, JWT, rate limits, CORS, caching, AI Gateway token limits & semantic caching).
     - **Slide 7 — Performance, Cost & Operational Excellence:** Capacity/CPU/Memory telemetry trends, App Insights sampling, Diagnostics, APIOps & Backend abstraction.
     - **Slide 8 — Prioritized Remediation Roadmap:** Phased action plan (**Quick Wins / 0–30 Days**, **Short-Term / 30–60 Days**, **Strategic / 60–90+ Days**) ranked by risk reduction and effort.
3. **Mode 2: Interactive Deep-Dive Explorer Mode**
   - Instant toggle from Slide Mode into a full-screen technical workbench:
     - **Searchable & Filterable Findings Table:** Filter by APIM instance, WAF Pillar, MCSB Control, Severity, Category, or affected API; expand any finding to view exact evidence, affected resources/APIs, and copy-paste remediation guidance + Learn links.
     - **Effective Policy Matrix:** Interactive grid showing every API (and operation summary) vs. effective controls inherited from Global/Product/API scopes.
     - **MCSB Control Matrix:** Pass/Fail/Warning status mapped across all applicable Microsoft Cloud Security Benchmark controls.
4. **Presentation Polish**
   - Dark / Light theme toggle, collapsible Speaker Notes panel per slide, and `@media print` stylesheet for clean PDF slide export directly from the browser.

---

## 8. Declarative Configuration (`assessment.yaml`) & Packaging

- **Rich YAML Config (`--config assessment.yaml`):**
  - `targets`: Explicit APIM resource IDs (with optional per-instance `env: prod|non-prod`), subscription lists, resource group lists.
  - `modules`: Enable/disable `metrics`, `log_analytics_kql`, `networking`, `defender_policy`, `afd` (auto-discover + explicit IDs), `appgw` (auto-discover + explicit IDs).
  - `telemetry`: Lookback window (`7d`, `14d`, `30d`), KQL max rows/timeout.
  - `rules`: Rule waivers/suppressions (with justification), severity overrides, and custom thresholds (e.g., `capacity_warning_pct: 70`, `cert_expiry_days: 30`, `app_insights_max_sampling_pct: 50`).
  - `ai_enrichment`: Optional Azure OpenAI / OpenAI-compatible endpoint & deployment configuration for narrative synthesis.
- **Container & CLI Packaging:**
  - `pyproject.toml` providing the `apim-assess` CLI entrypoint (`typer` + `rich`).
  - Multi-stage `Dockerfile` allowing zero-install execution via `docker run --rm -v ~/.azure:/root/.azure -v ./output:/output apim-assess assess ...`.
