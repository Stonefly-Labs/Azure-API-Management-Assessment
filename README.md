# apim-assess

**Understand the configuration, risks, and assessment coverage of your Azure API
Management gateways.** Run a read-only assessment from the CLI or through a local
MCP server, then explore the results in a self-contained HTML report.

`apim-assess` assesses one or many instances with 55 deterministic rules across
the five Azure Well-Architected pillars and selected Microsoft Cloud Security
Benchmark mappings. It inspects effective policies, networking, telemetry,
governance, and supported AI/MCP/A2A gateway configuration. Findings are
configuration assessments, not runtime security certification or complete MCSB
compliance.

## Start here

| You want to... | Use |
|---|---|
| Try it without Azure access | [Offline quickstart](#try-an-offline-assessment) |
| Assess your gateways | [Live assessment](#assess-your-azure-gateways) |
| Drive it from Copilot or Claude | [Local MCP server](#use-it-through-copilot-or-claude) |
| Run without installing Python on your host | [Containers](#run-in-a-container) |
| Understand a rule or a coverage gap | [Assessment reference](docs/assessment-reference.md) |

## Install

Requires Python 3.11+. Run these commands from a source checkout:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install .
.\.venv\Scripts\apim-assess --help
```

Installation is currently source-based; PyPI publication is not configured.
The package is a pure-Python wheel. On Windows, `apim-assess.exe` is the
installer-generated Python command launcher, not a compiled assessment binary.

Install `".[mcp]"` instead of `.` if you want the optional local MCP interface.
Contributor dependencies are separate: see [Development](#development).

## Try an offline assessment

No Azure login or network access is needed. The sample contains three synthetic
instances and intentionally includes failures and missing evidence.

```powershell
.\.venv\Scripts\apim-assess analyze `
  --snapshot tests\fixtures\sample_multi_apim_snapshot.json `
  --output output\findings.json

.\.venv\Scripts\apim-assess report `
  --snapshot tests\fixtures\sample_multi_apim_snapshot.json `
  --findings output\findings.json `
  --output output\apim-assessment-report.html

Start-Process .\output\apim-assessment-report.html
```

The report includes findings, verification gaps, pillar scores, MCSB mappings,
policy coverage, and telemetry trends where evidence is available. Its CSS,
JavaScript, and charts are embedded: no CDN or external runtime assets.

## Assess your Azure gateways

Collection uses `DefaultAzureCredential`. For local use, Azure CLI login is one
supported option. Supply an authorized, explicit APIM resource ID:

```powershell
az login

.\.venv\Scripts\apim-assess assess `
  --resource-id "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.ApiManagement/service/<apim-name>" `
  --env non-prod `
  --output-dir output
```

Use `--env prod` for a production gateway, regardless of its SKU. Omit it to use
the default `auto` classification, or specify per-instance profiles in config.
Repeat `--resource-id` for multiple instances. Scoped discovery is also available:

```powershell
.\.venv\Scripts\apim-assess assess `
  --subscriptions "<subscription-id>" `
  --resource-groups "<resource-group>" `
  --output-dir output
```

The tool does not enumerate every subscription in your account. APIM read
permissions are required; optional networking, governance, upstream WAF and
Log Analytics signals need their corresponding read/query permissions.
Unavailable signals become explicit coverage warnings.

Use `--config assessment.yaml` for targets, module options, thresholds, severity
overrides, and justified waivers. Start from
[assessment.example.yaml](assessment.example.yaml).

### What gets saved?

```text
collect -> snapshot.json -> analyze -> findings.json -> report -> HTML
```

`assess` composes these same stages. Saved snapshots and findings can be analyzed
and reported offline; reporting does not recollect Azure configuration.

- `snapshot.json`: sanitized configuration, inventory, telemetry, and warnings.
- `findings.json`: deterministic rule results, evidence, scores, and settings.
- `apim-assessment-report.html`: the interactive readout.

No Azure resources are changed. Collection does not retrieve subscription keys,
secret values, or private certificate payloads. Do not commit live artifacts.
Review coverage alongside scores: unknown, unsupported, waived, and not-applicable
checks do not count as passes. Assessment failures do not themselves cause a
nonzero CLI exit; invalid inputs or unusable collection do.

## Use it through Copilot or Claude

The local MCP server exposes the assessment engine to agent clients over
**stdio**. It is separate from the assessment's ability to inspect MCP/A2A APIs
hosted in Azure API Management.

Install the optional dependencies and create an artifact workspace:

```powershell
.\.venv\Scripts\python -m pip install ".[mcp]"
New-Item -ItemType Directory -Force .\output
$cli = (Resolve-Path .\.venv\Scripts\apim-assess.exe).Path
$workspace = (Resolve-Path .\output).Path

copilot mcp add apim-assess -- $cli mcp --workspace $workspace
```

For Claude Code, use:

```powershell
claude mcp add --transport stdio apim-assess -- $cli mcp --workspace $workspace
```

The client launches and owns the server process; no listening port is needed.
The standalone command is `apim-assess mcp --workspace <existing-directory>`.
For Copilot workspace configuration, the equivalent `.mcp.json` entry is:

```json
{
  "mcpServers": {
    "apim-assess": {
      "type": "local",
      "command": "C:\\path\\apim-assess\\.venv\\Scripts\\apim-assess.exe",
      "args": ["mcp", "--workspace", "C:\\path\\apim-workspace"],
      "tools": ["*"]
    }
  }
}
```

Replace the example paths with absolute paths on your machine. The workspace
must exist. On Linux/macOS, use your installed `apim-assess` launcher instead.

### MCP tools

| Tool | Purpose |
|---|---|
| `collect` | Collect a sanitized snapshot from explicit Azure targets |
| `analyze` | Analyze a saved snapshot offline |
| `report` | Render matching saved artifacts to HTML |
| `assess` | Run collect, analyze, and report |
| `get_job_status` | Inspect job state, stage, and diagnostics |
| `get_job_result` | Get terminal output references, counts, scores, and warnings |
| `cancel_job` | Stop a running owned worker |
| `query_findings` | Filter and paginate findings, evidence, gaps, and waivers |
| `explain_rule` | Read catalog applicability, impact, remediation, and references |

Pipeline tools return a **job ID**. Poll status, then fetch the result.
One pipeline runs at a time; additional starts return `BUSY`. Job IDs are
process-scoped, while completed files persist in `runs\<job-id>\`.
Inputs and outputs stay within the configured workspace.

Try: **"Assess this APIM resource ID, wait for the job, show High/Critical
failures separately from unknowns, and generate the report."**

Or copy the sample snapshot into your workspace and ask:
**"Analyze snapshot.json and explain its security findings."**

The server never remediates resources or makes model-enrichment calls. Copilot CLI
and Claude Code tool use has been verified natively and through Docker, along
with live native/container assessments and saved-login reuse in a fresh container.
Iteration 11 is in [PR #15](https://github.com/Stonefly-Labs/Azure-API-Management-Assessment/pull/15).
See [MCP setup and behavior](docs/mcp.md) for complete configuration, limits,
errors, authentication, and client support details.

## Run in a container

There are **two different images**:

| Build | Use | Authentication |
|---|---|---|
| `Dockerfile` | Lean CLI, including offline analysis/reporting | Supported workload/environment credentials; Azure CLI is not installed |
| `Dockerfile.mcp` | Local MCP with Python and Azure CLI included | Separate container login and persistent Azure CLI cache, or supported workload credentials |

Build and inspect the lean CLI:

```powershell
docker build --tag apim-assess:local .
docker run --rm --network none apim-assess:local --help
```

Build the MCP image and perform its initial login:

```powershell
docker build --file Dockerfile.mcp --tag apim-assess:mcp .
docker run --rm -it --entrypoint az `
  --mount "type=volume,source=apim-assess-azure,target=/home/assessor/.azure" `
  apim-assess:mcp login --use-device-code --tenant "<tenant-id>"
```

Configure the client to launch the runtime command with the same cache:

```powershell
docker run --rm -i `
  --mount "type=volume,source=apim-assess-azure,target=/home/assessor/.azure" `
  --mount "type=bind,source=C:\path\apim-workspace,target=/workspace" `
  apim-assess:mcp
```

Use `-i`, **not `-t`**, for MCP. Both images run as UID/GID 10001; mounted output
and cache directories need appropriate permissions. On Windows, use the
container-created cache rather than expecting an encrypted Windows/WAM login
to transfer into Linux. Device-code login must be permitted by tenant policy,
and reauthentication may be required later.

Images are currently built locally. Manual release-wheel/GHCR publication is
prepared but not performed automatically; PyPI is deferred. Container commands,
cache permissions, and release requirements are detailed in [the MCP guide](docs/mcp.md).

## Learn more

- [Assessment behavior and technical reference](docs/assessment-reference.md):
  rule decisions, policy inheritance, sanitization, telemetry, scoring, and limits.
- [Local MCP guide](docs/mcp.md): tools, job lifecycle, client setup, and authentication.
- [Project scope](docs/project-scope.md) and [roadmap](docs/project-plan.md):
  product requirements, delivery boundaries, and future phases.
- [Azure validation lab](docs/assessment-reference.md#iteration-10-azure-validation-lab-and-lifecycle-automation):
  paired APIM profiles and automated deploy/validate/destroy workflows.

## Development

```powershell
.\.venv\Scripts\python -m pip install -e ".[dev,mcp]"
.\.venv\Scripts\python -m ruff check .
.\.venv\Scripts\python -m ruff format --check .
.\.venv\Scripts\python -m mypy
.\.venv\Scripts\python -m pytest -q
.\.venv\Scripts\python -m build
```

CI covers Python 3.11/3.13 on Windows/Linux and offline container checks. Normal
tests use synthetic artifacts and mocked credentials/HTTP, not live Azure.
Live smoke tests are explicit and separate. Iterations ship on dedicated
branches and human-reviewed PRs; publication and future phases require their
own explicit requests.
