# Local MCP assessment server

The optional server exposes the same deterministic, read-only assessment engine
as the CLI. It does not invoke models, remediate Azure resources, or inspect
subscriptions unless explicitly targeted. Agent clients receive sanitized
assessment data; access to a model-hosted client is your choice.

## Native installation

Python 3.11+ is supported. From a source checkout:

```powershell
python -m pip install ".[mcp]"
New-Item -ItemType Directory -Force C:\apim-workspace
apim-assess mcp --workspace C:\apim-workspace
```

The server starts over stdio, not as an HTTP listener. Normally the client starts
it, rather than running the last command in an interactive terminal. The workspace
must already exist. Only workspace-relative config/input/output references are
accepted; arbitrary file access and paths outside the workspace are rejected.

For a release wheel, use `pipx install "<wheel-path>[mcp]"` or
`python -m pip install "<wheel-path>[mcp]"`. PyPI distribution is not configured.
Ordinary CLI installs do not include the server extra. The tested SDK is official
Python MCP SDK 2.3.0 (`MCPServer`), with current and legacy protocol support.

## Container and first login

Build the companion image (the existing `Dockerfile` remains the lean CLI image):

```powershell
docker build --file Dockerfile.mcp --tag apim-assess:mcp .
docker run --rm -it --entrypoint az `
  --mount "type=volume,source=apim-assess-azure,target=/home/assessor/.azure" `
  apim-assess:mcp login --use-device-code --tenant "<tenant-id>"
```

Open the Microsoft sign-in address printed by Azure CLI in your normal browser,
enter its temporary code, and finish account/MFA authentication. If prompted,
select the intended subscription. The container saves its cache in the named
volume, which persists after the login container exits. Neither passwords nor
tokens belong in MCP configuration or tool arguments.

Then launch the server with the same cache and a separate artifact mount:

```powershell
docker run --rm -i `
  --mount "type=volume,source=apim-assess-azure,target=/home/assessor/.azure" `
  --mount "type=bind,source=C:\apim-workspace,target=/workspace" `
  apim-assess:mcp
```

Use `-i`, not `-t`, for MCP. No ports are published. The non-root image sets
`AZURE_CONFIG_DIR` and installs Azure CLI 2.93.0 in its own environment. An empty
named volume inherits the owned cache directory; an existing volume or bind mount
must permit UID/GID 10001 to read/write it. The workspace also needs write access.

Windows `.azure` caches are encrypted and can use WAM: mounting them into Linux
does not transfer the Windows session. Use the container-created volume above.
Linux/macOS CLI caches can be bind-mounted where their permissions and cache
versions are compatible; the cache must be writable for refresh/updates.

CLI tokens refresh when possible, but expiry, revocation and Conditional Access
may require rerunning login. Device-code flow must be allowed by the tenant.
The server never starts an interactive login in the protocol stream. For logout:

```powershell
docker run --rm --entrypoint az `
  --mount "type=volume,source=apim-assess-azure,target=/home/assessor/.azure" `
  apim-assess:mcp logout
```

Other supported `DefaultAzureCredential` sources remain available through the
container environment. Native installations can use the host's Azure CLI login.
Use separate login volumes for distinct account/tenant sessions.

## Client configuration

Copilot CLI:

```powershell
copilot mcp add apim-assess -- apim-assess mcp --workspace C:\apim-workspace
copilot mcp list
```

For Docker, configure `command: "docker"` and arguments from the runtime command
above. This Copilot build also accepts user `mcp-config.json` or workspace
`.mcp.json`/`.github\mcp.json`, with a top-level `mcpServers` object:

```json
{
  "mcpServers": {
    "apim-assess": {
      "type": "local",
      "command": "apim-assess",
      "args": ["mcp", "--workspace", "C:\\apim-workspace"]
    }
  }
}
```

Claude Code:

```powershell
claude mcp add --transport stdio apim-assess -- apim-assess mcp --workspace C:\apim-workspace
claude mcp list
```

Claude Desktop recipe (not yet a verified support claim): use its
`claude_desktop_config.json` with `mcpServers` and the same command/args, omitting
Copilot's `type` field. VS Code recipe (also documentation-only): use its
`.vscode\mcp.json` with top-level `servers` and `type: "stdio"`.
Verify current client documentation and use an absolute executable path if a GUI
does not inherit your terminal PATH. Do not overwrite existing client settings.

## Tools and jobs

| Tool | Input and result |
|---|---|
| `collect`, `assess` | Existing typed `AssessmentConfig`, or `config_file`; explicit targets required |
| `analyze` | Workspace `snapshot`, optional config; no Azure calls |
| `report` | Matching `snapshot` and `findings`; writes existing HTML |
| `get_job_status` | `job_id`; running/completed/failed/cancelled and actual stage |
| `get_job_result` | Terminal job, counts, warnings and artifact references; NOT_READY while running |
| `cancel_job` | Stops owned worker tree; terminal jobs remain unchanged |
| `query_findings` | `findings`, optional filters, `page_size`, `cursor` |
| `explain_rule` | Existing `rule_id`; catalog metadata and remediation |

Config file and inline config are mutually exclusive. Configs with AI enrichment
are rejected by MCP rather than silently initiating a remote model call.
The existing CLI enrichment option is unchanged.

Start tools return a job ID, not a successful assessment. Poll status, then get
the result. One pipeline runs at a time; additional starts return BUSY rather
than queue. Jobs and the most recent 50 terminal records belong to this server
process. Closing the client/server cancels active work. Completed files remain
under `runs\<job-id>\`; use saved references after restart, not old job IDs.

Files are atomic per stage, not a transaction across all stages. Failed/cancelled
runs may contain a completed snapshot/findings file; these are partial outputs,
not a successful assessment. The engine preserves unknown evidence, unsupported
capabilities, non-applicability, waivers, and collection warnings.

Query filters: resource ID, pillar, severity, underlying outcome, waiver state,
and rule ID. Pages default to 25, cap at 100, and are limited to 256 KiB of finding
JSON; inputs cap at 64 MiB. Oversized results fail explicitly: narrow filters or
reduce the page size, or inspect the saved local artifact. Evidence is not silently
truncated. Cursors are bound to content and filters; changed files yield STALE_CURSOR.

Common safe codes: TARGETS_REQUIRED, PATH_DENIED, INVALID_CONFIG,
INVALID_SNAPSHOT, INVALID_FINDINGS, DIGEST_MISMATCH, AUTHENTICATION_FAILED,
NO_READABLE_INSTANCES, UNKNOWN_JOB, UNKNOWN_RULE, BUSY, NOT_READY, WORKER_FAILED.
Permission gaps with usable collection remain warnings, not errors or passes.

## Offline quickstart and acceptance

```powershell
Copy-Item tests\fixtures\sample_multi_apim_snapshot.json C:\apim-workspace\snapshot.json
python scripts\mcp_smoke.py --workspace C:\apim-workspace
```

Prompt: "Using apim-assess, analyze snapshot.json, wait for completion, show
Critical failures and unknown security checks separately, and generate the HTML
report." For live collection, explicitly provide authorized instance IDs or a
workspace config. No implicit all-subscription targeting occurs.

Automated acceptance covers SDK in-memory and real stdio transports, current and
legacy clients, deterministic artifact parity, and worker/path/error behavior.
Native tool invocation was verified locally in Copilot CLI and Claude Code using
isolated test configuration on Windows/Python 3.13. A live native APIM assessment
also completed through the MCP tools, producing snapshot, findings, and HTML
artifacts. Container client use and container login/cache reuse have not been
verified locally because Docker's daemon was unavailable.
CI builds the companion image and exercises stdio analyze/query/report without
network or credentials, plus non-root and cache permissions. Real Copilot/Claude
sessions and authorized live Azure login/cache reuse are separate acceptance
checks; automated fixtures are never described as live evidence.

## Release distribution

The `publish-mcp.yml` workflow is manual only. First explicitly request a source
release with a supplied version, then explicitly request wheel/image publication.
The tag must target a merged phase PR on main and match package metadata. A version
mismatch is a blocker, not permission to bump source during release.

The workflow verifies the exact target, builds/tests it, uploads wheels/sdist and
checksums, and publishes Linux amd64
`ghcr.io/stonefly-labs/apim-assess:<tag>-mcp` with its digest/provenance.
Configure the `mcp-release` environment and its reviewer protection before use.
GitHub packages initially default to private: a repository administrator must
set this package public and verify anonymous pull before announcing public
availability. Nothing is published on PRs or ordinary main pushes.

SDK/protocol grounding: official `modelcontextprotocol/python-sdk` documentation.
Login/cache grounding: Microsoft Learn's interactive Azure CLI and MSAL cache
documentation. HTTP hosting, durable history and protocol extensions belong to
Iterations 12-14, not this implementation.
