# Repository instructions

## Project context and source of truth

`apim-assess` is a read-only Azure API Management assessment CLI for one or
many instances. It evaluates all five Azure Well-Architected Framework
pillars and the Microsoft Cloud Security Benchmark, then produces structured
artifacts and a self-contained HTML readout.

Read `docs\project-scope.md` for requirements and `docs\project-plan.md` for
the module layout, rule IDs, iteration boundaries, and delivery workflow.
These documents describe the intended product, not already implemented
capabilities. Surface conflicts or ambiguous requirements rather than
silently changing the plan.

## Delivery boundaries

- Work on a dedicated `feature/`, `bugfix/`, or `chore/` branch, never directly
  on `main`. Preserve unrelated worktree changes.
- Implement only the requested iteration or maintenance task. Do not build
  future iterations, stub their modules, or expand the rule catalog early.
- Deliver one iteration per feature branch and PR. Verify its end-to-end CLI
  behavior and tests, commit cohesive changes, push, and open a PR using `gh`.
- Stop after opening the PR. Never merge it. Start the next iteration only
  after a human has merged the current PR and explicitly requested the next.
- Use `.github\skills\deliver-iteration\SKILL.md` for iteration delivery and
  `.github\skills\add-assessment-rule\SKILL.md` for rule additions or changes.

## Architecture and implementation

- Preserve the `collect -> analyze -> report` artifact boundaries:
  `snapshot.json`, `findings.json`, and the HTML report. `assess` composes
  those stages; do not duplicate their logic.
- Only collection requires live Azure access. Analysis and reporting must
  work offline from saved, sanitized artifacts.
- Follow the planned Python `src\apim_assess` layout, Typer/Rich CLI,
  Pydantic models, YAML rule metadata, Python evaluators, and Jinja2 reporting.
  Add dependencies only when required by the active iteration.
- Keep evaluators deterministic. Optional AI enrichment must not change
  evidence, findings, applicability, severity, or scores.
- Keep report CSS, JavaScript, and SVG inline: no CDN or external runtime
  assets. Escape untrusted resource names, policy text, and embedded data.
- Resolve effective XML policies structurally, honoring scope inheritance,
  `<base />` placement, and fragment expansion; text presence alone does not
  establish an effective control.

## Collection and assessment integrity

- Use `DefaultAzureCredential` and read-only Azure operations. Never change
  assessed resources or retrieve secret values merely to inspect metadata.
- Sanitize before persisting artifacts or logging evidence. Never commit
  live snapshots, credentials, subscription keys, backend authorization
  values, certificate private payloads, or unredacted policy secrets.
- Record permission gaps and unavailable signals as structured
  `collection_warnings`. Distinguish missing evidence from a confirmed
  absence; do not turn an unsupported or uncollected signal into a pass.
- Make rules environment-, SKU-, and capability-aware. Honor waivers and
  thresholds, preserve evidence provenance, and explain assessment coverage.
- Verify Azure feature, API-version, policy, and MCSB claims against current
  authoritative Microsoft documentation. Catalog entries are starting
  requirements, not proof that a feature or control mapping is current.

## Verification and repository state

At bootstrap, only project documents and Copilot configuration exist. There
is no application package, dependency manifest, test suite, or CI yet; do not
invent working installation or validation commands. Add app scaffolding and
CI with Iteration 1, not as part of this configuration bootstrap.

Once tooling exists, read `pyproject.toml` and the checked-in CI configuration
for supported setup, test, lint, type-check, and build commands. Run the
smallest relevant checks and focused regression tests. Use synthetic,
sanitized fixtures and mocked Azure clients for normal tests; keep any live
smoke test explicit and separate. For documentation-only changes, check
paths, skill frontmatter, and diff hygiene; do not claim application tests
ran. Report failed or unavailable checks honestly.
