---
name: deliver-iteration
description: Deliver one phase-gated apim-assess iteration from the project plan through implementation, verification, and a pull request. Use when asked to start, resume, finish, or ship a numbered iteration or steel-thread phase; never advance to the next iteration automatically.
---

# Deliver one iteration

## Establish the boundary

1. Read `docs\project-scope.md`, `docs\project-plan.md`, and
   `.github\copilot-instructions.md` from the repository root.
2. Inspect the worktree and current branch with `git status --short` and
   `git branch --show-current`. Inspect relevant PRs with `gh pr list` and
   `gh pr view` to distinguish in-progress work from merged work.
3. Identify the iteration the user requested and its prerequisites. Before
   starting a later iteration, verify the preceding iteration's PR was
   merged by a human and that the user explicitly requested advancement.
   An open PR or a passing check is not permission to move forward.
4. Create or resume the appropriate `feature/` branch. Do not overwrite
   unrelated changes or repurpose an unrelated branch. For maintenance,
   use the corresponding `bugfix/` or `chore/` branch instead.
5. Translate that iteration's goals into a bounded acceptance checklist:
   commands, collected signals, rules, report behavior, and relevant tests.
   Identify unresolved contradictions before implementing affected behavior.
   Do not include features from later iterations.

## Implement a vertical slice

1. Inspect existing models, helpers, fixtures, and tooling before editing.
   On Iteration 1, create only the scaffolding and tooling needed to run and
   verify its end-to-end slice; later iterations reuse and extend it.
2. Keep the saved snapshot and findings interfaces consistent across
   collection, analysis, reporting, and the composed `assess` command.
3. Enforce read-only collection and sanitize data before any persisted
   artifact or log. Preserve per-module coverage and collection warnings.
4. Keep analysis and reporting runnable without Azure credentials.
   Exercise multi-instance and environment-aware behavior within the slice.
5. Use the `add-assessment-rule` skill for rule work. Add focused tests for
   the behavior introduced or fixed; use synthetic fixtures, not live data.

## Verify the iteration

1. Discover supported commands from the actual dependency manifest and CI.
   Run the relevant tests and configured lint, type, and build checks for
   the changed code. Do not install tools merely to satisfy guessed commands.
2. Exercise the implemented CLI stages end-to-end using mocked collection
   and sanitized fixtures. Confirm the generated snapshot, findings, and
   self-contained HTML agree on resource identity, evidence, and scores.
3. Perform the iteration's live Azure smoke test only with authorized
   targets and available credentials. Do not discover arbitrary targets to
   compensate for missing input. Never substitute an offline test for a
   claimed live verification.
4. Check for secret leakage, unavailable-signal handling, and accidental
   scope expansion. Review `git diff` and run `git diff --check`.
5. If required checks fail or cannot run, report the blocker and keep the
   iteration incomplete; any PR opened with unmet acceptance criteria must
   remain a draft. Do not claim that the phase gate passed.

## Publish and stop

1. Commit only the iteration's cohesive changes. Preserve unrelated work
   and follow any applicable commit-message requirements.
2. Push the feature branch. Use `gh pr create` to open a PR targeting `main`,
   or update the existing PR for this same iteration.
3. Include the iteration number, delivered scope, exact checks and results,
   offline versus live verification, known limitations, and deferred work.
4. Return the PR number and stop. Never merge the PR or begin the next
   iteration, even if automation is green. Human review, human merge, and a
   new explicit request are required.
