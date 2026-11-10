---
name: cut-release
description: Publish a versioned GitHub release of an apim-assess phase already merged into main using gh. Use only when the user explicitly asks to cut or publish a release and supplies a version such as v0.0.1-alpha, v0.1.0-rc, or v1.0.0; optionally accept --pr followed by the merged phase PR number.
---

# Cut a post-merge GitHub release

## Invocation and version

Read the version and optional PR number from the user's invocation:

```text
/cut-release v0.0.1-alpha
/cut-release v0.1.0-rc
/cut-release v1.0.0
/cut-release v0.1.0-rc.1 --pr 12
```

The version is required. Preserve it exactly as the tag and release title;
never select, increment, normalize, or replace it. Accept a lowercase `v`
prefix followed by SemVer `MAJOR.MINOR.PATCH`, an optional prerelease, and
optional build metadata. Reject missing or multiple versions, extra options
other than `--pr <number>`, leading zeroes in core or numeric prerelease
identifiers, empty identifiers, and whitespace within a version.

Set `$Version` to that exact argument, then validate it in PowerShell:

```powershell
$number = '(?:0|[1-9][0-9]*)'
$identifier = '(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
$pattern = "\Av$number\.$number\.$number(?:-(?<pre>$identifier(?:\.$identifier)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\z"
$versionMatch = [regex]::Match($Version, $pattern)
if (-not $versionMatch.Success) {
    throw 'Supply a valid version such as v0.0.1-alpha, v0.1.0-rc, or v1.0.0.'
}
$IsPrerelease = $versionMatch.Groups['pre'].Success
```

A prerelease component sets GitHub's prerelease flag regardless of its name
(`alpha`, `beta`, `rc`, or another valid identifier). Build metadata alone
does not: `v1.0.0+build-1` is stable. A `v0.x.y` version without a prerelease
component is also a normal GitHub release.

## Resolve the merged phase

1. Read the repository instructions, `docs\project-plan.md`, and the local
   `gh release create --help`. Inspect `git status --short` and the current
   branch without changing or committing the worktree.
2. Resolve `$Repo` with `gh repo view --json nameWithOwner --jq .nameWithOwner`.
   Check authentication and use that explicit repository for subsequent
   commands; do not rely on ambient repository selection when publishing.
3. If `--pr` was supplied, require a positive integer and inspect that PR
   with `gh pr view <number> --repo <repo>` and JSON fields `number`, `title`,
   `state`, `mergedAt`, `baseRefName`, `headRefName`, and `mergeCommit`.
4. Without `--pr`, first inspect the PR associated with the current phase
   branch. If it is not an unambiguous merged phase PR, resolve remote
   `main` and inspect the PRs associated with its tip using the GitHub API.
   Select only a merged phase PR whose `mergeCommit.oid` equals that tip.
   Do not guess from the most recently updated PR, an unmerged feature
   branch, a chore PR, or an arbitrary older phase. If no single phase can
   be identified, stop and request an explicit `--pr <number>`.
5. Require `state == MERGED`, a nonempty `mergedAt`, `baseRefName == main`,
   and a full `mergeCommit.oid` matching the intended iteration in the
   project plan. Set `$TargetSha` to that merge commit, never local `HEAD`,
   a PR head SHA, or the moving string `main`.
6. Resolve remote `main` through the GitHub API. Compare
   `<target-sha>...<main-sha>`; require `identical` or `ahead`, meaning the
   target is on main's history. A later main tip must not silently change
   the release target. This also handles squash and rebase merges.
7. Inspect the phase PR's verification record and required checks, plus any
   configured release checks for the exact target. Stop on failed or pending
   required checks. If no CI is configured, state that fact rather than
   claiming checks passed. Do not invent application tests or build assets.

An unmerged phase is a blocker. Never merge its PR, bypass the human gate,
bump source versions, or start another iteration as part of releasing.

## Check for an existing tag or release

1. Inspect the exact remote tag and release for `$Version`. For API lookups,
   distinguish an explicit HTTP 404 from authentication, rate-limit, and
   network errors; never interpret every nonzero exit as "not found."
2. Resolve any existing tag to its actual commit. For annotated tags, follow
   tag objects until reaching the commit; a release's `target_commitish`
   alone is not proof of where its tag points.
3. If the tag points anywhere other than `$TargetSha`, stop. Never delete,
   force-push, or move an existing tag.
4. If a published release already exists with the correct tag commit and
   prerelease flag, report its URL as already released and stop without
   editing it. If its classification differs or it is a draft, stop and
   describe the conflict rather than silently changing or publishing it.
5. If only a matching tag exists, set `$TagExists = $true` and use
   `--verify-tag` when creating the release. Otherwise set it to `$false`;
   `gh` can create the new tag at the pinned `$TargetSha`.

## Publish and verify

The invocation is the user's request to publish this version, not merely
prepare a draft. State the resolved repository, version, phase PR, target
SHA, and prerelease status before executing the write. Do not publish a
release when the user is only asking to create or edit this skill.

After all preflight steps succeed, run:

```powershell
$releaseArgs = @(
    'release', 'create', $Version,
    '--repo', $Repo,
    '--target', $TargetSha,
    '--title', $Version,
    '--generate-notes'
)
if ($IsPrerelease) {
    $releaseArgs += @('--prerelease', '--latest=false')
}
if ($TagExists) {
    $releaseArgs += '--verify-tag'
}
gh @releaseArgs
if ($LASTEXITCODE -ne 0) {
    throw 'Release creation failed. Inspect the remote tag and release before retrying.'
}
```

Use generated GitHub release notes. Do not attach live snapshots, findings,
HTML assessments, or credentials. This is a source release, not a package
registry publish or container deployment; only attach built assets if
explicitly requested and verified. For stable releases, leave Latest
selection to GitHub's default behavior rather than force-promoting an older
version. Prereleases must never replace Latest.
Different explicit versions may intentionally reference the same merged
commit, such as promoting a release candidate to a stable release.

Read the release back with `gh release view <version> --repo <repo>` and
JSON fields `tagName`, `name`, `isDraft`, `isPrerelease`, and `url`. Resolve
the remote tag again and verify its commit equals `$TargetSha`, the exact
tag and title match `$Version`, the release is published, and the prerelease
flag matches `$IsPrerelease`. Report partial failures explicitly; do not
delete a tag or release as automatic cleanup.

Return the release URL, version, phase PR, target SHA, and release type.
Stop without merging any PR or advancing the implementation phase.
