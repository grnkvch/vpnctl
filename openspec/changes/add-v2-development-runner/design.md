## Context

See proposal.md. The parent already has registered commands, dependency edges,
private attempts and owner-scoped shared Lima sessions. Several child scripts
also reject dirty Git state; removing only the parent check would not work.

## Goals / Non-Goals

Goals: execute a selected registered check from working files, retain actual
inputs, preserve fixture safety and keep release acceptance strict.

Non-goals: a new cache/fingerprint framework, cross-run resume, arbitrary shell
execution, concurrent VM stages, frozen Git worktrees for development, changes
to runtime vpnctl, or automatically scheduling an entire discovery matrix.

## Decisions

- Add one `run-dev <stage>` entry to the existing runner. Use the existing
  registry and stage/fixture functions, including only declared prerequisites.
  This avoids duplicating cleanup or inventing another stage registry.
- Create a fresh private directory under `artifacts/v2lab/development-runs`.
  Do not create a release candidate or aggregate. Retain `development.json`
  with `production_ready: false`, actual status and snapshot/manifest hashes.
- Inventory existing tracked/untracked non-ignored files within explicit
  repository input roots (`cmd`, `internal`, `scripts`, `test`, `openspec`,
  `docs`, Go module files and repository guidance). Snapshot current bytes,
  not Git tree objects. The repository may be unborn; no HEAD lookup is needed.
  Record file modes and checksums and compare the manifest after execution.
  This is provenance/drift detection, not a reusable stage-cache key.
- Child harnesses share a small source-context helper. Only a validated context
  below this repository's development root permits dirty/uncommitted execution;
  its source marker is the literal `development`, never a fabricated Git SHA.
  Existing provider-archive verification and fixture rules are unchanged.
  Final runner commands discard inherited development context before dispatch.
- Reuse passing prerequisites only within this fresh invocation. A failure
  stops its dependent branch; another independent `run-dev` invocation remains
  available after cleanup. No requirement to run the complete fast phase first.
- Keep strict `--resume` unchanged. Development prints a fresh selected-stage
  retry command, never a misleading release-resume instruction.

## Risks / Trade-offs

- A source snapshot is broader than one stage's dependency closure: accept this
  small local storage cost; do not build a dependency-analysis project.
- Commands still use the working files: before/after manifests detect ordinary
  concurrent edits, but this is not hermetic or adversarial race-proof execution.
- Generated/cache inputs outside the snapshot retain their existing child-harness
  hash checks; the snapshot is not a claim of complete environment reproducibility.
- Registered commands may themselves run broad suites or repeat setup. Selecting
  one stage removes the outer full-gate prerequisite, not the stage's real work.
- New context must not leak into final qualification: cover inherited context,
  nested source checks and rejection of development receipts with regressions.

## Migration Plan

No migration of sealed evidence. Existing commands keep their defaults. Add
focused host-only fake-command/fake-Lima regression coverage; do not start real
VMs/VPS to validate orchestration. Update the existing PR and documentation.
Rollback removes the new entry and helper without changing retained old runs.
