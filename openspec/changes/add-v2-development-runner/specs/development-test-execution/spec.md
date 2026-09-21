## Purpose

Allow selected development checks to run against uncommitted working files
while preserving their actual inputs and the independent final release boundary.

## ADDED Requirements

### Requirement: Selected development checks are independent of Git commits

The gate SHALL provide `run-dev <stage>` for a named registered stage and its
declared prerequisites without requiring a commit, clean Git tree, unchanged
HEAD, completed fast phase or final-candidate preparation. A new invocation
SHALL make a distinct observation rather than reuse or replace an earlier run.
Unknown stages and unsupported arguments SHALL fail before fixture mutation.

#### Scenario: Run with uncommitted source and no first commit
- **WHEN** the developer selects a stage from an initialized repository with working files and no commit
- **THEN** the selected check can execute without a Git SHA or clean-tree prerequisite

#### Scenario: Continue after changing HEAD
- **WHEN** the developer creates a documentation commit between two selected-stage runs
- **THEN** the next run is allowed without requalifying earlier independent stages and the first result remains unchanged

### Requirement: Development evidence identifies actual inputs

Each development run SHALL retain a private snapshot and content manifest of
the current repository test/build inputs, including uncommitted source and
helpers, plus the selected commands and outcomes. Root-local secrets and ignored
artifacts SHALL NOT be swept into that snapshot. Existing pinned provider-asset
checksum checks SHALL remain in force. A detected input change during execution
SHALL make the observation non-passing. No cross-run cache or automatic proof of
unaffected-result reuse is introduced.

#### Scenario: Edit a helper without committing
- **WHEN** a selected check uses a modified test helper
- **THEN** the retained input snapshot contains those bytes, not the committed version

#### Scenario: Source changes while a check runs
- **WHEN** the before/after input manifests differ
- **THEN** the run retains its outcome and drift evidence but cannot report a passing observation

### Requirement: Development mode preserves fixture safety

The development runner and nested harnesses SHALL retain existing fixture
ownership, readiness, clean-state, content-verification and cleanup checks.
Host-only stages SHALL NOT invoke Lima. VM stages SHALL restore the exact
fixtures to Stopped on success, failure or handled interruption. Only explicitly
selected capacity checks SHALL run capacity. Failed prerequisites SHALL block
their dependent stage without altering the failure.

#### Scenario: Dirty-source VM check fails
- **WHEN** a selected VM stage fails in development mode
- **THEN** its failure remains visible and the existing owner-scoped cleanup and stopped-fixture verification run

### Requirement: Development observations cannot qualify a release

Development evidence SHALL be explicitly non-release, stored separately, and
SHALL NOT create `candidate.json`, `automated.json` or `final-summary.json` for
release acceptance. Nested development summaries SHALL NOT impersonate a Git
commit. Final prepare, run, resume and finalize commands SHALL retain their
existing clean-source, commit, artifact and evidence requirements regardless
of an inherited development context.

#### Scenario: Try to finalize a development run
- **WHEN** a developer supplies a development directory to final acceptance
- **THEN** it is rejected and no production-ready receipt is created
