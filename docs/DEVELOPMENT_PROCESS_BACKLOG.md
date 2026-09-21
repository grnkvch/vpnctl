# Development Process and Infrastructure Backlog

This backlog records deferred improvements to repository guidance, agent
workflows, release orchestration, evidence handling, and development
infrastructure. It is intentionally separate from the product backlog in
[`BACKLOG.md`](BACKLOG.md).

The baseline for this list is the completed `complete-gateway-bootstrap`
candidate `04cb94c371ba44a7f4a51b63d6705468c06b27fa` and its passed 18-stage
deployed release gate. These items do not change that candidate retroactively.
These are optional, separately scoped improvements, not an additional MVP or
discovery gate. Choose work by an observed current cost or risk, not merely its
presence in this backlog. Avoid disturbing an active rollout.

## Process decision — 2026-09-21

The root [AGENTS.md](../AGENTS.md) defines development/discovery as the default:
cover the available end-to-end path, retain independent failures, then group
nonblocking fixes. Use targeted regressions and explicit final qualification,
not a full release cycle after each edit. Git SHA is optional provenance during
development/discovery; changing a commit alone does not invalidate observations.
Keep exact tested inputs and artifact checksums, failed attempts and cleanup.

The [release-gate guide](v2/DEPLOYED_RELEASE_GATE.md) separates this workflow
from the current strict final runner. Its commit/tree enforcement is not yet
changed. No new fingerprint framework, journal migration or preflight system is
required to use the development policy; those implementations remain deferred.

## Working rules

- Do not mix these items into a production rollout or incident response.
- Give each implementation its own OpenSpec change when it changes a runtime,
  evidence, or release contract. Pure documentation changes may remain a
  reviewed documentation-only commit.
- Preserve existing failed attempts and host history; never rewrite them to
  make a new workflow appear cleaner.
- Prefer an automated invariant in a script or test over duplicating detailed
  shell instructions in `AGENTS.md`.
- Verify process changes in proportion to their impact: documentation needs
  diff, link and consistency review; runtime/evidence tooling also needs focused
  tests and explicit compatibility/rollback boundaries. Do not require a VM
  run or new infrastructure to finish a documentation-only rule.

## Priority order

| ID | Priority | Item | Primary owner |
| --- | --- | --- | --- |
| `REL-001` | P0 | Canonical release repository and distribution endpoints | release/docs/tests |
| `REL-002` | P0 | Publication-tool and remote-state preflight | release tooling |
| `PROC-001` | P1 | ~~Root `AGENTS.md` and authority map~~ — completed | repository guidance |
| `PROC-002` | P1 | Candidate and operations workspace separation | Git/evidence contract |
| `PROC-003` | P1 | Host-journal archival and compact active ledger | documentation/evidence |
| `GATE-001` | P1 | Hermetic VM release-gate plan and preflight | gate orchestration |
| `GATE-002` | P1 | Declarative stage prerequisites and fingerprints | stage registry/tests |
| `GATE-003` | P1 | Fixture baseline and package-actor guard | VM harness/tests |
| `REL-003` | P1 | Split build, test, verify, and publish commands | release scripts/tests |
| `REL-004` | P1 | Exact production-helper retention | release evidence/runbooks |
| `PROC-004` | P2 | Session checkpoints and retrospective skill | repository-local skill |
| `TOOL-001` | P2 | CWD-independent manifest verification | helper/test |
| `TOOL-002` | P2 | Owner-safe cache cleanup and no-write validation | helper/test |
| `PROC-005` | P2 | Bounded output and long-operation status protocol | guidance/skill |

Unresolved P0 release-readiness defects must be resolved before publication.
P1/P2 express relative priority, not deadlines or mandatory prerequisites for
the next candidate cycle. Schedule them only when their benefit justifies the
cost; neither class blocks an authorized discovery pass by itself.

## Release readiness

### REL-001 — Canonical release repository and distribution endpoints

Observed on 2026-09-16: Git `origin`, the updater, and the production handoff
use `grnkvch/vpnctl`; the default v2 installer and public installation examples
use `vgrinkevich/vpnctl`. The former public repository exists and the latter
returns HTTP 404. Go module/import identity is a separate compatibility
decision and must not be changed accidentally as part of a URL correction.

Deliverables:

- choose one canonical release repository;
- centralize its distribution value for installer, updater, documentation, and
  release tooling where technically possible;
- decide explicitly whether the historical Go module path remains unchanged;
- add a regression that rejects disagreement among online installation,
  updater, and publication endpoints;
- document how a repository rename or transfer is handled without relying on
  an unverified redirect.

Done when online installation and update resolve the same published release,
all examples are executable, and the chosen module-path compatibility policy
is tested or explicitly documented.

### REL-002 — Publication-tool and remote-state preflight

The production handoff currently assumes `gh release create`, while the
development host used for final preparation did not have `gh` installed. Tag
and release absence were checked through other read-only mechanisms, but this
should be discovered before the publication boundary, not during it.

Deliverables:

- define the supported authenticated publication mechanism and its minimum
  version;
- add a read-only preflight for authentication, repository ownership, default
  branch, tag absence, release absence, and exact local candidate identity;
- fail before creating a tag if any publication prerequisite is unavailable;
- retain a machine-readable preflight result without credentials;
- keep tag creation, tag push, release creation, and public asset verification
  as separate authorization and rollback boundaries.

Done when an unprepared workstation cannot begin publication and a prepared
one can prove the complete remote pre-state without mutation.

## Repository process

### PROC-001 — Root `AGENTS.md` and authority map

Status: completed 2026-09-21 in the separately authorized documentation task.
The root [AGENTS.md](../AGENTS.md) supplies the authority map and stable safety,
discovery-versus-acceptance, nonblocking-failure, candidate and journal rules.
Document/link review is the verification; no new agent session, product test,
VM/VPS action or journal migration is claimed. `PROC-002` through `PROC-005`
retain their separate implementation/verification requirements.

Create a concise root `AGENTS.md` containing only stable repository rules:
worktree safety, test escalation, candidate identity, host/VM ownership,
evidence and secret handling, communication cadence, and stopping conditions.
It must link to authoritative product and operator documents instead of
copying them, and it must not contain current commits, VM state, usernames,
attempt numbers, or release-specific package versions.

Done when a new session can locate the correct OpenSpec, test, release,
operations, evidence, and journal authority without reading historical
transcripts, and a review finds no dynamic project state in the file.

### PROC-002 — Candidate and operations workspace separation

For final qualification, separate immutable tested inputs from operation plans,
host results and later documentation. Development/discovery does not require a
frozen checkout or a commit before testing. This task is deferred tooling work,
not a condition for starting discovery.

Deliverables:

- exact candidate artifacts and relevant source/helper/configuration inputs;
  Git commit/tree hashes may be retained as provenance, not the sole validity key;
- a dedicated candidate checkout/worktree when needed for final qualification;
- run-local pre/post operation record inside the evidence directory;
- optional separate operations worktree when tracked pre-entries are required;
- later metadata commits must not relabel evidence or invalidate unchanged
  tested inputs solely because HEAD moved;
- tooling that detects drift in actual tested inputs without deleting user
  changes or rejecting an unrelated documentation edit. The existing strict
  final runner remains unchanged until this is implemented and verified.

Done when release evidence, operational records, and tracked summaries can all
advance without split-brain paths or mutation of the frozen checkout.

### PROC-003 — Host-journal archival and compact active ledger

At the 2026-09-16 checkpoint, `docs/v2/HOST_CHANGELOG.md` had grown to 8022
lines and mixed actual host mutations with plans, source work, test summaries,
diagnostics, and next-session instructions.

Deliverables:

- preserve the complete current file as an immutable tracked archive with a
  clear date and commit boundary;
- create a compact active journal for completed external mutations,
  outstanding cleanup, and evidence links only;
- store the pre-mutation plan and detailed transcript in immutable run-local
  evidence, then promote a concise reviewed result to the tracked ledger;
- define a single entry template and archive rotation policy;
- update references in operator and test-lab documentation.

Done when source-only work no longer changes the host journal, historical facts
remain reachable, and current host obligations can be found without scanning
the archive.

### PROC-004 — Session checkpoints and `review-agent-session` skill

Create a repository-local skill for long-running work. It should maintain a
small session identity, append-only significant events, a bounded current
checkpoint, and a final evidence-backed retrospective across context
compaction. It must distinguish observed facts, hypotheses, user decisions,
and pending recommendations, and it must never modify normative guidance
without a separate reviewed change.

Done when start/checkpoint/finalize flows are validated on a sanitized fixture,
concurrent session IDs do not collide, secrets are rejected, and recovery after
context compaction resumes from the recorded next action rather than repeating
completed work.

### PROC-005 — Bounded output and long-operation status protocol

Add stable guidance for focused searches and user-visible progress during
long-running gates. Evidence directories should be excluded from broad text
searches unless explicitly targeted, tool output should be bounded, and an
active long operation should report its phase, last result, and next decision
point at least once per minute.

Done when the rule is represented in `AGENTS.md` or the retrospective skill and
the standard handoff template contains a concise phase/status field.

## Release-gate infrastructure

### GATE-001 — Hermetic VM plan and preflight

Extend the existing deployed release gate with read-only `plan-vm` and
host-side `preflight-vm` operations before Lima starts. The preflight should
show every mandatory stage and its reuse state, materialize pinned provider
assets, create fresh evidence-scoped Go caches, and prove the complete offline
module graph and exact pending build targets.

It must distinguish source, asset, dependency, fixture, product, cleanup, and
orchestration failures and must not create a product attempt when a host
prerequisite fails.

Done when a clean checkout with a missing asset, direct-only module cache,
empty extracted module, stale negative build cache, or undeclared network
dependency fails before any VM starts.

### GATE-002 — Declarative stage prerequisites and fingerprints

Deferred: do not build a caching/fingerprint framework to unblock ordinary
development. First prove that a smaller change cannot remove the observed cost.

Move provider hashes, Go build targets, cache contracts, fixture roles,
dependencies, and cleanup adapters into the versioned stage registry or a
referenced manifest. A prerequisite or command change must alter the stage
contract fingerprint and invalidate incompatible reuse.

Target identity is the actual per-stage inputs, not HEAD or the complete Git
tree. Git commit hashes should be optional provenance rather than independent
reuse blockers. Preserve exact product assets, test oracle/helper/configuration,
dependency/environment inputs and original failed attempts. Identical product
binaries do not permit reuse after a relevant test predicate changed: rerun
that predicate and its consumers. Missing input equivalence cannot establish
reuse. The final runner still enforces its existing same-source contract until
a separately implemented and tested change updates code and OpenSpec together.

Done when preflight derives its checks from the same versioned data used by
execution, with regression coverage for fingerprint invalidation and no
second hand-maintained prerequisite list. Include unchanged inputs under a new
commit, unrelated docs-only edits, changed test predicates and missing input
identity. Do not silently migrate or relabel old sealed receipts.

### GATE-003 — Fixture baseline and package-actor guard

Add one machine-readable clean-state baseline before the first product stage.
It should reject stale owner markers, package journals, forbidden packages,
listeners, services, and runtime residue. Package-mutating stages must handle
APT locks and background timers through a bounded owner-scoped guard, record
their pre-state, and restore it during cleanup.

Done when a baseline failure runs no product stage, leaves both fixtures in the
declared stopped state, and independently verifies timer/package-manager and
runtime cleanup.

## Release construction and evidence

### REL-003 — Split build, test, verify, and publish commands

Replace the coarse release script with composable commands for tests, asset
construction, asset verification, and publication preparation. A build-only
path may skip tests only when it receives an exact frozen candidate and passed
evidence satisfying a documented contract; it must never silently weaken the
normal release path.

Done when production assets can be reproduced without re-running unrelated
tests, the default end-to-end command remains strict, and regression tests
cover misuse of the build-only boundary.

### REL-004 — Exact production-helper retention

Any script that may execute on production must be retained before rehearsal as
an exact versioned or content-addressed input artifact. Evidence must contain
the bytes, hash, invocation contract, sanitized result, and cleanup boundary;
a result plus a remembered hash is insufficient.

Done when the handoff can copy the exact rehearsed helper without
reconstruction and verification rejects any byte drift.

## Tooling ergonomics

### TOOL-001 — CWD-independent manifest verification

Provide a verifier that resolves relative entries against the manifest's own
directory, checks file type before hashing, and reports one bounded result. Add
regressions for invocation from the repository root, the artifact directory,
and an unrelated directory.

### TOOL-002 — Owner-safe cache cleanup and no-write validation

Provide narrow helpers for temporary Go caches and read-only syntax checks.
Cleanup must validate the exact realpath, expected owner, and approved temp
root before restoring owner write permission inside that root and deleting it.
Syntax validation must avoid implicit `__pycache__` writes or place them in an
explicit owner-scoped directory.

Done when read-only checks create no unexpected files and a deliberately
read-only Go module cache can be removed without broad permissions or globs.

## Optional implementation order

This is a menu for separately selected work after a safe boundary, not a
waterfall the product must finish before continuing:

1. Complete `REL-001` and `REL-002` if they were not already resolved as
   release blockers.
2. `PROC-001` is complete. Select the remaining `PROC-002` or `PROC-003` only
   when their evidence/journal work is justified; guidance creation does not
   make those migrations complete.
3. Implement `GATE-001`, `GATE-002`, and `GATE-003` through a dedicated
   OpenSpec change with deterministic fixtures.
4. Implement `REL-003` and `REL-004` as a release-tooling change.
5. Add `PROC-004`, then finish the smaller `TOOL-*` and `PROC-005` items.

Re-evaluate priorities after the first controlled real-VPS run. New evidence
may change ordering, but it should add or refine backlog items rather than be
silently converted into permanent repository rules.
