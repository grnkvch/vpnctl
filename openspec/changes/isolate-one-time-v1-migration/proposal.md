## Why

The v1 migrator is needed for one controlled transition of one production Gateway, but it currently expands the permanent v2 source tree and turns each migration-only correction into a full product release cycle. The real Gateway has also exposed migration defects that should have been found first on a disposable native Ubuntu fixture.

## What Changes

- Move migration-only source, orchestration, tests, and documentation to a versioned operational source line based on an exact v2 candidate commit; keep reusable v2 runtime fixes in the product source line.
- Remove the standalone migrator from normal v2 release artifacts and from the maintained post-migration product surface.
- Add a dedicated disposable Ubuntu 24.04 migration gate that exercises realistic v1 discovery, dry-run, apply, watchdog recovery, rollback, repeated apply, acceptance, and v1/v2 traffic validation without using the production Gateway as a development fixture.
- Split migration validation into a fast source-level loop and an explicit full native lifecycle gate required before the one-time production operation.
- Bind the operational migrator, migration evidence, and host journal to the exact product commit, release bundle, fixture contract, and binary checksums; retain failed attempts without treating them as passes.
- Remove the deployed migrator after explicit acceptance while preserving an immutable source ref and evidence for audit and incident recovery.
- Keep the existing product release evidence model, `release.sh` verification, and on-demand capacity policy unchanged.

## Capabilities

### New Capabilities

- `one-time-migration-operations`: Versioned isolation, native pre-deployment qualification, immutable evidence, execution, acceptance, and retirement of the single-use v1-to-v2 migrator.

### Modified Capabilities

None. The original v2 capability is still under an active change; this change adds the operational contract that governs how its one-time migration requirement is delivered and retired.

## Impact

- Affected source: `cmd/vpnctl-v1-migrate`, migration-only files under `internal/lifecycle`, `scripts/migrate-v1-to-v2.sh`, migration fixtures, operational documentation, traceability, and release/deployment checks.
- Affected workflow: maintainers use a dedicated operational branch/ref and migration evidence instead of rebuilding the complete product release for migration-only edits.
- Affected systems: disposable Lima Ubuntu fixtures and the one existing v1 Gateway. No new public vpnctl v2 command or steady-state daemon is introduced.
