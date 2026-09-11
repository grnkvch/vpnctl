## Purpose

Defines how the single-use v1-to-v2 migrator is isolated, qualified, executed, audited, and retired without becoming a permanent vpnctl product surface.

## ADDED Requirements

### Requirement: Operational source isolation
The v1-to-v2 migrator SHALL be built from a versioned operational source line based on one exact clean v2 product commit. Normal v2 release assets and the maintained product source line SHALL NOT contain the migration executable or migration-only implementation. A change outside the declared migration-only paths MUST be treated as a product change and MUST NOT be hidden in the operational source line.

#### Scenario: Migration-only correction
- **WHEN** only a declared migration-only path changes after a v2 product candidate and its release evidence are fixed
- **THEN** a new migrator candidate can be qualified against the unchanged product commit and bundle without invalidating or recreating that product release evidence

#### Scenario: Shared runtime correction
- **WHEN** a discovered migration defect requires a change to shared install, network, firewall, service, state, or release-bundle behavior used by ordinary v2
- **THEN** the operational workflow rejects it as migration-only work and requires a new product commit, product evidence, and product bundle

#### Scenario: Normal v2 release contents
- **WHEN** normal v2 release assets are built or verified
- **THEN** their canonical asset set contains no standalone v1 migrator

### Requirement: Exact migration candidate binding
Every migrator candidate SHALL bind the exact product commit, migration commit, release version, complete release-bundle size and SHA-256, migrator size and SHA-256, migration source contract, fixture contract, and pinned native image digest. Qualification or execution MUST fail closed when any bound value differs, is missing, or is ambiguous.

#### Scenario: Migrator tested against another bundle
- **WHEN** the supplied product bundle differs from the size or SHA-256 recorded for the migrator candidate
- **THEN** the migration gate and production runbook reject it before fixture or Gateway mutation

#### Scenario: Operational source changed after qualification
- **WHEN** migration-only source changes after a passing native result was recorded
- **THEN** that result is not reusable for the changed migrator candidate

### Requirement: Two-tier migration validation
The operational workflow SHALL provide a fast source-level suite that does not start a VM and a separate full native migration gate. The full native gate SHALL be required before production migration, while the normal product release gate and the advisory capacity gate SHALL NOT be rerun merely because migration-only source changed.

#### Scenario: Migration development iteration
- **WHEN** a maintainer changes only migration-only source
- **THEN** the fast migration suite can validate the change without starting Lima or invoking the complete product release gate

#### Scenario: Production migration readiness
- **WHEN** the migrator is proposed for transfer to the real Gateway
- **THEN** the exact migrator candidate has both passing fast evidence and passing native lifecycle evidence against its bound product bundle

### Requirement: Disposable native migration lifecycle
The native gate SHALL use an owner-scoped disposable Ubuntu 24.04 amd64 fixture with systemd, nftables, UFW, WireGuard, and the resource shape needed to reproduce the real v1 Gateway. It SHALL create a representative released-v1 installation and verify dry-run without mutation, successful apply through watchdog confirmation, retained client identity and traffic, rollback to exact working v1, a second apply, explicit acceptance, and post-acceptance v2 health. The production Gateway MUST NOT be accepted as a gate target.

#### Scenario: Full native lifecycle passes
- **WHEN** every native migration phase succeeds on the disposable fixture
- **THEN** evidence proves the initial v1 state, dry-run immutability, v2 convergence, client continuity, rollback restoration, repeated migration, acceptance, and final v2 health

#### Scenario: Native phase fails
- **WHEN** any native phase, watchdog transition, service check, firewall check, or traffic probe fails
- **THEN** the attempt remains failed, no passing aggregate is created, diagnostic evidence is retained, and owner-scoped cleanup restores or removes only the disposable fixture

#### Scenario: Non-fixture target supplied
- **WHEN** a caller attempts to direct the native gate at an arbitrary or production SSH target
- **THEN** the gate rejects the target before connection or mutation

### Requirement: Immutable migration evidence
Fast and native attempts SHALL be stored independently and append-only. Passing results SHALL be reusable only when every relevant candidate, command, source, fixture, configuration, and native-image fingerprint still matches. Failed, interrupted, malformed, or invalidated attempts MUST remain visible and MUST NOT contribute to the final passing aggregate.

#### Scenario: Native retry after failure
- **WHEN** a native attempt fails and the maintainer retries the unchanged candidate
- **THEN** a new numbered attempt is written without replacing the failed attempt

#### Scenario: Candidate inputs no longer match
- **WHEN** an earlier passing attempt has any mismatching required fingerprint
- **THEN** the workflow reports it as non-reusable and does not create final migration evidence from it

### Requirement: Owner-scoped fixture and host change accounting
Before and after every native attempt, the fixture SHALL be absent or in its declared stopped clean state. Creation, start, mutation, stop, cleanup, and any retained recovery action SHALL be recorded in the attempt evidence and the repository host-change journal. Cleanup MUST be bounded by an exact ownership marker and MUST fail closed on foreign or ambiguous state.

#### Scenario: Interrupted gate leaves residue
- **WHEN** a previous native attempt was interrupted with an owned fixture or owned residue present
- **THEN** the next invocation reports the retained state and performs only the documented owner-scoped recovery before starting another attempt

#### Scenario: Foreign fixture collision
- **WHEN** the expected fixture name or path exists without the exact ownership contract
- **THEN** the gate refuses to modify or remove it

### Requirement: Controlled production execution and retirement
The production operation SHALL use trusted SSH/SCP transfer, verify the candidate and product bundle checksums on the Gateway before migration, and append every host mutation and rollback instruction to the Gateway journal. After v2 is explicitly accepted, the deployed migrator and private rollback payload SHALL be removed, while the non-secret journals, exact checksums, native evidence, and an immutable source ref SHALL be retained for audit.

#### Scenario: Transfer is ready for execution
- **WHEN** the operator prepares the qualified migrator and bound bundle on the Gateway
- **THEN** local verification proves both exact checksums before the dry-run or maintenance mutation is allowed

#### Scenario: Migration is accepted
- **WHEN** v2 validation succeeds and the operator explicitly accepts the migration
- **THEN** rollback material and the deployed migrator are removed according to their ownership records while immutable source and evidence references remain available

#### Scenario: Migration is rolled back
- **WHEN** the operator selects rollback before acceptance
- **THEN** the existing rollback contract restores v1 and the retained evidence identifies the exact failed migrator and product bundle without rewriting either attempt
