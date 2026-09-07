## ADDED Requirements

### Requirement: Phase-selective automated release execution
The deployed release gate SHALL expose a host-only fast phase and a Lima-backed VM phase while retaining the existing full automated command as the ordered composition of both phases. `run-fast` MUST execute no Lima command and MUST NOT require Lima to be installed. `run-vm` SHALL require reusable passing evidence for every mandatory fast stage before starting a fixture. Fresh-versus-resume refusal SHALL be scoped to the selected phase, and the explicit `--resume` form SHALL retain the same immutable-attempt reuse rules as the full gate. Partial phase completion MUST NOT create `automated.json`.

Private VM-harness timing and shared-session environment variables MUST NOT be inherited by fast-stage commands or their nested test processes.

#### Scenario: Cheap candidate rejection
- **WHEN** the operator runs `run-fast` for a newly prepared candidate and a host-only stage fails
- **THEN** the failed attempt is retained, no Lima command is executed, and the operator can explicitly resume the fast phase without rerunning its matching passes

#### Scenario: Heavy phase follows a completed fast phase
- **WHEN** every mandatory fast attempt passes and the operator invokes `run-vm` for the first time
- **THEN** the gate accepts the existing fast attempts, runs only pending VM stages, and creates final automated evidence only if the complete mandatory set passes

#### Scenario: Backward-compatible full execution
- **WHEN** the operator invokes the existing `run-automated` command on a new or resumable evidence directory
- **THEN** the gate applies the same fast-then-VM ordering and produces the same logical mandatory evidence as separate phase invocations

### Requirement: Structured diagnostic phase timings
Every new stage attempt and VM session SHALL record bounded structured monotonic durations for the phases controlled by that layer, including validation/preflight, fixture startup, test execution, clean-state verification, cleanup, and fixture shutdown where applicable. Timings SHALL be diagnostic evidence only and MUST NOT alter pass/fail outcomes or existing product latency, reconnect, workload, and capacity bounds.

#### Scenario: Inspect a slow stage
- **WHEN** a stage attempt or shared VM session completes or fails normally
- **THEN** its immutable evidence identifies the measured phases and durations without requiring wall-clock reconstruction from logs

#### Scenario: Diagnostic timing exceeds a prior observation
- **WHEN** a diagnostic setup or cleanup duration is slower than an earlier run but every normative assertion remains within its existing bound
- **THEN** the timing is recorded without independently failing or relaxing the stage

### Requirement: One isolated Lima session per VM-phase invocation
Each VM-phase invocation SHALL begin with both exact pinned fixtures stopped, have the parent orchestration start each required fixture at most once, run all pending VM stages sequentially while preserving the fixtures running, and stop both fixtures before returning. The mandatory `transport-supervision` boot-recovery assertion MAY perform exactly one additional stage-owned Gateway restart; the gate SHALL record that restart separately and SHALL NOT permit any other additional fixture restart. A mandatory fail-closed clean-state witness SHALL run before the first stage and between stages, proving that all known stage-owned units, processes, ports, namespaces, files, routes, firewall objects, and temporary configuration are absent or at their documented baseline. A missing or failed witness SHALL prevent the next stage and final aggregation. On stage failure, cleanup failure, `INT`, or `TERM`, the gate SHALL apply only existing owner-scoped cleanup, stop both exact fixtures, retain the failed/interrupted evidence, and refuse success.

#### Scenario: Clean multi-stage VM pass
- **WHEN** several pending VM stages run successfully in one invocation
- **THEN** parent orchestration boots both fixtures once, only `transport-supervision` may additionally restart Gateway once for its boot-recovery assertion, every adjacent stage pair is separated by a passing clean-state witness, and both fixtures are stopped after the final stage

#### Scenario: VM stage leaves residue
- **WHEN** a VM stage reports success but its following clean-state witness finds owned residue or a changed baseline
- **THEN** the attempt does not become reusable, no later stage starts, owner-scoped cleanup runs, both fixtures stop, and `automated.json` remains absent

#### Scenario: Resume after VM failure
- **WHEN** a VM stage fails and the operator resumes the unchanged candidate after both fixtures are stopped
- **THEN** the new VM session skips matching passing attempts, begins at the first missing or non-reusable VM stage, and never adopts state from the prior VM session

### Requirement: Canonical hash-bound stage dependencies
The tunnel and ingress release harnesses SHALL each run once as canonical mandatory stage attempts. Their registry commands SHALL receive shell-quoted absolute evidence paths below their exact repository artifact roots. The release-gate failure stage SHALL execute only its unique failure assertions when selected canonical tunnel and ingress attempts are reusable, and its input fingerprint SHALL bind the exact result SHA-256 of both dependencies plus their stage contracts. A changed, missing, failed, malformed, or invalidated dependency SHALL invalidate the dependent failure attempt. Direct standalone execution of the failure harness SHALL retain its complete self-contained coverage unless explicit validated dependency evidence is supplied.

#### Scenario: Failure stage consumes canonical provider evidence
- **WHEN** canonical tunnel and ingress attempts pass for the current candidate and the failure stage runs under the top-level gate
- **THEN** the failure attempt records both dependency hashes and does not execute either complete provider release harness again

#### Scenario: Dependency result changes
- **WHEN** a selected tunnel or ingress result no longer has the exact hash recorded by a passing failure attempt
- **THEN** that failure attempt is not reusable and cannot contribute to final automated evidence

#### Scenario: Standalone failure regression
- **WHEN** a developer invokes the failure harness without top-level dependency evidence
- **THEN** it runs the canonical provider checks and unique failure assertions as a self-contained gate

### Requirement: Optimized gate preserves the release boundary
Optimization SHALL NOT remove a mandatory assertion, weaken a capacity threshold, shorten the 300-second capacity workload, parallelize conflicting VM stages, migrate or rewrite old evidence, or reuse an attempt across a source commit, release version, tracked input, stage/dependency contract, or pinned Lima image mismatch. Final `automated.json` SHALL continue to reference exact immutable passing results for the complete mandatory stage set.

The capacity harness SHALL enter its fault command on Gateway before starting measured workload processes, require a bounded exact ready/trigger handshake while the fixtures are idle, SHALL perform the manifest-defined delay inside that already-open guest command, and SHALL wait for that exact process at the fault boundary. Pre-existing, missing, timed-out, symlinked, or mistyped schedule files SHALL fail closed. This scheduling MUST NOT change the fixed fault offset, accepted failure window, outage duration, reconnect bound, request profile, or latency bounds. Failure or interruption SHALL terminate and wait for the tracked command and remove only its fixed owner-scoped schedule files before existing cleanup and fixture shutdown.

#### Scenario: Optimized candidate reaches aggregation
- **WHEN** the phase-selective optimized gate completes every mandatory stage
- **THEN** its logical checks and fixed acceptance values equal the pre-optimization contract, all failed attempts remain visible, and final aggregation succeeds only from exact matching results

#### Scenario: Fault delivery is not delayed by a loaded Lima control connection
- **WHEN** the minimum-host capacity workload reaches its manifest-defined fault offset
- **THEN** a ready and explicitly triggered already-open tracked Gateway command injects the outage after its guest-local delay, no new Lima shell must enter the loaded fixture at that boundary, and unchanged steady-state latency checks exclude only the existing accepted window
