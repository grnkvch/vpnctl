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
Every new stage attempt and VM session SHALL record bounded structured monotonic durations for the phases controlled by that layer, including validation/preflight, fixture startup, test execution, clean-state verification, cleanup, and fixture shutdown where applicable. A fixture-start/readiness failure SHALL retain and seal an immutable failed session with the actual elapsed startup/shutdown timings, an empty witness list when no witness was reached, its diagnostic log, and an explicit resume command. Timings SHALL be diagnostic evidence only and MUST NOT alter pass/fail outcomes or existing product latency, reconnect, workload, and capacity bounds.

#### Scenario: Inspect a slow stage
- **WHEN** a stage attempt or shared VM session completes or fails normally
- **THEN** its immutable evidence identifies the measured phases and durations without requiring wall-clock reconstruction from logs

#### Scenario: Diagnostic timing exceeds a prior observation
- **WHEN** a diagnostic setup or cleanup duration is slower than an earlier run but every normative assertion remains within its existing bound
- **THEN** the timing is recorded without independently failing or relaxing the stage

### Requirement: One isolated Lima session per VM-phase invocation
Each VM-phase invocation SHALL begin with both exact pinned fixtures stopped, have the parent orchestration start each required fixture at most once, atomically install and SHA-256-verify the exact topology-owned lab report/fault helpers on both fixtures before the first witness, run all pending VM stages sequentially while preserving the fixtures running, and stop both fixtures before returning. Helper source, destination, mode, and bytes SHALL be fingerprinted; missing or mismatching setup SHALL fail before any VM stage and SHALL retain the same immutable failed-session/resume evidence as fixture startup failure. The mandatory `transport-supervision` boot-recovery assertion MAY perform exactly one additional stage-owned Gateway restart; the gate SHALL record that restart separately and SHALL NOT permit any other additional fixture restart. A mandatory fail-closed clean-state witness SHALL run before the first stage and between stages, proving that all known stage-owned units, processes, ports, namespaces, files, routes, firewall objects, and temporary configuration are absent or at their documented baseline. A missing or failed witness SHALL prevent the next stage and final aggregation. On stage failure, cleanup failure, `INT`, or `TERM`, the gate SHALL apply only existing owner-scoped cleanup, stop both exact fixtures, retain the failed/interrupted evidence, and refuse success.

Each witness MAY inspect the two independent fixtures concurrently and SHALL batch repeated read-only observations within a fixture, but MUST preserve the complete manifest, unknown owner-marker search, one-pass executable inspection, every resource-class assertion, and the sequential stage boundary. Batching SHALL NOT parallelize VM stages or introduce a cleanup mutation.

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

The capacity harness SHALL enter its fault command on Gateway before starting measured workload processes, require a bounded exact ready/trigger handshake while the fixtures are idle, SHALL perform the manifest-defined delay inside that already-open guest command, and SHALL wait for that exact process at the fault boundary. Pre-existing, missing, timed-out, symlinked, or mistyped schedule files SHALL fail closed. This scheduling MUST NOT change the fixed fault offset, scheduling sanity bound, outage duration, reconnect bound, request profile, fixed 2,890 webhook-success minimum, or product latency bounds. Failure or interruption SHALL terminate and wait for the tracked command and remove only its fixed owner-scoped schedule files before existing cleanup and fixture shutdown.

Every webhook request SHALL retain a sanitized bounded lifecycle record containing scheduled order and offset, actual start, completion, response latency, dispatch lag, status, and error class. The first webhook failure within the fixed 135–175-second scheduling sanity bound SHALL freeze the client disruption start. The latest completion of the first five consecutive later webhook successes that each complete within the existing 2,000 ms bound SHALL freeze its end. The end SHALL NOT be recomputed after a later failure. The interval MUST NOT exceed 11.5 seconds, every failure outside it MUST fail the gate, and the independent fixed success minimum MUST still pass.

Pre-disruption and post-recovery webhook success latency SHALL be asserted as separate samples against the unchanged p95 and p99 bounds. Fault-intersecting requests MAY be excluded only from those two steady-state samples and SHALL remain represented in disruption and global success evidence. Global and pre/post webhook dispatch-lag p99 plus global Bot API dispatch-lag p99 SHALL each be at most 1,000 ms, and no request in either final scheduled 30-second tail MAY exceed that lag bound. Bot API failures and latency SHALL remain globally asserted without a fault exclusion. A reconnect failure after workload start SHALL retain bounded transport diagnostics captured by monitors already running across the fault window, allow only the already-started fixed-duration workloads to finish, emit a failed summary, and perform the existing owner-scoped cleanup.

Before the unchanged measured workload, both paths SHALL complete one versioned ten-second warm-up at the same 10/s webhook and 5/s Bot API rates; warm-up requests MUST all complete successfully and SHALL NOT enter measured counts or percentiles. Generator concurrency SHALL be the checked-in rate times the unchanged eight-second request timeout plus 20% headroom: 96 webhook workers and 48 Bot API workers. These values, warm-up, and timeout SHALL be fingerprinted and SHALL NOT alter the 300-second duration, 3,000/1,500 scheduled requests, request rates, fault schedule, or any acceptance threshold.

The normative minimum-capacity resource profile SHALL apply only to the exact Gateway role: 1 vCPU, 512 MiB RAM, 10 GiB disk, and 1 GiB managed swap. The exact shared Node role SHALL use the checked-in 4-vCPU/2-GiB/10-GiB profile and retained managed swap as functional/load infrastructure. Node resource values MUST NOT be compared with the Gateway acceptance thresholds, but Node OOM, service crash, failed functional checks, or incomplete workload MUST fail or invalidate the attempt. No capacity command MAY resize a VM.

The role names, template paths, CPU, memory, disk, swap, pinned image digest, isolated network, exact readiness-probe metadata and script SHA-256, and capacity responsibility SHALL form one versioned topology contract. Every reusable VM attempt, shared session, and final aggregate SHALL bind its exact contract SHA-256; a topology/profile change or drifted live fixture SHALL invalidate or refuse evidence before session allocation or VM mutation. A resource-only metadata edit that retains a stale readiness probe SHALL remain drift and require explicit replacement of only the stopped disposable fixture from its checked-in template.

Capacity evidence SHALL report independent `gateway_capacity`, `node_fixture_health`, `load_generator_validity`, `fault_reconnect`, `client_disruption`, and `steady_state_latency` domains. Load-generator validity SHALL require both scheduled counts, completion of every scheduled request, the predeclared dispatch-lag bounds, no persistent post-recovery queue, and a backlog/error-free final scheduled 30 seconds. An invalid generator or unhealthy Node SHALL never pass and SHALL be distinguished from a proven Gateway-capacity rejection. Prestarted resource timelines SHALL retain load average, run queue, CPU busy, iowait, and steal plus bounded FRPC/supervisor/unit/process/TCP-state evidence around the fault without a new boundary-time Lima session.

Required Gateway and Node monitors SHALL use one bounded batched systemd snapshot before and after measurement for authoritative restart counters. During the measured interval they MUST NOT spawn systemd queries; each fault-window sample SHALL instead read direct cgroup-v2 population and bounded process state for every declared unit. Only the exact Gateway FRPS fault unit MAY have an absent cgroup during the declared outage; an absent cgroup for any other unit is a structured monitor error. Collection SHALL retain sanitized unit/offset/error-class records and continue after a malformed or unavailable required observation, but any degraded required monitor MUST classify the aggregate as `invalid_measurement_evidence`, MUST remain non-passing, and MUST NOT by itself assert Gateway saturation. The managed-swap profile SHALL continue to require an exact one-GiB allocation while recognizing only the versioned 4,096-byte kernel metadata reservation in observed `SwapTotal`; swap-use and all other resource thresholds remain unchanged.

#### Scenario: Optimized candidate reaches aggregation
- **WHEN** the phase-selective optimized gate completes every mandatory stage
- **THEN** its logical checks and fixed acceptance values equal the pre-optimization contract, all failed attempts remain visible, and final aggregation succeeds only from exact matching results

#### Scenario: Fault delivery is not delayed by a loaded Lima control connection
- **WHEN** the minimum-host capacity workload reaches its manifest-defined fault offset
- **THEN** a ready and explicitly triggered already-open tracked Gateway command injects the outage after its guest-local delay, no new Lima shell must enter the loaded fixture at that boundary, and the first client-visible impact is inside the fixed scheduling sanity bound

#### Scenario: Fault tail crosses the scheduling window
- **WHEN** an in-flight or queued request affected by a correctly scheduled bounded outage completes after the fixed 175-second sanity boundary
- **THEN** it remains disruption evidence, does not pollute either steady-state latency sample, and cannot move the already frozen recovery boundary

#### Scenario: Degradation continues after recovery
- **WHEN** a request fails, steady-state latency exceeds its unchanged bound, or dispatch backlog exceeds its generator-validity bound after the first stable recovery cohort
- **THEN** the gate fails without enlarging or reopening the client disruption interval

#### Scenario: Reconnect fails during measured load
- **WHEN** FRP does not produce stable recovery within eight seconds
- **THEN** the bounded workloads and immediate diagnostics are retained in a failed capacity summary, no passing stage result is produced, and owner-scoped cleanup restores both fixtures

#### Scenario: Load-generating Node is saturated
- **WHEN** the Node cannot dispatch or complete the fixed workload within the declared generator-validity contract
- **THEN** the attempt remains non-passing, records `invalid_load_generation` with Node/worker diagnostics, and does not claim that the Gateway exceeded its capacity

#### Scenario: Role profile drifts
- **WHEN** either exact live fixture or its evidence differs from the checked-in role-specific topology contract
- **THEN** the VM phase refuses before mutation or invalidates reuse, without resizing the instance inside the gate

#### Scenario: Fixture readiness fails during parent startup
- **WHEN** an exact preflighted fixture fails to start or satisfy readiness
- **THEN** the parent restores both fixtures stopped, seals a non-reusable failed session with measured startup/shutdown timing and any zero-or-more completed witnesses, and prints the diagnostic log and explicit resume command

#### Scenario: Fresh fixture has no historical lab helpers
- **WHEN** an exact fixture created from its checked-in template reaches readiness without either lab helper on its new disk
- **THEN** the parent installs only the exact topology-owned helper bytes and modes, verifies their guest SHA-256 before the first witness, and either proceeds self-contained or fails and stops both fixtures before any VM stage

#### Scenario: Capacity runtime diagnostics observe a loaded Gateway
- **WHEN** the fault-window monitor samples declared services while the one-vCPU Gateway carries the measured workload
- **THEN** it reads cgroup-v2 state without spawning systemd commands, retains structured degraded evidence if a required observation is malformed, and never converts missing telemetry into a Gateway-saturation claim

#### Scenario: Load path starts cold
- **WHEN** the capacity fixture has just completed provider and connection-limit setup
- **THEN** both paths must pass the separate fixed warm-up before the unchanged 300-second measured workload and its pre-disruption percentiles begin

#### Scenario: Clean-state manifest has many entries
- **WHEN** a between-stage witness checks the two running fixtures
- **THEN** it may batch each resource-class snapshot and inspect the fixtures concurrently while preserving every declared absence check and the sequential stage boundary
