## Context

See `proposal.md` for motivation. The current schema-v2 attempt ledger makes late retries cheap only while the source commit is unchanged. A clean candidate still starts and stops the same constrained QEMU/amd64 gateway and node in five self-managed stages and once more for the final shared stages. Retained evidence shows that repeated fixture lifecycle accounts for roughly 18 minutes, while `failure` additionally repeats the complete tunnel and ingress release harnesses that the top-level gate later runs again.

The child harnesses already distinguish fixtures they started from fixtures that were running at entry and apply owner-scoped cleanup. This permits a shared parent session, but merely leaving the VMs running is insufficient: every stage needs a positive, bounded clean-state witness so later evidence cannot depend on residue.

## Goals / Non-Goals

**Goals:**

- Reject source/test failures without installing or invoking Lima.
- Reduce clean-gate time structurally by eliminating repeated VM lifecycle and duplicate provider release runs.
- Preserve independent immutable attempts, explicit resume, current thresholds, and final evidence semantics.
- Make stage, setup, cleanup, and VM lifecycle time directly measurable.

**Non-Goals:**

- Changing production vpnctl behavior or its public CLI.
- Shortening workload durations or tuning acceptance values from the observed failures.
- Parallel VM boot or parallel execution of stages sharing ports/namespaces/units.
- Disabling Ubuntu background services, changing the pinned image/architecture, retaining installed nginx, or adding an APT cache.
- Canonicalizing every repeated standard/routing/tunnel subtest in this change.

## Decisions

### 1. Preserve the full command and add two phase commands

The script will expose:

```text
run-fast [--resume] <evidence-directory>
run-vm [--resume] <evidence-directory>
run-automated [--resume] <evidence-directory>
```

`run-automated` remains the compatibility path and calls the same fast phase followed by the same VM phase. `run-fast` contains traceability, strict OpenSpec, ordinary Go, race, vet, credential lifecycle, and update/restore. It performs candidate/ledger validation but does not resolve, inspect, or execute `limactl`. `run-vm` refuses until all fast attempts are reusable.

The private child timing path and shared-Lima-session marker are supplied only to VM harness commands. Fast commands explicitly remove both variables from their child environment, including when the operator's shell already defines them, so a full Go regression cannot mistake the enclosing attempt timing file for its own nested harness output.

Fresh-attempt refusal is phase-scoped: a first `run-vm` is valid after completed fast attempts, but a second invocation with an existing non-passing VM attempt requires `run-vm --resume`. `run-automated` without `--resume` still requires an empty complete ledger. This keeps retries explicit without forcing the split workflow to pretend that its second phase is an error recovery.

Alternatives considered:

- `run-automated --phase fast|vm` keeps one verb but makes `--resume` ordering verbose and error-prone.
- Making every invocation implicitly resumable weakens the deliberate audit boundary already accepted for the gate.

### 2. Bump the attempt/session contract and store monotonic timing objects

New candidates use automated-attempt schema 2. Completed attempt `result.json` adds a bounded `timings` object; completed fixture sessions gain immutable `input.json` and `result.json` beside `session.log`. Durations use a monotonic clock and integer milliseconds. UTC timestamps remain correlation metadata only.

The parent records its validation, command execution, clean-state witness, fixture boot, and shutdown durations. Its command wrapper always produces the minimum child timing document with `execute_ms`; instrumented VM child harnesses receive the same private explicit output path and replace that minimum with their major owned phases (source/build checks, provider setup, verification/load, cleanup). The parent validates and hashes the resulting timing document before sealing the attempt. A missing or malformed timing file is a stage failure for the new schema; duration magnitude is never a new acceptance bound.

Interrupted schema-2 attempts/sessions remain unsealed and non-reusable. Schema-1 evidence is neither upgraded nor rewritten.

Alternatives considered:

- Parsing Lima logs and artifact mtimes preserves ambiguity and cannot reliably separate cleanup from verification.
- Using wall time for duration makes measurements vulnerable to guest/host clock adjustment.

### 3. Use one sequential, owner-scoped VM session with explicit witnesses

At `run-vm` entry both exact fixtures must match pinned name, image digest, QEMU/amd64, CPU, memory, disk, network, and `Stopped` state. The parent creates a new immutable session record, starts gateway and node once, validates both as `Running`, and then executes only missing/non-reusable VM attempts sequentially. The existing `transport-supervision` boot-recovery assertion is the sole explicit exception: it may perform one additional Gateway stop/start cycle inside the shared session. That restart is recorded separately in timing evidence, is surrounded by clean-state witnesses, and does not permit any other stage or the parent orchestration to restart a fixture.

A checked-in clean-state manifest enumerates the complete known test-owned surface on each fixture: exact roots/files, systemd units and drop-ins, process executable prefixes, TCP/UDP listeners, network namespaces, nftables tables/chains, policy-routing tables/priorities, temporary routes/interfaces, and package state that individual stages may change. The witness captures the relevant baseline immediately after boot and requires that baseline plus absence of every owner-marked stage resource before the first attempt and after each attempt cleanup. It emits a sanitized bounded JSON record whose SHA-256 is bound into the adjacent attempt/session result.

Each child harness continues to own and validate its resources. On nonzero exit the child's existing trap runs first. The parent then runs the witness. If a successful child leaves residue, the parent changes that attempt to failed. If residue exists after any failure, a stage-to-cleanup-command map may invoke only that harness's existing owner-checking cleanup entrypoint; no generic path deletion, process match, firewall flush, or cleanup of partial/foreign ownership is introduced. Both VMs are then stopped in node-before-gateway order and verified `Stopped` before the command returns.

`INT` and `TERM` use explicit nonzero signal exits and the same cleanup/stop path. An uncatchable host failure can leave VMs running; the next invocation refuses before mutation and prints the exact owner-scoped recovery action instead of adopting the session.

The initial VM order is fail-fast and dependency-aware: short functional/supervision/watchdog stages precede broad capability suites, canonical tunnel and ingress precede their dependent unique failure stage, and the fixed five-minute capacity stage runs last. Ordering is part of the session and stage contract fingerprint.

Alternatives considered:

- Trusting a child exit code without a witness permits cross-stage contamination.
- Recreating the VM for every stage is safer by isolation but is the measured dominant cost.
- Snapshot rollback risks hiding lifecycle cleanup defects and changes the evidence environment.

### 4. Make provider release attempts canonical dependencies of failure

The top-level VM order runs `tunnel-release` and `ingress-release` exactly once. `v2failure-e2e.sh` gains a unique-only mode accepting exact dependency evidence paths and expected result hashes. It validates candidate commit, release version, stage contract, Lima digest, passed status, immutable modes, and result SHA before skipping the nested provider release commands. Its own attempt input and contract hash include both dependency result hashes and the dependency ordering/version.

The existing standalone `v2failure-e2e.sh verify` remains self-contained and still invokes both provider release gates. Thus developer use does not silently lose coverage, while the top-level gate avoids roughly nine minutes of duplicate execution.

Canonical provider commands receive a shell-quoted absolute evidence path rendered from the validated repository root. The registry stores an explicit `{repository}` placeholder, so the path requirement is part of its versioned command contract rather than an implicit current-working-directory assumption.

If either selected dependency changes or becomes non-reusable, `failure` becomes non-reusable. Final aggregation validates the full dependency graph in addition to all selected attempt hashes.

Alternatives considered:

- Merely deleting the nested commands loses standalone failure coverage and leaves no evidence link.
- Treating log text as proof is not stable or cryptographically bound.

### 5. Keep the complete acceptance set explicit

Fast and VM stage lists, order, dependencies, and commands are versioned data used by both execution and aggregation rather than duplicated free-form shell lists. Regression tests compare the optimized mandatory check set and capacity manifest values with the pre-optimization contract. No phase can write `automated.json`; only the common aggregator can do so after all fast and VM attempts, dependencies, clean-state witnesses, and final stopped-state checks pass.

### 6. Enter the capacity fault guest before measured load

Retained real attempts showed that invoking a new `limactl shell` at the nominal 145-second fault offset can take roughly 14 seconds while both minimum fixtures are loaded. The actual outage therefore moved to about 159 seconds while the fixed accepted window remained 135–175 seconds, allowing recovery-tail latency to contaminate the steady-state p99.

The host now starts the fault command before the workload and waits for a fixed root-only readiness marker proving that the guest command has entered. The fault helper boundedly waits for a fixed trigger. The host creates that trigger while the fixture is still idle and only then starts the same monitors, five clients, webhook load, and Bot API load; the already-open guest process performs the manifest-defined 145-second delay. The fault helper performs policy mutation and arms timeout-sensitive probes after the delay, so it adds no polling worker or altered restart policy during the steady-state prefix. Its local PID and fixed schedule files are explicitly included in signal/failure cleanup. The 300-second duration, 145-second target, 135–175 accepted window, three-second outage, reconnect bound, request counts, latency thresholds, and product configuration remain unchanged.

Alternatives considered:

- Advancing the host call by an observed fixed number of seconds would encode one machine's Lima dispatch latency and could inject outside the window on a faster host.
- Widening the accepted window or raising p99 would hide the orchestration defect by weakening the release boundary.

### 7. Separate capacity scheduling, disruption, and steady-state evidence

The fixed 135–175-second interval remains only a sanity bound for the first client-visible fault impact. It no longer defines the latency sample. Every scheduled webhook result records its fixed request index, scheduled offset, actual start, completion, response latency, and dispatch lag. These sanitized records are bounded by the unchanged 3,000-request profile and retained in failed as well as passing evidence.

The client-observed disruption begins at `D0`, the actual start of the first failed webhook request. `D0` must be within the fixed sanity bound. Results are then processed once in scheduled-request order. The first five consecutive valid HTTP 200 webhook results whose end-to-end time from scheduled dispatch through completion is no greater than the unchanged 2,000 ms webhook p99 bound form the stable recovery cohort. `D1` is the latest completion time in that first cohort and is frozen; a later failure cannot reopen or extend the interval. A request is fault-affected only when it was scheduled before `D1` and completed at or after `D0`, which includes in-flight and queued work without extending either boundary from an arbitrary slow tail.

The disruption duration `D1 - D0` must not exceed 11.5 seconds: the existing maximum accepted 3.5-second physical outage (the requested three seconds plus the existing 0.5-second upper tolerance) plus the unchanged eight-second reconnect bound. The existing gateway-local FRPS downtime, unavailable-503, stable reconnect, and no-client-service-restart checks remain independent. The fixed global minimum of 2,890 successful webhooks also remains independent, so dynamic classification cannot grant a larger failure budget.

Webhook latency is reported and asserted separately for successes completed before `D0` and successes scheduled at or after `D1`; requests intersecting the disruption are reported but excluded from both steady-state percentiles. Each pre- and post-disruption segment must independently satisfy p95 at most 1,000 ms and p99 at most 2,000 ms. Every failure outside the frozen disruption and every failure in the final scheduled 30 seconds remains fatal.

Dispatch lag is generator-validity evidence, not product response latency. Global and pre/post-disruption webhook p99 plus global Bot API p99 must each remain at most 1,000 ms. This deliberately coarse bound is ten webhook scheduling periods and detects multi-second executor backlog without reclassifying it as service latency or absorbing it into the dynamic disruption. Bot API correctness and latency continue to cover its entire workload because an FRPS reverse-tunnel outage is not an allowed exception for the independent outbound path. Every request scheduled in the final 30 seconds must also remain within the 1,000-ms lag bound, rather than applying another percentile to that tail.

The capacity harness waits for the complete fixed workload even if the fault helper reports reconnect failure and retains bounded unit/listener/status diagnostics from the monitors already running around the fault. It then performs owner-scoped cleanup and fixture-state restoration before deterministically emitting the passing or failed summary, so the summary can attest that cleanup completed. A passing summary is possible only when every independent scheduling, disruption, workload, resource, reconnect, and cleanup assertion passes.

Alternatives considered:

- Replacing 2,890 with a dynamically calculated failure allowance would silently change the accepted product boundary and could reward a longer outage.
- Defining `D1` as the final failure or final slow result would make the interval self-expanding and hide degradation.
- Comparing Gateway and Node monotonic timestamps would create false precision across separate VM clock domains; client boundaries therefore use only the Node workload clock while Gateway recovery remains a separate duration assertion.
- Excluding the disruption from Bot API latency would hide host-wide overload unrelated to the reverse ingress tunnel fault.

### 8. Make Gateway the only normative minimum-capacity host

The product capacity claim is for a dedicated Gateway with one vCPU, 512 MiB RAM, a 10 GiB disk, and one GiB managed swap. The private Node has no matching minimum-resource product promise. During the capacity stage it also hosts FRPC supervision, Mihomo, the webhook backend, five synthetic WireGuard clients, two load generators, and a resource monitor. Retained attempts reached roughly 79% average Node CPU, 100% intervals, and 17–19 seconds webhook dispatch lag without memory pressure, so keeping artificial resource parity can turn the load source into the hidden system under test.

The lab retains the same two exact QEMU/amd64 instances and pinned image. Role-specific checked-in templates keep `vpnctl-v2-gateway` at 1 vCPU/512 MiB/10 GiB and set `vpnctl-v2-node` to 4 vCPU/2 GiB/10 GiB; both retain the provisioned one-GiB swap and isolated `lima:user-v2` network. A third capacity VM is rejected because the earlier Node stages are functional rather than minimum-capacity claims, and a third concurrently running fixture would add host scheduling noise and another lifecycle/cleanup boundary. Every harness continues to enforce the exact role-specific profile.

A checked-in fixture-topology contract names both roles, templates, resources, image digest, network, and capacity responsibility. Its SHA-256 is part of every VM stage and shared-session input/result/final aggregate fingerprint in addition to the source-tree hash. Existing one-vCPU Node instances are deliberate drift and must be explicitly edited or recreated from the versioned Node template while stopped; no capacity invocation mutates VM resources.

Capacity summary evidence is split into `gateway_capacity`, `node_fixture_health`, `load_generator_validity`, `fault_reconnect`, `client_disruption`, and `steady_state_latency`. Only Gateway CPU, memory, swap, disk, service OOM, request/latency, and connection bounds contribute to the Gateway capacity claim. Node must remain functional and OOM/crash-free, but its CPU, memory, swap, disk, load average, and run queue remain diagnostic rather than Gateway acceptance thresholds.

Load generation is valid only when both fixed scheduled counts complete, global and pre/post webhook plus global Bot API dispatch-lag p99 are at most 1,000 ms, no post-recovery queue persists, and the final scheduled 30 seconds have neither errors nor any request dispatched more than 1,000 ms late. A Node with dispatch lag outside that predeclared contract yields `invalid_load_generation`, never a pass and never a proven Gateway capacity defect. The frozen disruption cannot absorb dispatch lag.

Both resource monitors are started before load and retain a fixed two-second timeline containing CPU busy, iowait, steal, load averages, runnable/total process counts, and bounded runtime snapshots across the fixed fault-sanity window. Those snapshots add Gateway/Node unit and cgroup-process state, TCP state counts, and authenticated FRPC status without opening a new Lima control session at the fault boundary. These signals distinguish likely Node CPU starvation, worker-pool exhaustion/timeout accumulation, FRP control recovery failure, and Gateway saturation without automatically promoting a heuristic diagnosis to a product verdict.

Alternatives considered:

- Keeping both VMs at the Gateway minimum conflates load-infrastructure failure with the product claim, as the retained evidence demonstrates.
- A third capacity-only Node preserves the old shared Node size but consumes more host resources and adds lifecycle complexity without preserving a stated product boundary.
- Resizing Node dynamically during a run would make evidence non-reproducible and is prohibited; the exact stopped VM must already match its checked-in role contract.

## Risks / Trade-offs

- **[Incomplete clean-state manifest could permit contamination]** → derive it from all existing owner constants, add adversarial residue fixtures for every resource class, and make unknown owner-marked state fail closed.
- **[A child harness may stop a VM it did not start]** → preserve and test each harness's initial-state tracking with already-running fixtures before enabling the shared path.
- **[The mandatory transport boot-recovery check requires a real restart]** → retain exactly one stage-owned Gateway restart as a fingerprinted exception, record it separately, and prohibit fixture restarts everywhere else.
- **[Long shared uptime changes capacity background conditions]** → do not disable background services or alter the image; retain all current resource bounds and record session age/timings in capacity evidence for review.
- **[Canonical dependency mode accidentally skips coverage]** → keep standalone full mode as default, require exact immutable dependency metadata, and test missing/tampered/cross-candidate evidence.
- **[Schema change strands in-progress evidence]** → this is intentional because source commit already invalidates it; refuse with a clear message and never mutate old evidence.
- **[Timing instrumentation becomes another source of failure]** → validate only presence/shape/bounds for schema 2; never compare diagnostic durations to performance thresholds.
- **[The prestarted fault command survives an interrupted host runner]** → retain it in the harness's explicit background PID lifecycle; its existing EXIT/signal trap and the outer owner-scoped cleanup restore the restart policy, transient timer, probes, and service before fixture shutdown.
- **[The fault and load guest commands race at startup]** → require an exact readiness marker and explicit trigger before load; reject pre-existing, symlinked, mistyped, or timed-out schedule files and clean only those fixed owner-scoped paths.
- **[A dynamic disruption interval hides a slow system]** → freeze the first qualifying recovery cohort, cap the interval at 11.5 seconds, retain the independent 2,890-success minimum, and reject every later failure plus pre/post dispatch backlog.
- **[The load generator, rather than vpnctl, is saturated]** → record scheduled/start/completion timestamps for every request and fail the sample independently when p99 dispatch lag exceeds the fixed generator-validity bound.
- **[Reconnect fails before the workload reporter completes]** → continue only the already-started bounded workload, capture immediate diagnostics, emit a failed summary, and then apply the existing owner-scoped cleanup.
- **[A larger Node weakens a hidden minimum-host claim]** → state explicitly that only Gateway has the minimum-capacity promise; retain all Node functional, crash, OOM, and cleanup checks, and fingerprint the role-specific topology.
- **[Diagnostic heuristics overclaim root cause]** → report independent resource, worker-pool, transport, and Gateway domains; classify invalid measurements deterministically but leave causal signals descriptive.

## Migration Plan

1. Add schema-2 timing/session records and phase-selective commands with the current execution topology; verify contract and fake-orchestrator behavior.
2. Add the clean-state manifest/witness and validate every current VM harness against already-running fixtures.
3. Move all VM attempts into the single parent session and add signal/failure/resume tests using fake Lima plus focused real-harness tests run manually.
4. Reorder canonical tunnel/ingress before failure, add dependency-bound unique mode, and prove standalone full coverage remains unchanged.
5. Update operator documentation and host journal, validate OpenSpec/full Go/targeted regression locally, then commit without running the complete heavy gate.
6. Replace fixed-window capacity latency classification with the bounded client disruption model, load-generator validity checks, and failed-run diagnostics; validate the model without Lima and retain all earlier evidence unchanged.
7. The operator prepares a new evidence directory and runs one clean full gate. Its schema-2 timing evidence becomes the first optimized benchmark; retain all earlier failed evidence for comparison.

Rollback is a source revert before preparing another candidate. No evidence directory is downgraded or rewritten.
