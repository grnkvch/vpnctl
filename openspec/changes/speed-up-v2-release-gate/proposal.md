## Why

The clean deployed v2 release gate spends roughly 90% of its wall time in Lima stages, including about 18 minutes repeatedly booting and stopping the same two constrained x86_64 fixtures. A late deterministic failure currently makes the next source commit pay that full cost again, so the gate needs a faster execution topology without weakening or hiding any evidence.

## What Changes

- Split mandatory automated execution into explicit host-only `fast` and Lima-backed `vm` phases while retaining the existing full `run-automated` composition and explicit resume behavior.
- Move the unchanged sustained capacity measurement to an explicit resumable `run-capacity` command. It remains append-only, source/topology-bound evidence, but is advisory and never runs implicitly or participates in `automated.json`.
- Record structured monotonic phase timings so future optimization is based on comparable evidence rather than reconstructed timestamps.
- Run all pending VM stages inside one owner-scoped Lima session per invocation, with a fail-closed clean-state witness between stages and stopped fixtures before and after the invocation.
- Make tunnel and ingress release checks canonical VM attempts and let the unique failure-path stage depend on their exact immutable result hashes instead of executing both release harnesses a second time.
- Separate the capacity fault scheduling sanity bound, the bounded client-observed disruption interval, and pre/post-fault steady-state latency so a shifted fault cannot pollute or enlarge the performance sample.
- Retain the fixed 2,890-success budget, qualify the load generator independently, and preserve complete sanitized request/failure diagnostics even when reconnect fails before final aggregation.
- Make the 1-vCPU/512-MiB capacity boundary explicitly Gateway-only and give the shared functional Node/load-generator fixture a versioned 4-vCPU/2-GiB profile, with both role profiles, exact stored readiness probes, and topology bound into reusable evidence and checked before VM mutation.
- Seal fixture-start failures as immutable sessions with real startup/shutdown timings, zero witnesses when boot never completed, and an actionable explicit resume command.
- Make a freshly created role-specific fixture self-contained by atomically installing and SHA-256-verifying the exact versioned lab report/fault helpers during parent startup before the first witness; bind the helpers into the topology fingerprint and fail closed before any VM stage.
- Harden the real capacity measurement against test-infrastructure artifacts: warm both paths before the unchanged measured profile, size generator workers from rate and request timeout, retain bounded degraded-monitor evidence without misclassifying it as Gateway saturation, and recognize the kernel-reserved swap metadata page without relaxing the one-GiB allocation.
- Keep fault-window process diagnostics observational on the minimum Gateway: take only bounded pre/post systemd restart snapshots and read cgroup-v2 population/process state directly during the measured interval, so diagnostic polling cannot become a competing systemd workload.
- Complete the test-only FRPS restart-policy setup before the fault command publishes readiness and before measured load starts, so its `daemon-reload` cannot create a boundary-time saturation wave; retain the hard KILL, protected restart job, exact outage timing, and every acceptance threshold.
- Establish and validate the Gateway-local TLS/HTTP fault probe before readiness, keep that exact connection alive at a versioned five-second interval, and reuse it at the fault boundary so no new Python/TLS client setup competes with the minimum Gateway under measured load.
- Keep successful fault recovery free of test-only system-manager cleanup: transfer the exact temporary restart-policy drop-in to the parent and restore it only after the fixed workload, while retaining immediate restoration on fault-helper failure or interruption.
- Batch each read-only clean-state snapshot and inspect the two independent fixtures concurrently while preserving every residue class and the between-stage fail-closed boundary.
- Preserve every existing test, capacity threshold, five-minute workload, source/version/input/image binding, immutable failed-attempt history, and legacy-evidence refusal; change only capacity scheduling and release-blocking status.
- Keep parallel VM boot, background-service quiescence, lean images, deeper standard/tunnel/routing deduplication, and APT caching outside this change until separate measurements justify them.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `release-delivery-and-migration`: Add phase-selective execution, structured timings, a single isolated VM session with clean-state witnesses, and hash-bound canonical stage dependencies to the resumable deployed release gate.

## Impact

- Affects `scripts/v2deployed-release-gate.sh`, the Lima E2E harness boundary, failure/tunnel/ingress orchestration, the capacity load model and reporter, release-gate evidence schemas, regression fixtures, traceability, and operator documentation.
- Adds no product command, daemon, network endpoint, dependency, relaxed Gateway threshold, or migration of existing evidence. The shared Node fixture changes from 1 vCPU/512 MiB to 4 vCPU/2 GiB because it is test infrastructure rather than the claimed minimum-capacity product host.
- The next release candidate must use a newly prepared evidence directory because these source and evidence-contract changes invalidate earlier candidates by design.
