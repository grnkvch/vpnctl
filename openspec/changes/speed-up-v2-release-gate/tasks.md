## 1. Evidence and phase contracts

- [x] 1.1 Define one versioned authoritative registry for every mandatory stage, its `fast` or `vm` phase, fail-fast order, command, Lima requirement, cleanup adapter, and dependency list; verify contract tests reject a missing, duplicate, reordered-without-version-change, or unknown stage.
- [x] 1.2 Bump new candidate attempt/session evidence to schema 2 and add bounded monotonic timing plus clean-witness/dependency references without migrating old evidence; verify schema-1 evidence remains unchanged/read-only and malformed or interrupted schema-2 records are retained but never reused.
- [x] 1.3 Add immutable structured timing records for parent-controlled validation, execution, witness, boot, and shutdown phases and an explicit private child timing-output contract; verify durations are monotonic non-negative integers and changing their magnitude alone never changes pass/fail.

## 2. Fast and VM execution phases

- [x] 2.1 Add `run-fast [--resume]`, `run-vm [--resume]`, and the backward-compatible full `run-automated [--resume]` composition with phase-scoped fresh-attempt refusal; verify fake-orchestrator tests cover first run, explicit retry, cross-phase continuation, completed phase, and final aggregation.
- [x] 2.2 Make `run-fast` execute the exact host-only stage set without resolving or invoking `limactl`, and make `run-vm` refuse before mutation unless every fast result is reusable; verify a PATH with a failing fake `limactl` still passes/fails fast stages solely from their own outcomes.
- [x] 2.3 Reorder VM stages from short/fail-fast checks through canonical dependencies to capacity last while preserving the complete mandatory set; verify the order is fingerprinted and the fixed capacity manifest, 300-second duration, and all existing check names/commands remain byte-for-byte or semantically unchanged as applicable.

## 3. Shared Lima clean-state boundary

- [x] 3.1 Inventory every test-owned path, unit/drop-in, process prefix, listener, namespace, nftables object, route/rule/interface, and package-state mutation used by mandatory VM harnesses in a checked-in bounded clean-state manifest; verify the inventory is traced to all owner constants and rejects duplicate, wildcard, broad, or foreign cleanup targets.
- [x] 3.2 Implement a read-only clean-state witness that captures the post-boot baseline and produces sanitized bounded JSON before/between stages; verify fake and fixture tests detect residue in every resource class, accept the documented baseline, and never mutate or delete a foreign resource.
- [x] 3.3 Make each self-managed VM harness preserve an already-running exact fixture, emit its owned phase timings, and finish with its existing owner-scoped cleanup; verify focused tests cover both initially-stopped standalone mode and initially-running shared-session mode without changing logical assertions.
- [x] 3.4 Run all pending VM attempts sequentially inside one append-only parent fixture session, with one parent start per exact VM and only the fingerprinted `transport-supervision` Gateway boot-recovery restart exception, and seal session input/log/result evidence; verify fake Lima behavior covers success, the single restart, stage failure, witness failure, cleanup failure, `INT`, `TERM`, and resume with both fixtures stopped afterward.
- [x] 3.5 Add bounded stage-specific cleanup dispatch using only existing ownership-checking cleanup entrypoints when a witness finds residue; verify partial/changed ownership is refused, later stages do not start, the failed attempt remains immutable, and no broad process/path/firewall cleanup is possible.

## 4. Canonical provider dependencies

- [x] 4.1 Add an explicit dependency-evidence mode to `v2failure-e2e.sh` that validates exact current-candidate tunnel/ingress passing results and then runs only unique failure assertions, while retaining self-contained full `verify` as the default; verify missing, failed, malformed, cross-commit, wrong-version, wrong-image, changed-hash, and wrong-mode dependencies fail closed.
- [x] 4.2 Bind dependency names, contracts, selected attempts, ordering, and result SHA-256 values into the failure attempt input/fingerprint and final aggregate validation; verify a changed dependency invalidates only its dependent result and appends a new failure attempt without rewriting history.
- [x] 4.3 Prove the optimized top-level gate invokes each canonical tunnel/ingress release command once while standalone failure still invokes both, and compare the resulting mandatory logical check set with the pre-optimization contract.

## 5. Documentation and validation

- [x] 5.1 Update deployed release-gate documentation, traceability, and the host change journal with phase commands, schema-2 layout, timing semantics, shared-session cleanup/recovery, dependency evidence, expected speed source, and explicit unchanged thresholds; verify documented commands match parser contract tests.
- [x] 5.2 Run Bash syntax/diff checks, strict OpenSpec validation, targeted orchestration/cleanup/dependency tests, the complete host-only fast phase, and full Go/vet as justified; do not run the complete Lima/capacity gate automatically and record why full race or VM repetition is or is not necessary.
- [x] 5.3 Correct the real-gate fault scheduling defect exposed by retained capacity attempts: enter and track the Gateway fault command before workload startup, delay inside the guest to the unchanged manifest offset, and verify contract/order/signal cleanup without changing any workload, fault-window, reconnect, or latency bound.
- [x] 5.4 Remove the remaining fault/load guest-start race exposed by real evidence: require a bounded fixed-path ready/trigger handshake before load and reject unsafe/stale schedule files while preserving exact owner-scoped cleanup.
- [ ] 5.5 Prepare a new same-commit evidence directory and run one clean full automated gate; verify fast stages precede a single VM session, all logical checks pass, earlier failed evidence remains unchanged, and schema-2 timings demonstrate the structural boot and duplicate-provider savings without introducing a guessed percentage threshold.
