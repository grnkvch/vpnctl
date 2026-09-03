# Transport provider lifecycle

Task 8.1 fixes the provider-neutral boundary used by both `standard` and
`restricted`; task 8.7 adds the read-only-state, non-mutating transport-test
orchestration on that boundary. Concrete WireGuard and Mihomo/ShadowTLS
providers are documented separately. The confirmed switch saga remains task
8.8.

## Provider contract

Each provider owns its rendered configuration, staged files, secret lookup,
processes, and transient test connection. The shared layer sees only a
non-secret candidate descriptor: immutable owner, transport kind, credential
generation, and configuration hash.

The lifecycle is ordered as follows:

1. `Render` deterministically creates an opaque candidate without changing the
   running data plane.
2. `Prepare` stages that candidate without selecting it for production.
3. `Validate` runs provider-native validation against the staged candidate.
4. `StartTest` runs isolated control, reverse-tunnel, selected TCP, and selected
   UDP probes. The provider must remove its transient test connection before
   returning; production marks, routes, selection, and credentials are outside
   this method's mutation scope.
5. `Activate` is called only by a later explicit operation after all required
   confirmation and probes have passed.
6. `Health` reports runtime role separately from reachability. `active` plus
   `degraded` or `unavailable` remains the selected active transport.
7. `Drain` performs the explicitly bounded old-path drain requested by a switch
   operation.
8. `Rollback` removes or restores only the provider-owned candidate and is the
   compensating action for a failed explicit operation.

Provider implementations must make `Prepare`, `Drain`, and `Rollback` safe to
retry or reconcile after an interrupted operation. Exact atomic publication,
process supervision, and rollback artifacts belong to the concrete provider.

## Manual selection invariant

`Selection` is a complete pair with exactly one `standard`/`restricted` active
member and the other member standby. `Registry` accepts exactly one provider of
each kind. The task-8.1 manager is intentionally observation-only:

- `ObserveActive` calls only the selected provider and never probes standby;
- an active outage is returned as health degradation without changing intent;
- `CheckSteadyState` verifies selected runtime roles but never adopts or repairs
  reversed roles;
- no timer, health callback, retry, or provider fallback can change selection.

The public non-mutating test workflow resolves exactly one configured target
from read-only local node state, snapshots the canonical state, and runs
`Render`, `Prepare`, provider-native `Validate`, and `StartTest`. It requires
all four named control, reverse-tunnel, selected-TCP, and selected-UDP results,
then always calls `Rollback` from an independent cleanup context. The whole
diagnostic is bounded to 45 seconds, each provider stage to 30 seconds, and
cleanup to 10 seconds. A failed check is a completed negative diagnostic, not
permission to activate a different provider.

After cleanup the workflow reloads and byte-compares canonical authoritative
state. It reports a concurrent-state conflict rather than claim a stable test
if active intent, pending state, configuration, or any generation changed. Its
dependency surface contains no state writer and it never calls `Activate`,
`Drain`, or `Health`. The only component allowed to create a new selection is
the confirmed make-before-break saga in task 8.8, which must persist the
authoritative state transition after successful target activation and bounded
old-path drain.

Both public gateway listeners are provisioned and supervised independently of
that per-node selection. Gateway init publishes the standard and restricted
provider configurations plus hash-bound readiness markers as one pre-start
file set, then enables both role units. A listener process failure or gateway
reboot restores the listeners through systemd; it does not inspect, rewrite,
or repair a node's active/standby pair. An active node-path outage therefore
remains unavailable/degraded until an operator explicitly tests and switches.

The concrete standard renderer, service, credential ownership, passive health
semantics, and packet-level acceptance contract are documented in
[`STANDARD_TRANSPORT.md`](./STANDARD_TRANSPORT.md).
