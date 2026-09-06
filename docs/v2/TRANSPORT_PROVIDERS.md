# Transport provider lifecycle

Task 8.1 fixes the provider-neutral boundary used by both `standard` and
`restricted`; task 8.7 adds the read-only-state, non-mutating transport-test
orchestration on that boundary; task 8.8 adds the confirmed make-before-break
switch workflow; task 8.9 reuses the restricted provider for explicit
node-local handshake-host recovery. Concrete WireGuard and Mihomo/ShadowTLS
providers are documented separately.

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
`Drain`, or `Health`.

## Confirmed manual switch

The switch planner resolves the joined local node, its exact active/standby
pair, and a complete next-generation state without touching either provider.
Apply reloads and byte-compares the canonical precondition after operator
confirmation; any generation, pending-operation, configuration, or other state
change makes the reviewed plan stale before a provider is called.

Switching to the already active target is health-only and idempotent: it calls
only that provider with a bounded context, neither probes nor activates standby,
and performs no state write. A degraded/unavailable observation remains the
manual active selection and is returned as a degraded result with an explicit
diagnostic action.

A real change is ordered as one make-before-break transaction:

1. render the old candidate for compensation and render/prepare/native-validate
   only the explicitly requested target;
2. require the target's authenticated control, reverse-tunnel, selected-TCP,
   and selected-UDP probes to all pass;
3. call the target provider's single `Activate` boundary, which represents
   control, tunnel, and selected egress together, then require active/healthy
   observation of that same identity and credential generation;
4. drain/deactivate the previous provider within ten seconds;
5. persist exactly one next-generation state with target `active` and previous
   `standby`.

The total operation is bounded to 90 seconds, individual stages to 30 seconds,
and compensation to an independent ten-second context. Failures before target
activation roll back only its staged candidate. Failures after an activation
attempt first reactivate the old rendered candidate and only then remove the
target; target cleanup is intentionally retained if old-path restoration cannot
be proven. A state-write error is reloaded: a proven old generation is
compensated, a proven candidate generation is reported as commit-uncertain
without a blind rollback, and any other state is left for explicit
reconciliation.

The CLI adapter uses the common availability-impact confirmation boundary.
`--defer` sends the exact non-secret current/target/generation plan to the
reachable authoritative gateway writer and never calls local `Apply`; active
connections remain unchanged until a later explicit node-local apply. Durable
cross-host phase reconciliation is composed around this local transaction by
the general saga coordinator in task 13.3.

Both public gateway listeners are provisioned and supervised independently of
that per-node selection. Gateway init publishes the standard and restricted
provider configurations plus hash-bound readiness markers as one pre-start
file set, then enables both role units. A listener process failure or gateway
reboot restores the listeners through systemd; it does not inspect, rewrite,
or repair a node's active/standby pair. An active node-path outage therefore
remains unavailable/degraded until an operator explicitly tests and switches.

The production node adapter now compiles both complete generation-bound
standard/routing/DNS/tunnel bundles from one state and host snapshot. It uses
the role-repair transaction for exact config replacement, dependency-ordered
service restart, and rollback of any failed host mutation. The two provider
instances share one in-memory selector and one replacer, so `Activate` cannot
move control, frpc, selected TCP, and selected UDP independently. Immediate
planning remains lazy and state-only. A deferred operation reconstructs the
last Applied `N` configuration separately from its retained `N+1` intent mirror
and compiles the already published Desired `N+2` target, preserving an exact
rollback generation. Until the isolated production candidate tester is wired,
`StartTest` fails before `Activate`; host replacement is therefore not yet
reachable from the public test/switch commands.

Each compiled generation also retains one opaque standalone restricted
candidate derived from the same trust and credential generation. It is
validated with the complete bundle but is not part of the published role files
or convergence material. Its sole purpose is to let the isolated tester launch
a loopback-only target process without modifying the live routing configuration
or production selector.

The node mTLS RPC client accepts an internal dial-path override for that tester.
Its default remains the ordinary system dialer. The override changes only how
the already validated overlay address is reached; all TLS identity, protocol,
deadline, response, and one-request/one-connection checks remain mandatory.
Consequently the control result can reuse the authenticated read-only
`repair.probe` without introducing a weaker test-only gateway API.

The concrete standard renderer, service, credential ownership, passive health
semantics, and packet-level acceptance contract are documented in
[`STANDARD_TRANSPORT.md`](./STANDARD_TRANSPORT.md).
