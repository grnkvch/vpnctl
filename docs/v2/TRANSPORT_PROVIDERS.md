# Transport provider lifecycle

Task 8.1 fixes the provider-neutral boundary used by both `standard` and
`restricted`. It does not implement WireGuard, Mihomo/ShadowTLS, the public
`transport test` command, or the confirmed switch saga.

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

The public non-mutating test workflow is task 8.7. The only component allowed
to create a new selection is the confirmed make-before-break saga in task 8.8,
which must persist the authoritative state transition after successful target
activation and bounded old-path drain.

The concrete standard renderer, service, credential ownership, passive health
semantics, and packet-level acceptance contract are documented in
[`STANDARD_TRANSPORT.md`](./STANDARD_TRANSPORT.md).
