# Registered pending apply

Task 13.4 makes `vpnctl apply` the only general executor for already registered
pending desired state. It does not register new intent, infer desired changes
from files, or repair drift.

## Eligibility and preview stability

The apply coordinator accepts a concrete `ConvergencePlanner`, not an arbitrary
plan provider. Consequently, every executable resource change has already
passed the planner's authoritative binding rule: it belongs to exactly one
persisted pending operation ID. An unregistered desired/applied difference, an
operation bound to unchanged resources, ambiguous ownership, or a desired
generation gap with no registered resource changes fails before scope
resolution or execution.

Changes are grouped by operation ID and retain their operation type, target,
per-operation expected/desired generations, stable resource identity, old/new
revision hashes, and impact. The complete grouped plan is retained for
conditional consent. Immediately after consent,
apply repeats authoritative snapshot loading, owned-resource discovery,
operation grouping, and role resolution. Any changed generation, operation,
resource/hash, scope, or drift observation makes the preview stale and requires
a new plan. Executors still receive both applied and desired generations and
must use their component CAS/generation checks.

## Drift boundary

An exact resource identity present in both pending changes and vpnctl-owned
drift is a conflict. Apply stops before any executor call and directs the
operator to the separate previewed `vpnctl repair` flow. This includes missing,
modified, and positively owned unexpected resources; unknown foreign resources
remain outside discovery and therefore outside both apply and repair.

Non-overlapping owned drift does not become part of the apply batch. It remains
in the result as a warning and explicit repair action. Apply consent is based
only on the maximum impact of changes it will execute, not on unrelated drift.

## Role boundary

| Command host | Accepted operation scope | Execution boundary |
| --- | --- | --- |
| Gateway | Gateway-local only | `GatewayApplyExecutor.ApplyGateway` |
| Private node | That immutable current node ID only | `RequireGateway`, then `ApplyCurrentNode` |

The gateway coordinator contains no node-execution method. If its plan includes
a node-scoped operation, the complete batch is refused before gateway-local
work starts, with an action to run `vpnctl apply` on that node. It cannot
pretend that a remote node process exists.

There is no permanent node management agent. The private-node `vpnctl apply`
process is the node-side participant for its lifetime. It must reach the
authoritative gateway even for a no-op result, cannot act for another node, and
may use the cross-host saga coordinator for operations involving both its local
components and gateway state. Gateway-only work is run on the gateway.

The role-specific executor receives one validated batch only after every
operation scope has been accepted, preventing partial execution of a mixed or
foreign batch. A successful result must name the exact ordered operation IDs
and report the exact desired applied generation. It may report `changed=false`
when generation reconciliation proves that a previously uncertain execution
already completed.

`apply` itself supports neither `--dry-run` nor `--defer`. `vpnctl plan` is the
read-only preview, while resource commands create deferred state. Conditional
confirmation is requested only for availability or destructive apply impact;
JSON mode never grants consent.
