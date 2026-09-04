# Deterministic convergence planning

Task 13.1 establishes one read-only planning boundary shared by later `apply`,
`repair`, and status work. It intentionally keeps three states distinct:

1. `desired` is the authoritative target after registered deferred operations;
2. `applied` is the last generation vpnctl successfully activated;
3. `observed` is a current read-only inspection of vpnctl-owned resources.

Pending work is always `desired ↔ applied`. Drift is always
`applied ↔ observed`. The planner never compares desired directly with observed.
Consequently, a manually changed file that happens to equal a future desired
version is still drift from the applied baseline. A later `apply` can therefore
refuse the overlap and direct the operator to explicit repair instead of
silently adopting an unrecorded change.

## Managed resource contract

Every state, file, systemd unit, and network resource has a stable tuple of
component, kind, and ID plus two SHA-256 fingerprints. The revision fingerprint
also includes source/policy/credential generations and drives desired/applied
diff. The runtime fingerprint contains only observable shape and drives
applied/actual drift. This prevents a dependency-only refresh from looking like
manual runtime drift. Plaintext configuration is absent from manifests and
plans. Each record declares the impact of applying and removing it as `none`,
`availability`, or `destructive`.

Desired changes are classified as create, update, or delete and must be bound
to exactly one registered pending operation. An unbound desired difference, a
pending operation bound to an unchanged resource, or two operations bound to
the same resource is invalid authoritative input rather than implicit work.
The common artifact adapter fingerprints mode, content hash, and all direct
source, policy, and credential generations from the existing render manifest.

Owned drift is classified as missing, modified, or unexpected. Discovery
adapters may return unexpected resources only after positive vpnctl ownership
evidence such as an exact owner marker. Foreign resources stay outside the
owned observation set and can never become repair targets. This ownership
boundary is part of the adapter contract and will be enforced by each concrete
component adapter as it is connected to the planner.

## Determinism and effects

The planner canonicalizes manifests, pending operation bindings, and owned
observations by resource identity before comparison. Its result has stable
ordering and includes per-item and maximum impact. Input enumeration order does
not change JSON output.

The planning source exposes only `ReadConvergenceSnapshot`; discovery exposes
only `DiscoverOwnedResources`. Neither interface has state-save, file-write,
unit-control, or network-mutation methods. Planning also passes an isolated copy
of the applied manifest to discovery. Tests cover all four forbidden mutation
classes, preserve byte-identical state and filesystem sentinels, and verify that
source material never appears in the plan.

The public `plan-v1` adapter emits pending changes and drift as separate arrays.
Intentional pending work keeps the success exit category. Drift adds a
`review_drift` action pointing to `vpnctl repair`; it does not cause planning
itself to mutate or repair anything.
