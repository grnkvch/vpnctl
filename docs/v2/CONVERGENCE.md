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

Each emitted desired change retains the registered operation's exact
expected/desired generation pair. The expected generation cannot precede the
current applied manifest, and the desired generation cannot exceed the
authoritative desired manifest. This gives later apply executors a per-operation
CAS guard instead of only a batch-level generation.

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

## Persisted snapshot boundary

The production read boundary is the root-only regular file
`/var/lib/vpnctl/convergence.json`. Readers open the exact path without
following symlinks, require mode `0600`, one filesystem link, a bounded
non-empty payload, one closed JSON value, and a fully valid canonical snapshot.
An absent file is an unavailable observation; unsafe shape, malformed JSON, or
invalid manifests are authoritative validation failures. The reader never
creates or repairs the file. Initial publication and atomic CAS updates remain
a separate writer integration so a partial implementation cannot silently
declare desired and applied state equal.

The first production discovery adapter is deliberately limited to file
resources positively named by the applied manifest under `/etc/vpnctl/`. It
maps the production root explicitly, never enumerates neighboring files,
follows neither symlinks nor hard links, hashes regular content through a
16-MiB bound, and fingerprints type, mode, and content without returning raw
bytes. Missing paths are omitted for the planner's `missing` classification;
wrong type, mode, or content becomes `modified`. Unit, state, and network
resources remain typed unsupported until their own ownership-aware adapters
are connected, so a mixed manifest cannot yield a partial healthy result.
