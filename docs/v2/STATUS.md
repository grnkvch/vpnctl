# Passive status contract

Task 13.6 defines `vpnctl status` as an observation and presentation command,
not a health probe or convergence trigger. It combines three read-only inputs:

1. validated authoritative role state;
2. the strict `desired ↔ applied` / `applied ↔ observed` convergence plan;
3. cached and local process metadata from a passive runtime observer.

For a Gateway, the read-only inputs also include one shared bootstrap readiness
projection: compatible manifest-declared package versions, the exact owned
nginx drop-in, active immutable ingress tree/hash, nginx load/enable/active and
runtime-version state, the TCP 443 listener, and the loopback enrollment
listener. This inspection does not refresh APT, start a unit, open an HTTP/TLS
connection, or repair anything. Missing or drifted mandatory ingress therefore
makes status degraded even when the controller and WireGuard data plane remain
healthy. The stable action is `repair_gateway_ingress`, beginning with
`sudo vpnctl repair --dry-run`.

The observer interface has no probe or mutation operation. Implementations may
read cached readiness, process state, versions, generations, and configuration
hashes, but must not open network connections, issue DNS requests, invoke a
transport test, call a webhook/provider URL, start or reload a service, or
repair/apply anything. Explicit network diagnostics belong only to
`vpnctl doctor`.

The public command reads the root-only persisted convergence snapshot and the
production owned file/unit observers used by `vpnctl plan`. Gateway/node init,
successful join, and committed-generation recovery publish their exact role
baselines. Missing, unsafe, invalid, or unsupported convergence inputs remain
fail-visible and return `degraded`/`failed` rather than inventing generations or
claiming that drift is absent. Mutation-side Desired publication for later
deferred operations is not connected yet; locally retained pending state must
therefore remain explicitly unavailable rather than looking like a clean
applied generation.

## Output structure

JSON always includes the complete non-secret structure, independently of
`--all`:

- host role, overall condition, authoritative/desired/applied generations;
- running and manifest vpnctl versions, control protocol versions, and pinned
  component versions, capabilities, and available SHA-256 hashes;
- resource counts and safe node/client/preset/policy/transport/expose/operation
  projections;
- gateway/control connectivity, selected transport, and active data-plane
  passive health metadata with generation/runtime hashes;
- registered pending changes and vpnctl-owned drift as separate arrays;
- active unexpired invites and active unexpired logging opt-ins;
- certificate lifetime/fingerprint metadata and portable-backup metadata;
- the normalized problem list, warnings, and copy-ready required actions.

Credential references, keys, invite hashes, enrollment endpoints, expose paths
and upstreams, request/response bodies, and raw configuration never enter the
report. The `status-v1` schema gives every full-status item an explicit closed
shape, so adding such a field fails schema validation.

Human output is intentionally smaller. By default it prints role/overall/
generation, only the normalized problem table, warnings, and required actions.
`--all` adds the component, runtime, managed-resource, pending, drift, invite,
logging, certificate, and backup tables. Those tables are an unexported human
projection; using `--all` cannot change JSON bytes or omit full JSON data.

## Conditions and exit categories

Status uses deterministic precedence:

| Observation | Overall / result | Exit category |
| --- | --- | --- |
| healthy, including active warning or pending intent | `healthy` / `ok` | `success` (`0`) |
| vpnctl-owned drift only | `degraded` / `degraded` | `conflict` (`3`) |
| degraded active component or unavailable mandatory passive metadata | `degraded` / `degraded` | `unavailable` (`4`) |
| invalid authoritative or convergence state | `failed` / `failed` | `validation` (`2`) |

Unavailable runtime takes precedence over simultaneous drift. Pending changes
remain intentional successful state and include separate `plan` then `apply`
actions. Repair is never implicit.

An active invite, active temporary logging session, certificate inside its
warning window, missing gateway backup, or latest gateway backup at least 30
days old produces a warning without degrading otherwise healthy data-plane
status. An expired certificate is an unavailable prerequisite and does degrade
status. Certificate and backup warnings include the role-correct manual command;
public certificate rotation still requires external webhook re-registration as
documented by the rotation workflow.

Passive readiness cannot prove that public TLS routing works through the
external edge. `vpnctl doctor ingress` remains the active bounded check for the
public-IP certificate and reserved health path and separately checks that the
loopback enrollment upstream is reachable.

## Snapshot consistency

The collector gives the observer an isolated validated state copy. It reports
missing control, joined-node gateway, selected-transport, or active data-plane
metadata as unavailable instead of silently assuming health. If authoritative
state changes during collection, a second authoritative-state read detects the
race and status asks the operator to run it again; it does not retry a mutation
or synthesize traffic. Convergence material may legitimately retain an older
generation after invite, logging, backup, or another metadata-only mutation,
so generation inequality alone is not drift when the material and semantic
readiness projections are otherwise clean.

For operational triage, start with `vpnctl status --all`; it is always the
passive snapshot. Use `vpnctl plan` to separate intentional pending work from
owned drift. Run the narrowest `vpnctl doctor <scope>` only when an active
network check is needed, and run `vpnctl repair --dry-run`/confirmed
`vpnctl repair` only when the plan identifies repairable vpnctl-owned drift.
Neither status nor plan proves the public edge by sending traffic, and neither
may repair it implicitly.
