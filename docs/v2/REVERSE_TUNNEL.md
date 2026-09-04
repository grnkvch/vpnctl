# Reverse-tunnel production contract

This document fixes the implementation-neutral boundary introduced by task
11.1. The selected development provider is frp, but public expose behavior and
authoritative state do not depend on frp terminology or configuration shapes.

## Topology

- The gateway renders one provider candidate containing every active node
  session. One server process is shared by all nodes.
- A private node renders exactly one node session. Every enabled expose mapping
  is a member of that session, so adding a mapping does not imply another
  daemon, persistent connection, or permanent credential.
- A node session records the manually selected active transport. Provider
  rendering must not add an automatic standby path.
- Disabled exposes are omitted from provider mappings but retain their
  authoritative internal-port allocation until the expose is removed.

The `internal/tunnel.Provider` interface receives this complete desired
topology and returns an opaque candidate. Its secret-free descriptor carries
provider, host and node identities, state and credential generations, the
manually active transport, and a configuration hash. Provider configuration
bytes remain opaque. Atomic file activation, authorization, and readiness are
implemented by the later reverse-tunnel tasks rather than leaking into the
public expose model.

## Mapping identity

Every expose maps TCP from one gateway endpoint to its normalized private-node
upstream. The gateway endpoint is exactly `127.0.0.1:<allocated-port>`; it is
never a public listener or firewall input.

Provider mapping names use both immutable identities in full:

```text
vpnctl-n-<32 lowercase node UUID hex>-e-<32 lowercase expose UUID hex>
```

The 76-byte result is stable across editable expose labels, transport changes,
process restarts, and credential rotations. It cannot collide merely because a
provider truncates a user-visible label.

## Internal loopback allocation

The v2 internal range is TCP `20000-29999`, yielding 10,000 possible expose
endpoints. The range is deliberately disjoint from the internal tunnel server
on TCP `17000`. Neither the range nor an allocated port is CLI input or public
API.

`Expose.TunnelPort` is the persisted assignment. Allocations are deterministic:
the lowest free port is selected, repeated allocation by expose ID is
idempotent, and removing an expose releases only its own port. Authoritative
state rejects duplicate ports globally, including ports retained by disabled
exposes.

At restore, vpnctl first validates the entire saved assignment set and the
currently unavailable loopback ports. Duplicate saved identities or ports are
state corruption and fail restore. Free in-range assignments are preserved.
Unavailable or legacy out-of-range assignments are remapped in expose-ID order
to the lowest remaining free ports.

Restore returns a complete in-memory assignment/remap plan or no plan at all.
If the range is exhausted, no tunnel or ingress candidate may be published.
The caller must write the remapped authoritative expose state, tunnel
configuration, and ingress configuration as one staged generation and publish
them only after all three validate. Therefore a public route can never observe
the old port after the tunnel has moved, or the new port before the matching
tunnel mapping exists.

## Pinned frp provider

Task 11.2 pins the official Linux/amd64 frp `0.69.0` archive at SHA-256
`6b90d1cd28fc661f170c0de90dde03d2c63e4fd7ce0ae2da2ca1c28014b8146e`.
The release bundle places only `frps` and `frpc` under
`/usr/local/libexec/vpnctl/`; service entrypoints reject another version and
run native `verify` after vpnctl's strict canonical validation.

The gateway renders one `frps` configuration bound to its private node-overlay
address on TCP `17000`. Proxy endpoints bind only to `127.0.0.1`, are limited
to TCP `20000-29999`, and require the tunnel-service authorization hook on
`127.0.0.1:19091`. No dashboard, HTTP/HTTPS vhost, public proxy bind, KCP, QUIC,
UDP proxy type, or shared provider token is enabled.

Each node renders one complete `frpc` configuration containing every enabled
mapping. It uses TCP wire protocol v1, `tcpMux`, declared pool zero, TLS trust
from the enrolled gateway certificate, server name
`vpnctl-tunnel-gateway`, and loopback-only administration on TCP `17400`.
The server address is always the internal gateway overlay endpoint; no public
address, `proxyURL`, or standby transport appears in frp configuration. The
node routing layer sends that endpoint through the one manually active
standard or restricted transport and blocks it when that transport is down.

Both service units discard output by default, use `Restart=on-failure`, and
are ordered after their standard or active-routing dependencies without any
controller lifecycle dependency. Gateway firewall input admits TCP `17000`
only from active node overlay identities; it is not a public fixed listener. The accepted runtime
gate reconfirmed one persistent connection for two exposes and 12 concurrent
streams per expose, TLS refusal before credential disclosure, dynamic mapping,
8-second reconnect, 2-second revoke, and a restricted steady state with no
direct TCP `17000` packets.

## Tunnel credentials

Every node credential generation owns one independently generated 256-bit
tunnel credential encoded as canonical unpadded base64url. Its single secret
reference is `tunnel-token:<immutable-node-uuid>-g<generation>`. Both the node
and gateway retain the required copy only through the root-owned secret store:
directories are mode `0700`, files are mode `0600`, and production reads reject
symlinks or non-owner permissions. A provider request must name the exact node
and generation; there is no shared gateway token or fallback to an older
generation.

The raw value may cross hosts only inside the authenticated encrypted
enrollment/rotation exchange and may enter only the root-only generated `frpc`
candidate needed to authenticate that process. Public exchange and
authoritative state retain a SHA-256 commitment bound to the immutable node ID
and credential generation. Candidate descriptors, status and operation
results expose only safe identity/generation/hash metadata; conservative output
classification rejects any token or credential field. Credential-store and
provider failures are sanitized, while tunnel units discard process output by
default.

Consequently current/previous state files, client exports, and any unencrypted
copy of authoritative state contain neither the credential nor its secret
reference. The later backup workflow may include the gateway's required secret
copy only inside its authenticated encrypted archive; no plaintext backup form
is allowed. Switching between standard and restricted transport rerenders the
same logical tunnel configuration and credential. Full node rotation instead
creates a new reference, value, and commitment as part of the next atomic
credential generation.

## Login and mapping authorization

The independently supervised gateway tunnel service owns both the frp
server-plugin endpoint and the `frps` child process. It starts `frps` only
after the authorizer is listening, and failure of either side stops the pair
so systemd can restart one coherent fail-closed unit. The plugin listener is
fixed to IPv4 loopback `127.0.0.1:19091`; it cannot be configured to a wildcard
or public address. Tunnel-service confinement allows only `AF_INET` and
`AF_UNIX`. The separate gateway controller owns only management. Its outage or
restart cannot stop the authorizer, `frps`, an established session, or its
mappings; state/credential read failure still rejects the next decision
without substituting a cached or permissive result.

Only versioned frp `0.1.0` `Login`, `NewProxy`, and `Ping` requests at the matching
`/handler?version=0.1.0&op=<operation>` endpoint are accepted. The HTTP boundary
has three-second read/write/header/idle deadlines, an 8 KiB header cap, a
64 KiB body cap, JSON depth and duplicate-field checks, and 32 non-blocking
concurrent admissions. Malformed, oversized, unsupported, or overloaded input
is rejected with one static credential-free response. Server error logging is
discarded by default.

For each valid request the authorizer reloads authoritative state. It requires
the exact canonical immutable node ID, active lifecycle, canonical current
credential generation, and the credential stored for that node/generation.
The submitted value is checked through the node/generation-bound commitment;
unknown, revoked, stale, invalid, and cross-node attempts all fail. State,
role, duplicate-record, credential-store, or stored-credential errors return a
separate but equally generic unavailable rejection. Neither response exposes
which identity check failed.

Pinned `frpc` 0.69.0 normalizes its declared `transport.poolCount = 0` to
Login `pool_count = 1`. Only after complete identity authorization does the
adapter return otherwise unchanged Login content with `pool_count = 0`.
Every other input is rejected. Native acceptance with the official binaries
observed one persistent TCP control connection and no preloaded work
connection.

Every `NewProxy` request independently repeats the same current node identity
authorization using `content.user.metas`; a prior successful Login is not an
authorization cache. The proxy announcement must then match exactly one
non-disabled authoritative expose owned by that node: its full deterministic
mapping name, TCP type, expose generation, and persisted tunnel port must all
be identical. The provider's fixed `proxyBindAddr = 127.0.0.1`, managed port
range, and this exact port match make the authorized endpoint loopback-only.
Unknown, stale, disabled, cross-node, malformed, or ambiguous announcements are
rejected. Invalid authoritative mapping data and state/store failures return
the generic unavailable rejection.

Native acceptance with official frp first admitted the node Login but rejected
an otherwise valid announcement changed from authoritative TCP `20000` to
`20002`; no listener appeared on `20002`. A subsequent exact announcement
bound only `127.0.0.1:20000` and retained one persistent control connection.

Every `Ping` independently repeats the same identity, lifecycle, generation,
and credential checks from `content.user.metas`; a successful Login is never a
revocation cache. Pinned frps returns a rejected plugin heartbeat as a Pong
error, and pinned frpc `0.69.0` closes its control session on that error. frps
therefore withdraws every mapping owned by the session, while the following
Login is checked against current state and rejected as well. Native acceptance
revoked an already connected test node, observed the next Ping rejection and
mapping/control close within six seconds, rejected reconnect Login, and
observed no mapping reappearance. The endpoint remains loopback-only and there
is no public kill API.

## Lifecycle integration

One desired-state compiler produces the tunnel plan for both gateway and node.
The gateway includes only active node sessions; a revoked node disappears from
the gateway plan. A node must have exactly one joined active identity, so a
revoked node cannot compile or restart its local tunnel plan. Sessions and
mappings are sorted and derived from immutable node/expose IDs and persisted
tunnel ports.

A manual standard/restricted transport switch recompiles the same node ID,
credential generation, mappings, and byte-identical frpc configuration. Only
the safe active-transport/state-generation descriptor changes, so new
readiness evidence is required while tunnel identity is preserved. The tunnel
provider does not select a transport and never introduces runtime automatic
fallback.

Full credential rotation creates a new generation-scoped tunnel value and a
different frpc candidate while preserving every logical mapping. During the
existing parallel readiness phase, the gateway authorizer can open one
process-local lease for exactly the validated next generation. It first
requires a valid one-generation state transition, byte-identical logical
tunnel identity, the exact current authoritative source state, and a valid
candidate credential. While the source state generation and current node
generation remain authoritative, current and candidate Login/NewProxy/Ping
requests may coexist. Any state-generation advance or revoke immediately makes
candidate admission fail closed.

Commit makes the candidate generation authoritative and causes the previous
generation's next Ping/Login to fail. Rollback or finalization removes the
lease; an uncommitted candidate can no longer connect. The lease holds no
credential or secret-store reference, is safe against stale removal, and
vanishes on tunnel-service restart. Thus an authorizer restart can reduce the
rotation overlap but cannot broaden authorization; a management controller
restart does not affect the lease.

## Atomic node mapping configuration

The node configuration manager renders and validates the complete canonical
frpc candidate before creating any transaction resource. Initial installation
writes one `0600` file with file and directory `fsync` followed by an atomic
same-filesystem rename; starting the service and publishing readiness are
separate lifecycle steps. Reapplying byte-identical content is a no-op.

Mapping changes are serialized across processes by the root-only empty
`/run/vpnctl/tunnel-client.lock`. Before dynamic activation, the manager
requires the current and candidate configurations to have the same immutable
node ID, credential generation and value, server endpoint, and TLS trust path.
Transport or credential changes therefore cannot accidentally use frpc's
mapping-only reload path. Both current and candidate files must remain
canonical and keep the admin listener fixed to `127.0.0.1:17400`.

For a change, vpnctl stages and fsyncs the candidate, validates that staged
path with the pinned frpc binary, persists one root-only `.previous` snapshot,
atomically replaces the live file, and runs the exact bounded command
`frpc reload -c <canonical-config>`. Success removes and fsyncs the snapshot.
Failure atomically restores the prior file and reloads it with a fresh bounded
rollback context, even if the caller context was canceled. If runtime rollback
also fails, the prior file and snapshot remain for explicit reconciliation and
further updates fail closed.

Official-frp acceptance held an active stream on mapping `20000` while adding
and removing mapping `20001`. Both reloads kept the same frpc PID, the original
stream remained usable, and TCP `17000` retained exactly one multiplexed
control connection. A successful reload alone is not advertised as upstream
readiness.

## Reconnect and readiness

Reconnect remains inside the pinned frpc process and never becomes a second
vpnctl transport selector. The canonical configuration has exactly one
`serverAddr`/`serverPort`, keeps `loginFailExit=false`, and contains no proxy or
standby endpoint. The version-locked retry contract follows the official
[`v0.69.0` client loop](https://github.com/fatedier/frp/blob/v0.69.0/client/service.go):
one-second initial delay, factor two, 10 percent jitter, a 10-second initial
maximum and 20-second reconnect maximum. Rapidly failing established controls
receive three bounded 200-millisecond retries in a one-minute window before the
same exponential limit. A provider upgrade must revalidate these values rather
than silently retaining stale constants.

Every mapping uses frpc's TCP health monitor against its exact configured node
upstream with a one-second timeout, one failed attempt before withdrawal, and a
three-second interval. frpc does not announce a new mapping before the first
successful check. After failure it withdraws only that mapping from frps; its
gateway loopback endpoint therefore closes while unrelated healthy mappings
remain available. The ingress provider treats that unavailable loopback
upstream as `503`, and frpc republishes the same authorized mapping
automatically after the application returns.

The provider-neutral readiness gate is stricter than process health. It first
byte-compares the installed root-only configuration with the desired candidate
and binds evidence to the exact descriptor generation, active transport, hash,
node identity, credential generation, and ordered mapping generations. It then
reads the official authenticated [`GET /api/status`](https://github.com/fatedier/frp/blob/v0.69.0/client/api_router.go)
only from `127.0.0.1:17400`, using the credential-derived admin password and a
two-second bound. The response is limited to 64 KiB and accepts only the
official TCP status shape, exact mapping names/types/local and remote
endpoints, known phases, no store source, no duplicate fields, and no other
proxy types. Status errors and bodies are never propagated.

Fresh TCP probes of the exact node upstreams run with a one-second bound and at
most eight concurrent probes. A readiness result contains only safe
identity/generation and passed/failed codes. Stale evidence, configuration or
mapping drift, a disconnected tunnel, failed authorization, and an unavailable
upstream all produce a degraded expose decision and `503`; no observation can
change the manually selected active transport. A healthy mapping may resume
without waiting for an unrelated failed application, while connection-wide or
generation failure closes every mapping.

Native acceptance on the minimum Ubuntu 24.04/amd64 fixture stopped and
restarted frps while keeping the original frpc PID, withdrew and recovered a
mapping across application stop/start, and restarted frpc from the same
candidate. Readiness moved through degraded/`503` and back to ready in every
case. A live sentinel on an unconfigured standby TCP `17001` accepted zero
connections, and the full pinned config/Login/NewProxy/reload suite remained
green.

## Provider acceptance

Task 11.9's clean-tree release harness passed all six production native cases
and the complete two-host spike regression on Ubuntu 24.04/amd64 fixtures with
1 vCPU, 512 MiB, and 10 GiB each. It retained one persistent connection for two
exposes and 24 concurrent streams, rejected malicious/stale/controller-down
authorization, reconnected without frpc restart, closed revoke within the
bound, preserved identity through the restricted switch, retained 279/305 MiB
available on gateway/node, and recorded zero OOM kills. The development tunnel
provider capability is complete at this contract.

Section 16 still owns deployed ingress/tunnel failure E2E and sustained
several-hundred-user whole-system capacity. Those product release gates do not
change the provider topology or reopen its implementation choice.
