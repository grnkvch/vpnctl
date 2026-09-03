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
to TCP `20000-29999`, and require the controller authorization hook on
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
are ordered after their standard/controller or active-routing dependencies
without coupling their lifetime to controller restarts. Gateway firewall input admits TCP `17000` only from active node
overlay identities; it is not a public fixed listener. The accepted runtime
gate reconfirmed one persistent connection for two exposes and 12 concurrent
streams per expose, TLS refusal before credential disclosure, dynamic mapping,
8-second reconnect, 2-second revoke, and a restricted steady state with no
direct TCP `17000` packets.

## Deferred provider work

Tasks 11.3-11.9 supply integrated independent 256-bit node credential storage,
local-only connection and mapping authorization, atomic dynamic reload,
readiness/reconnect behavior, revoke handling, and the release resource gate.
Those additions must preserve this topology, identity, and allocation contract.
