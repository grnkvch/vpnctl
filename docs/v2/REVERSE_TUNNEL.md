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
topology and returns an opaque candidate. Only provider name, host identity,
role, generation, and configuration hash cross the abstraction. Atomic file
activation, process supervision, credentials, authorization, and readiness are
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

## Deferred provider work

Tasks 11.2-11.9 supply the pinned provider renderer, independent 256-bit node
credentials, local-only connection and mapping authorization, atomic dynamic
reload, readiness/reconnect behavior, revoke handling, and the release resource
gate. Those additions must preserve this topology, identity, and allocation
contract.
