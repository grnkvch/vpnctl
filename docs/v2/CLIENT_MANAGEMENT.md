# vpnctl v2 personal client management

`client add <name> [preset...]` creates one gateway-owned personal identity. The
display name is unique case-insensitively among active and revoked clients; the
generated UUID is the immutable canonical identity. The v2.0 grammar has no
platform option, so new records use `generic` platform metadata.

Creation is a reviewed two-stage transaction. Planning is read-only: it validates
the name and complete explicit preset argument, allocates a collision-checked
UUID, computes the next free client-pool IPv4 address, and binds the plan to the
gateway state generation and, when presets are present, the complete preset
source-set hash. It does not generate or write a credential. A changed state,
address allocation, or preset source makes commit return stale.

Commit generates a unique WireGuard key pair and publishes the private key under
an owner-specific opaque reference with `0700` directories and a `0600` file.
One authoritative state transition then creates the client, its active standard
transport, and—only when preset arguments were supplied—its generation-1 policy.
The assignment is the canonical full set, not an incremental update. No preset
arguments creates a present empty assignment and no policy resource; there is no
implicit built-in/default selection.

If state persistence is proven not to have committed, the staged secret is
deleted. If a write may already be active, vpnctl retains the exact referenced
secret and returns a typed uncertain result instead of risking a credential-less
live identity. Reconciliation can therefore inspect the immutable client ID and
state generation safely.

The address allocator restores every non-deleted node/client reservation before
choosing the lowest free client-pool address. An active or revoked client's
address is stable; a concurrent creation invalidates an older plan rather than
silently moving it. Five-client acceptance covers independent UUIDs, addresses,
public keys, private-key references, and target-owned policy/transport records.
Packet-level client/client, client/node, and node/node blocking remains the
dedicated task-7.12 firewall gate.

## Secret-free inspection

`client list` returns active and revoked records in deterministic name/ID order
and omits deleted tombstones. `client show <name-or-id>` accepts one explicit
case-insensitive name or immutable ID and likewise hides deleted records.

The public view contains identity, platform, lifecycle, overlay address,
assigned presets, credential and policy generation numbers, active transport
kind/state, derived health, export state, and lifecycle timestamps. It contains
no private/public key, credential reference, profile content, or secret-store
path. Before the export lifecycle exists, export state is explicitly
`not-exported`; tasks 7.10-7.11 extend that field to `current`/`stale` from
durable artifact metadata without broadening the view to secret material.
