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
path. Export publication now records durable, content-free artifact metadata;
task 7.11 consumes it to extend the initial `not-exported` view to
`current`/`stale` without broadening the view to secret material.

## WireGuard profile rendering

The v2 WireGuard adapter delegates final text formatting to the retained v1
`wireguard.RenderClientConfig` implementation. It resolves an active client and
its standard transport from validated gateway state, reads only that transport's
opaque private-key reference, derives the address prefix from the configured
client CIDR, and uses the mandatory gateway public IPv4 with fixed `51820/UDP`.
The gateway standard provider supplies its public key at this boundary; task 8.2
owns that provider state rather than inventing a second server-key record here.

With no DNS override, profiles contain `1.1.1.1, 8.8.8.8`, matching the accepted
gateway-path defaults. An override must be a non-empty, unique list of canonical
IPv4 addresses. The renderer always uses v1 defaults `AllowedIPs = 0.0.0.0/0`
and `PersistentKeepalive = 25`, so this export is standard full-tunnel and does
not consume policy names, selectors, or policy generation.

The rendered content is deliberately a private field with only a defensive
`Bytes()` copy for the file writer. JSON serialization of profile metadata
cannot expose the private key or full profile. A preset-only policy replacement
advances authoritative state metadata but leaves the WireGuard bytes and
credential generation identical.

## Clash/Mihomo profile rendering

The v2 Clash adapter resolves the same active client and standard WireGuard
credential, then compiles the client's authoritative policy from the exact
active preset generations. Before rendering, it verifies that the stored
policy names, normalized selectors, and effective hash still match those
generations. It reconstructs preset boundaries rather than flattening away
exclusions: each preset remains `include - exclude`, followed by cross-preset
union, so an explicit selector in a second preset can reselect a more-specific
exception from the first.

Rules are deterministic and most-specific-first. Exact domains precede domain
suffixes; narrower IPv4/IPv6 CIDRs precede their parents. Both selected TCP and
UDP rules target the `VPNCTL-GATEWAY` manual-select group. In task 7.9 that group
contains only `VPNCTL-STANDARD`; it deliberately contains neither `DIRECT` nor
an automatic `fallback`/`url-test`. A failed selected path therefore cannot
change to direct. Explicit policy exclusions compile to `DIRECT`, and the sole
terminal catch-all is `MATCH,DIRECT` for unmatched traffic. Task 8.10 adds the
already-specified restricted choice to this same manual group without changing
the rule actions or adding automatic selection.

Clash DNS defaults to `policy` mode with Mihomo `redir-host`. Unmatched and
explicitly excluded domain queries use the configured direct IPv4 resolvers;
selected domain queries use the stable gateway resolver at the first address of
the client CIDR (normally `10.66.0.1`) and bind that request to
`VPNCTL-GATEWAY`. There is no selected-to-direct DNS fallback. Changing the
gateway resolver's upstreams therefore does not require client re-export. The
explicit `direct` compatibility mode omits `nameserver-policy` and sends all DNS
queries through the direct resolver list while retaining selective traffic
rules, matching the accepted v1 behavior boundary.

The profile fixes public standard transport at `51820/UDP`, disables IPv6 DNS
answers and background geodata updates, keeps logging silent, and contains no
remote health test or auto-switch rule. IPv6 CIDR selectors still compile to
the gateway group, so unsupported selected IPv6 cannot become a direct
fallback. As with WireGuard export, secret-bearing YAML is private and exposed
only as a defensive byte copy to the durable file publisher.

Automated semantic tests cover local exclusions, cross-preset reselection,
fully shadowed CIDRs, all-direct clients, both DNS modes, metadata redaction,
and deterministic output. The rendered profile also passed the exact pinned
Mihomo `v1.19.30` Linux/amd64 `-t` validator. Actual import and runtime DNS,
TCP, UDP-over-TCP, fail-closed, and reconnect behavior in supported Clash Mi
remain the deployed-service release gate in task 16.11.

## Artifact publication and delivery

`client export <name-or-id> <clash|wireguard>` has a read-only plan boundary for
`--dry-run`: it validates and renders the complete proposed artifact in memory
but creates no directory, profile, sidecar, state, or pending operation. Commit
re-plans immediately before publication. Any generation, client identity, or
lifecycle change after review refuses the export; profile bytes from the stale
read are never activated.

Without `--output`, publication uses these managed names:

```text
/var/lib/vpnctl/exports/clients/<name>.clash.yaml
/var/lib/vpnctl/exports/clients/<name>.wireguard.conf
```

Managed export directories, including the private `.metadata` directory, are
created or repaired to `0700`. Profiles and sidecars are staged as `0600`,
fsynced, atomically renamed into place, and followed by a directory fsync. An
explicit re-export to the managed path replaces the previous artifact. A
custom path is made absolute; an absent parent is created as `0700`, while the
mode of an existing operator-owned parent is preserved. An existing custom
file is left byte- and mode-identical unless `--force` is present. Final
symlink/non-regular targets and symlink/non-directory parents are rejected.
Custom output also cannot point directly or through a symlink alias into
vpnctl's reserved config, state, or runtime namespaces; specifying the exact
format's normal managed path retains managed re-export semantics.

The latest artifact metadata for each immutable client ID and format is stored
below:

```text
/var/lib/vpnctl/exports/clients/.metadata/<client-id>.<format>.json
```

The sidecar contains only the output path, required mode, content SHA-256, and
source generations. Both formats depend on the client credential generation;
only Clash depends on client policy generation. Global state generation is
provenance rather than a blanket invalidation trigger, so a preset-only edit
marks Clash stale while the full-tunnel WireGuard artifact remains current.
Task 7.11 connects this comparison to `client show`, rotation, revoke, and
delete lifecycle behavior.

The profile and sidecar are separate files, so a process/power failure between
their two atomic renames can leave a detectable hash/generation mismatch rather
than silently declaring an artifact current. Ordinary activation failures roll
the profile back to its exact prior bytes and mode; an indeterminate durability
result is returned explicitly and is safe to reconcile by repeating export.

Successful public output contains only the absolute path, `0600`, source state
generation, immutable client ID, and a copy-ready
`scp root@<public-ip>:<path> .` action. Human and JSON renderers never receive
the profile, content hash, private metadata path, QR payload, hosted URL, or
subscription data.
