# Explicit vpnctl-owned drift repair

Task 13.5 makes `vpnctl repair` the only generic path that reconciles observed
runtime drift. Repair does not apply pending intent, adopt manual edits, or
change a resource whose ownership has not been positively established.

## Repair baseline and actions

The strict convergence planner compares the last successfully applied manifest
with current owned observations. Repair derives exactly one action from every
reported drift item:

| Owned drift | Repair action | Required success evidence |
| --- | --- | --- |
| missing | restore | resource is present at the applied runtime SHA-256 |
| modified | restore | resource is present at the applied runtime SHA-256 |
| unexpected | remove | resource is absent and has no runtime hash |

The target is `applied_generation`: the runtime desired by the last successful
apply. A newer authoritative `desired_generation` and its registered pending
operations remain unchanged. This prevents repair from becoming an implicit
apply. Manifests and previews contain fingerprints and stable identifiers, not
rendered configuration or credential material.

Discovery adapters may report an unexpected resource only with positive
vpnctl ownership evidence, such as an exact owner marker. Unknown or foreign
files, units, network objects, and state records remain outside the observation
set. Since repair actions must exactly and in order cover planner drift, callers
cannot append a foreign action to an approved plan.

The production local scope resolver is closed over the authoritative role and,
for a node, its immutable node ID. It accepts only the fixed role unit catalog
and direct files in `/etc/vpnctl/generated/gateway` or
`/etc/vpnctl/generated/node`; a cross-role component, nested/sibling path, or
unsupported resource kind invalidates the whole plan. Repair-plan construction
is a read-only API with no executor dependency, so preview and a clean no-op do
not need to construct a mutation-capable runtime.

## Preview and consent

`vpnctl repair --dry-run` returns the complete non-secret repair set without an
executor call or consent prompt. Each item includes component, resource kind
and ID, drift kind, action, impact, and applicable observed/target hashes.

Normal repair always requires explicit yes/no confirmation; `--yes` may provide
that consent. `--json` changes only output format and never grants consent.
After consent the coordinator repeats snapshot loading, owned discovery, action
derivation, and role resolution. Any changed generation, pending set,
observation, ownership result, hash, impact, or scope makes the preview stale
before mutation.

## Role and execution boundaries

Gateway repair accepts only gateway-local actions. A private node accepts only
actions for its immutable current node ID and must reach the authoritative
gateway even when the plan is a no-op. There is no gateway-side remote-node
executor and no permanent node agent; node repair runs in the node's current
`vpnctl` process.

The role executor must return ordered per-resource evidence for the exact target
generation. A restored hash mismatch or an unexpected resource still being
present rejects the result, so repair cannot claim success without convergence.
The authoritative desired, applied, and pending snapshots are not rewritten by
repair itself; concrete component transactions perform only the previewed
runtime corrections.

The Linux role repair primitive is restore-only and action-scoped. Before its
first write it validates the complete batch, fixed role ownership, direct
generated-config paths, exact content hashes, unit targets, same-owner
directories, and current file/systemd observations. Apply consumes the opaque
in-memory plan, repeats that preflight, and rejects a stale plan. It writes only
selected files, reloads systemd only after a selected unit-file repair, and
changes only selected units or explicitly listed dependent restarts. Unit
success evidence covers exact `LoadState`, `ActiveState`, `SubState`, and
enablement as well as regular single-link file content and mode. A
per-file/per-unit attempt journal drives bounded rollback, including uncertain
post-rename errors and removal of a unit that was missing before repair.
Retained prior and target bytes are wiped
when the one-shot plan is consumed or rejected. Unit action attempts retain
call order and are unwound in reverse dependency order; an inactive unit that
an attempted start leaves failed may be reset during that rollback. A failed
or transient pre-state is rejected because it cannot be recreated safely.
Rollback re-observes the full pre-repair file and unit shape; if systemd cannot
reproduce an unusual prior substate, the operation reports the incomplete
rollback explicitly instead of claiming success.

The required material source is now a root-only, content-addressed archive
under `/var/lib/vpnctl/applied-material`. Its ID is derived only from the
canonical `Applied` manifest; loading by an arbitrary ID is impossible. Each
immutable `0600` bundle is bounded and validated one-to-one against every
applied file/unit runtime hash, including complete systemd state. APIs redact
and wipe retained bytes, reject symlinks/hardlinks/unsafe modes, and remove
only a fully validated uncommitted gateway-join bundle after convergence has
been conclusively rolled back.

Every role-generation publisher now follows `durable material -> convergence
Initialize/CAS`. This covers gateway and node initialization, active gateway
join, committed gateway repair, and active node join/repair. An equal-snapshot
retry still ensures the archive, so it heals a missing bundle before reporting
success. Portable backup intentionally excludes this local reconstruction
cache; recoverable uninstall preserves it, while purge removes it with the
state tree.

The primitive is still deliberately disconnected from public generic drift
repair. The remaining bridge must load only the current Applied bundle, bind
its entries to the already reviewed action set, and execute under the
authoritative host mutation lock. Re-rendering current or `previous` state is
not equivalent: state-only mutations may advance those values without
advancing the applied runtime. Until that executor bridge exists, public
repair keeps using the narrower committed-generation recovery adapters below.

## Committed-generation recovery boundary

Gateway and private-node initialization/join can commit authoritative state
before their service-generation convergence publication is durably
acknowledged. Public `vpnctl repair` therefore has a closed recovery adapter
for this state: it previews the complete role-owned committed generation by
service/config name and SHA-256, then recompiles the same generation after
consent. This adapter never adopts observed content, changes authoritative
state, downloads components, or targets resources outside the fixed role
catalog.

Gateway execution occurs only in the resident controller under the same
mutation lock used by DNS, logging, invites, and enrollment. If the initial
network activation has no committed watchdog transaction, recovery additionally
previews its firewall and original-network hashes. It may reactivate networking
only when a newly captured watchdog snapshot is byte-logically equal to the
oldest retained pre-vpnctl snapshot. The result then requires
`vpnctl confirm <transaction-id>` from a new SSH session; `--yes` cannot satisfy
that independent gate. A pending watchdog blocks repair, and a lost controller
response is reported as outcome-uncertain rather than safe to retry blindly.
