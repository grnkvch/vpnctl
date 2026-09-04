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
