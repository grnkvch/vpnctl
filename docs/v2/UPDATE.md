# Manual release updates

`vpnctl update` is an explicit, host-local operation. vpnctl performs no
background version check, has no beta/nightly channel, and never installs an
update on another machine.

## Release selection

```text
sudo vpnctl update
sudo vpnctl update 2.1.0
sudo vpnctl update v2.1.0
```

With no version, vpnctl contacts the latest-stable release endpoint only for
that invocation. An explicit version is canonicalized to `vMAJOR.MINOR.PATCH`
and addresses only that exact stable release. Prerelease labels and arbitrary
release URLs are rejected. `--dry-run` still downloads and verifies a private
temporary stage so its plan is evidence-based, but discards that stage without
changing state, installed files, or services. `--defer` is unsupported.

The release source provides three assets: the standalone vpnctl binary, the
complete bundle for both roles, and canonical checksum metadata. Before showing
an actionable plan, vpnctl verifies exact sizes and SHA-256 values, bundle
framing and platform, every bundled artifact, and equality of the standalone
binary with the bundle's vpnctl artifact. The complete target is staged before
role-local selection begins. Publisher identity relies on the HTTPS release
channel in v2.0; checksum metadata is not a cryptographic publisher signature.

## Gateway-first order

The operator updates the gateway first, then connects to each private node over
SSH and runs the node update locally. A gateway plan checks every active node
against the target control-protocol compatibility window and blocks if a node
would become unmanageable. A joined node performs one read-only, short-lived
mTLS preflight against the gateway's internal overlay endpoint before it may
change a local binary or service. That endpoint is served on the fixed internal
control port and is not exposed on the public gateway interface.

The node preflight proves that the target is not newer than the gateway, that a
mutual protocol exists, and that no earlier node management request remains
uncertain. It does not ask the gateway to update the node. An unjoined node has
no fleet dependency.

## Plan and apply

The confirmation plan reports:

- current and target release versions;
- every role-relevant component and whether its installed file changes;
- compatible installed Ubuntu package versions without invoking apt;
- fleet compatibility and the selected control protocol;
- current and target state schemas, migration steps, and reversibility;
- only the local services affected by changed files;
- expected management, transport, routing, tunnel, or ingress interruption;
- whether the planned migration permits rollback.

A blocked plan is returned without asking for consent and without mutation.
Otherwise update requires the normal availability-impacting confirmation.
When a future release has an actual irreversible state migration, it also
requires the separate exact typed confirmation from the stdin contract;
`--yes` cannot satisfy that barrier.

Apply stops only gateway management while it is the authoritative state writer,
records a pending operation, and replaces changed bundled components one at a
time. Each replacement is atomic and followed by its local service health
check. Providers are activated before the vpnctl binary. Unchanged healthy
data-plane components are not restarted. The verified bundle/checksum metadata
and component manifest become current only after component health
passes, then gateway management resumes and the operation is completed.

A proven failure in the active attempt restores already changed component
files and release metadata in reverse order, health-checks the restored local
services, restores the prior component state, records the failed operation,
and resumes prior management.

## Persistent snapshot and rollback

Before the first component replacement, a changed update copies the verified
prior bundle, canonical checksum metadata, and canonical prior state
into a mode-`0700` versioned directory under
`/var/lib/vpnctl/snapshots`. Every file is mode `0600` and bound by snapshot
SHA-256 metadata. An atomic pending pointer makes an interrupted update visible
instead of silently replacing the previous usable rollback. After the update
state is complete, vpnctl binds the snapshot to the exact resulting state and
atomically promotes it as the single previous-update snapshot. A failed update
removes only its own candidate and preserves any older successful snapshot.

```text
sudo vpnctl update rollback --dry-run
sudo vpnctl update rollback
```

Rollback is local and makes no release-network request. It re-verifies the
snapshot hashes, canonical checksum metadata, whole bundle, platform, role,
component manifest, current-state binding, installed files, apt package
ranges, and fleet protocol compatibility before showing its plan. The plan
lists the version/state restoration, changed components, affected services,
and expected interruption. Normal confirmation is required. Components and
metadata are restored sequentially with the same per-component health and
reverse-failure handling as a forward update; the prior semantic state is
restored at a new monotonic generation with both update operations retained as
audit history. The snapshot is consumed only after successful rollback.

Rollback stops before mutation if the snapshot is absent, incomplete,
corrupt, for another role/version, no longer matches current authoritative
state, fails package/fleet compatibility, or records an irreversible state
migration. The separate exact `accept irreversible migration` confirmation is
required before applying a forward update with a real irreversible migration;
`--yes` does not satisfy it. Portable encrypted backups remain a different
recovery boundary.

Single-gateway zero downtime is not promised. The exact plan is derived from
changed components: a controller binary can briefly interrupt management, a
Mihomo replacement can reconnect restricted transport while routing remains
fail-closed, and an frp replacement can temporarily make ingress return `503`
or interrupt an active request. No failure path switches selected traffic to
direct.
