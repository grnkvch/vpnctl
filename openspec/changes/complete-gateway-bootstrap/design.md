## Context

See `proposal.md` for the discovered failure. The verified release manifest
already carries role-filtered Ubuntu package compatibility records, and bundle
installation already returns them, but init drops the result after comparing
only the manifest. Gateway init provisions its public certificate and loopback
enrollment service but never calls the existing nginx renderer/activation
manager and owns no production nginx service definition. Current convergence
and passive status enumerate only `vpnctl-*` role units.

The nginx renderer, pinned native validator, immutable-tree activation and
rollback mechanisms are already implemented and qualified independently. The
missing work is lifecycle composition. The existing production candidate also
creates a compatibility boundary: its updater refuses a target while nginx is
missing, and a new CLI cannot send a new repair plan to the old running
controller. Recovery therefore cannot pretend that executing a staged new CLI
alone is sufficient.

## Goals / Non-Goals

**Goals:**

- make package, service, ingress-tree and listener readiness one explicit
  Gateway bootstrap transaction and postcondition;
- make shipped editable preset sources immediately selectable by compiling
  their exact initial snapshots into fresh Gateway state;
- share one bounded read-only readiness model across init, status, plan, doctor
  and repair;
- preserve existing identity, WireGuard and provider implementations;
- provide a truthful, rehearsable path from the one incomplete unpublished
  candidate to the final same-version release;
- keep the edit/test loop local and focused until the exact user scenario works.

**Non-Goals:**

- redesigning the release gate, evidence fingerprints, capacity or Lima
  topology;
- reviving or extending the v1 migrator;
- supporting arbitrary distributions, reverse proxies, package repositories or
  unattended OS upgrades;
- adding an offline/local-bundle update flag or another public recovery command;
- making controller startup repair drift automatically.

## Decisions

### 1. Consume the bundle package contract through one role package transaction

Add one package lifecycle adapter whose only accepted inputs are the validated
`APTPackageCompatibility` records selected for the initialized host role. Its
read-only plan records installed version, required exact version/range and the
action, and those rows become part of init/repair human and JSON previews.

Apply rechecks the retained baseline, serializes against package-manager use,
runs `apt-get update` only when an action is required, resolves the declared
pinned version, then uses noninteractive `apt-get install --no-install-recommends`
with an explicit `package=version`. It verifies the final dpkg version with the
same inclusive-minimum/exclusive-maximum rules. It never accepts a package name
or version outside the signed-by-checksum release manifest and never invokes
`apt upgrade` or `autoremove`.

A private transaction journal is written before package mutation and records
only package names/versions and prior mask/enable/active states. An exact retry
may reconcile a pending transaction. A known failure removes only packages that
were absent before this transaction and restores captured service state; an
interrupted or externally changed package state is reported as explicit residue
instead of guessed away. Successfully installed Ubuntu dependencies remain
ordinary host packages across `vpnctl uninstall`, consistent with the existing
recoverable-uninstall contract; vpnctl removes only its runtime/configuration.

During nginx package installation the distro service is temporarily masked so
post-install scripts cannot bind public ports with the distro default config.
The mask is restored on failure and removed only after the vpnctl service
configuration and baseline tree are ready.

Alternative considered: install all dependencies in `scripts/install.sh`.
Rejected because that installer deliberately has no role and would either
install Gateway packages on Nodes or introduce a second role-selection API.

### 2. Split immutable host preflight from package-provided capabilities

The first init snapshot continues to reject the wrong OS/architecture, missing
root/systemd/kernel capabilities, unsafe paths, occupied ports and foreign
network ownership. Missing commands supplied by a declared role package are
classified as planned package work rather than an unsupported host. Dry-run
shows that full capability validation is an apply postcondition.

After the package transaction, init rediscovers the host and runs the complete
existing capability, listener and network preflight before state, identities,
firewall or services are committed. This lets a clean Ubuntu host acquire
`nftables`, `wireguard-tools` and nginx while still failing closed if the kernel
or the post-install host cannot satisfy their capabilities.

Alternative considered: keep requiring operators to install prerequisites.
Rejected because it repeats the production defect and contradicts complete
selected-role initialization.

### 3. Compose the existing nginx tree transaction with an owned service drop-in

Gateway init renders an empty-expose `NginxCandidate` from the just-provisioned
public certificate, committed public IP, fixed hard limits and generation. The
existing activation manager performs pinned parsing and publishes the retained
immutable generation. A small service adapter owns only
`/etc/systemd/system/nginx.service.d/vpnctl.conf`; it clears the distro start/
reload commands and runs `/usr/sbin/nginx` against the managed `current` tree
and `/run/vpnctl-ingress`. Foreign content at that exact drop-in or the managed
tree is a conflict.

The apply order is:

1. finish package installation and full host rediscovery;
2. provision identity/certificate and validate the candidate nginx tree;
3. arm the existing network watchdog and persist the Gateway generation;
4. start the vpnctl role units, including the loopback enrollment upstream;
5. publish the retained nginx tree and owned drop-in, then enable/start nginx;
6. activate the existing firewall and verify service, TCP 443, IP-only TLS and
   the reserved health route;
7. publish convergence, commit the nginx generation and mark the watchdog
   activated.

The fresh authoritative candidate compiles each shipped built-in preset source
with the same initialization timestamp before it is persisted. The editable
files and effective records therefore start from identical hashes/selectors at
generation 1. Later file edits still require the ordinary explicit preset
workflow; repeated init neither reapplies edits nor recreates deleted sources.

A known failure stops only newly activated nginx state, restores the previous
drop-in/service/tree and package transaction, and invokes the existing network,
identity and transport compensation. If authoritative state was already
persisted, the command reports initialization/convergence pending; repeating
the same init re-plans the missing bootstrap work instead of returning the
current incorrect no-op.

Alternative considered: create a separate `vpnctl-ingress.service`. Rejected
because the accepted provider contract and uninstall/update surfaces already
identify `nginx.service`; a narrow owned drop-in composes with the Ubuntu package
without duplicating its full unit.

### 4. Introduce one read-only Gateway bootstrap readiness projection

A single bounded inspector derives expected readiness from authoritative state
and the installed verified bundle, then observes:

- dpkg version compatibility for every Gateway package;
- the owned nginx service drop-in and active generated-tree generation/hash;
- nginx load/enable/active state and pinned runtime version;
- the TCP 443 listener without making a request;
- the fixed loopback enrollment listener.

It performs no apt refresh, HTTP request, service control or filesystem repair.
The generic applied-material archive remains limited to the existing fixed
role files and units: package state, an immutable nginx tree and a distro unit
with a vpnctl-owned drop-in cannot be restored safely by its generic byte/unit
executor. Instead, the public convergence planner merges the shared readiness
projection into the ordinary role drift. This gives `plan` one effective view
without misrepresenting package/service/tree recovery as generic material.
Passive status uses the same observation and marks nginx mandatory;
`doctor ingress` retains the existing active TLS/health probes and cannot be
substituted by passive checks. Confirmed repair routes readiness drift through
the dedicated package, drop-in and immutable-tree lifecycle adapters.
Ingress readiness renders the current semantic ingress inputs at the retained
active tree's provenance generation. An older active generation remains healthy
when that exact tree hash matches; metadata-only authoritative generations such
as invite creation therefore require neither an nginx reload nor repair. A
newer active provenance or a semantic input change (for example public IP,
certificate, reserved route, or expose changes) remains drift. Passive status
detects a concurrent collection race by rereading authoritative state after
planning instead of equating authoritative and convergence generations, since
clean material may legitimately predate metadata-only state.
Package-manager and system-wide ingress mutation is deliberately not executed
by the resident controller: its systemd sandbox retains no APT, dpkg, nginx or
system-unit write access.
The controller does admit `AF_NETLINK` in addition to its existing IPv4 and
Unix families solely because pre-commit Gateway join readiness invokes the
read-only `wg` and `ip` observers. This does not add a capability, an IPv6
family, or any package/nginx/system-unit write path; without netlink the
sandbox makes a real WireGuard interface indistinguishable from absence.

Gateway repair schema advances once and binds the package baseline, drop-in,
candidate tree hash, service expectation and any existing network watchdog
material. After confirmation, ordinary generic owned-runtime repair remains
mediated by the controller. If mandatory bootstrap or network-watchdog work is
present, the short-lived root CLI
acquires the same root-only cross-process Gateway mutation lock as the
controller, revalidates the complete retained plan and authoritative generation,
then runs the same package/role/ingress/network transaction locally. Concurrent
controller mutations fail busy or wait outside that boundary; the lock is not a
replacement for generation and plan equality checks. The CLI verifies that the
authoritative state did not change and returns the same watchdog confirmation
contract. Because systemd `Type=simple` activation may precede WireGuard and
nginx listener readiness on the minimum host, post-activation runtime checks
retry only inside fixed bounded windows; timeout remains a failed transaction
and triggers the same compensation. A present incompatible package, foreign drop-in/tree or unmanaged TCP
443 listener is a conflict, not an adoption or downgrade.

Alternative considered: add independent nginx checks separately to status,
plan and repair. Rejected because that recreates the inconsistency that allowed
status to report healthy while the user path was absent.

### 5. Treat unavailable public enrollment as a stable failure category

The join HTTP adapter wraps bounded dial, timeout, TLS trust/identity and
gateway 502/503/504 failures in a dedicated enrollment-unavailable error while
retaining validation/authentication errors for malformed or rejected invites.
CLI classification returns `unavailable` plus a safe action to check Gateway
status and `doctor ingress`; it does not expose the endpoint transcript, token
or cryptographic data. Existing staging compensation remains authoritative, so
this mapping cannot turn a partial join into `changed=false`.

The public enrollment transaction, loopback HTTP response, nginx reserved
enrollment proxy, and Node response-header wait share one fixed 45-second
budget. TCP/TLS admission and request-header/body reads retain their shorter
bounded limits, and existing concurrency/rate caps remain in force. This is not
a general RPC timeout increase: first join synchronously stages and verifies
multiple Gateway services, which can exceed five seconds on the supported
1-vCPU/512-MiB host. A client timeout after writing the request remains an
uncertain outcome rather than being relabeled unavailable.
After service restart, the complete Gateway join readiness report retries every
100 milliseconds for at most 20 seconds inside that response budget. This
covers `Type=simple` process activation preceding WireGuard/listener readiness
without relaxing any health invariant. Exhaustion rolls back the exact staged
candidate and returns the non-oracular fixed `503 unavailable`, not a `404`
credential rejection.

The candidate transaction also renders the Gateway identity firewall from the
same candidate state and atomically replaces only the already-owned
`inet/vpnctl` table before readiness is observed. It snapshots that exact table
first and retains the rollback handle until authoritative invite/Node state is
committed. A readiness, convergence, credential, or state-commit failure
restores the exact prior table; a successful or provably committed join retains
the candidate table. The update never creates an absent ownership claim and
does not touch routes, policy rules, sysctls, or foreign nftables tables.

After the Node has durably committed the assignment, its systemd activation is
still a recoverable local convergence step. Every Node role unit declares the
same private `RuntimeDirectory=vpnctl`, so a reboot cannot fail its namespace
setup merely because the tmpfs-backed `/run/vpnctl` directory is absent. The
activator retries the current unit's start and active observation inside one
fixed 20-second window before advancing to the next unit. This covers a
transient WireGuard/routing-guard ordering race without skipping the failed
unit; exhaustion retains the existing activation-pending, fail-closed result
instead of claiming a successful join.

After all units report active, the activator retries the complete unchanged
routing-and-FRP readiness check within the same fixed 20-second bound before
publishing the active convergence generation. This closes the remaining
`Type=simple` post-start race without weakening any readiness invariant. If
the bound expires, authoritative Node assignment and the fail-closed runtime
remain intact, active convergence is not published, and repair remains the
explicit recovery path.

The recovery-table route for the public Gateway endpoint is derived from the
unique route Linux would use in the unmodified main table. Longest-prefix match
precedes metric, with the best default used only when no more-specific route
matches. The compiler copies that route's interface and next hop into the owned
table; equal-priority ambiguity or an invalid next hop fails before local
activation. This keeps ordinary Internet deployments unchanged while
preserving an explicit host route in isolated or multi-uplink environments.

### 6. Recover the one old candidate with a narrow prerequisite, then normal flows

The old candidate's updater already compares component pins and file SHA values,
so it can recognize a different bundle whose version string remains `v2.0.0`.
It blocks only because its package preflight finds nginx absent. A one-time
operational prerequisite therefore:

- verifies the exact recorded old binary/bundle/checksum hashes, Gateway state,
  absent nginx package/managed tree/TCP 443, idle package manager and expected
  Ubuntu architecture;
- refreshes apt metadata, requires the exact pinned nginx candidate, masks the
  distro service, installs only nginx with no recommendations, verifies it and
  leaves it disabled/inactive;
- appends its before/after state and exact reversal to the host journal.

After the final release is published, the existing old binary runs the normal
`vpnctl update v2.0.0`; manifest/SHA differences replace the product artifacts.
The corrected product then runs confirmed `vpnctl repair`. Its short-lived root
CLI transaction installs any other missing declared package and publishes/
health-checks ingress while the resident controller keeps its narrow sandbox.
This exception is rehearsed against the exact incomplete-candidate shape and is
retired with the other deployment staging artifacts. It is not part of future
user installation.

Alternative considered: execute the new staged CLI's repair directly. Rejected
because apply is mediated by the old controller, which cannot validate or apply
the new repair plan. Adding a permanent offline-update/recovery command is also
disproportionate for one unpublished candidate.

### 7. Prove behavior before adding only one focused E2E entrypoint

Fast development uses fake package/service/readiness adapters and the existing
nginx activation tests. No Lima command runs until these focused packages pass.
Then two manual scenarios use only the exact existing `vpnctl-v2-gateway` and
`vpnctl-v2-node` fixtures after owner/image/resource and stopped-state checks:

1. clean no-nginx install, Gateway init, Node init, invite, real public join and
   one request selected by a shipped generation-1 preset;
2. initialized Gateway with retained client plus missing nginx, guarded recovery,
   repair, client continuity and Node join.

Only after both pass, one `v2gateway-enrollment-e2e.sh`-style entrypoint captures
the critical fresh bootstrap/join and missing-ingress repair checks. It uses the
actual candidate binary/bundle, keeps invite material in a root-only transient
PTY/input boundary, emits no token, and restores only owner-validated resources
and the fixtures' initial stopped state. It does not join the general stage
registry in this change. The complete release gate runs once after source commit
freeze; capacity remains on demand.

## Risks / Trade-offs

- **[APT availability can make a valid product look broken]** → Separate
  package/bootstrap classification from product health, keep retries bounded,
  and run real APT only in the focused VM scenario and final deployment.
- **[Package post-install scripts can expose distro defaults]** → Mask nginx
  before install and unmask only after the owned tree/drop-in exist.
- **[Package rollback cannot erase apt cache/history]** → Restore installed
  package and service runtime state; retain harmless apt metadata and disclose it
  rather than claiming byte-identical filesystem rollback.
- **[Adding nginx to convergence may disturb expose/update flows]** → Derive one
  readiness descriptor from state and require init, expose, revoke, restore,
  update and repair tests to publish the same resource identity.
- **[Same-version recovery is operationally ambiguous]** → Bind every step to
  old/new commit and SHA-256, never publish the old assets, and verify installed
  final hashes rather than trusting `vpnctl version`.
- **[A focused VM script can grow into another gate framework]** → Fix its two
  modes and existing topology in contract tests; reject resume/fingerprint/
  capacity/migration features in this change.

## Migration Plan

1. Implement and exhaust fast package/init/nginx/readiness/repair/join tests with
   no VM or production access.
2. Run the manual fresh and incomplete-candidate scenarios on the existing Lima
   pair, recording every fixture mutation and owner-scoped cleanup.
3. Add and pass the one focused E2E, freeze the source commit, then run the full
   Go verification and existing fast/resumable VM gates once.
4. Build the final `v2.0.0` assets, verify their exact checksums, create the sole
   public tag/release, and retain the old candidate identity only in audit data.
5. On production, run the guarded nginx prerequisite, normal same-version
   update, confirmed repair and full Gateway readiness checks. Before update,
   rollback removes only the newly installed nginx packages and restores their
   captured state; after update, use the existing update snapshot/rollback plus
   the repair transaction's retained ingress generation.
6. Create a fresh invite, complete Node join, verify the selected Telegram API
   path and real webhook, then execute the previously agreed migration-artifact
   cleanup and archive the operational migration ref.
