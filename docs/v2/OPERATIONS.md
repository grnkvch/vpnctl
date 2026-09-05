# vpnctl v2.0 operator guide

This is the canonical operator guide for v2.0. The examples assume Ubuntu
24.04 amd64, root access, and a dedicated server for each vpnctl role. Replace
the documentation IPv4 `203.0.113.10`, names, paths, and resolver addresses
with values for the deployment.

The complete arguments, consent classes, JSON results, and exit codes are
frozen in [CLI_CONTRACT.md](CLI_CONTRACT.md). Every `vpnctl` command block in
this guide is checked against that contract and executed through the public
role gate by the documentation test. Commands which can change networking or
state should be previewed with `--dry-run` whenever the contract permits it.

## Deployment model and ports

One external-region gateway can serve multiple personal clients and multiple
private VPS nodes. A private node sends only explicitly selected traffic to the
gateway; unmatched traffic remains direct. The node receives no general access
to another private network segment. It uses the gateway only for selected
internet egress, internal management, and its outbound reverse tunnel.

The role selected by `init --gateway` or `init --node` is immutable. One binary
contains both roles, but an initialized host installs and runs only its own
services. The gateway takes ownership of vpnctl's dedicated host networking and
these fixed unsolicited public listeners:

| Listener | Purpose |
| --- | --- |
| `443/TCP` | IP-only HTTPS ingress plus reserved enrollment/recovery paths |
| `8443/TCP` | Shadowsocks 2022 + ShadowTLS v3 strict restricted transport |
| `51820/UDP` | standard WireGuard transport |

There is no public `443/UDP` or `8443/UDP` listener. Restricted UDP is carried
inside `8443/TCP`; it is not native gateway UDP and does not pass through the
HTTPS reverse proxy.

The minimum supported target is 1 vCPU, 512 MiB RAM, and 10 GiB disk. On a
low-memory clean host, initialization can offer one vpnctl-managed 1 GiB swap
file. Accepting or declining that explicit offer does not change the public
command. Existing suitable swap is reused and never claimed as vpnctl-owned.

## Install the signed release

Install the complete signed v2 release on every gateway and node before role
initialization. The online bootstrap and offline `scp` flow, exact four release
assets, trust anchor, and atomic rollback behavior are specified in
[INSTALLATION.md](INSTALLATION.md). The bootstrap retains the verified complete
bundle locally; ordinary init/apply/repair does not download Mihomo, frp, or
other bundled components from upstream.

Do not run init on a development laptop. Gateway init deliberately refuses an
unmanaged process on a reserved port, UFW/firewalld ownership, overlapping
networks, an unverified SSH listener, or incompatible TUN/WireGuard resources
before mutation.

## Happy path A: gateway and personal devices

Run initialization on the external-region VPS. The public IPv4 is mandatory
and is never looked up automatically.

```console vpnctl-doc-test id=init.gateway role=uninitialized
sudo vpnctl init --gateway --public-ip 203.0.113.10
```

Initialization may activate a lockout-risk network plan and return a short
transaction ID. Keep the original SSH session open, establish a new SSH
session through the configured public listener, and run the exact command from
the result:

```console vpnctl-doc-test id=confirm role=gateway
sudo vpnctl confirm fw-7K3M2P
```

Only the new session proves connectivity. Without confirmation, the independent
watchdog restores the prior vpnctl network snapshot after 120 seconds. If init
reports no transaction ID, no confirmation is needed.

Create an iPhone client with only the selected presets intended for that
device, then export a Clash-compatible profile:

```console vpnctl-doc-test id=client.add role=gateway
sudo vpnctl client add iphone telegram openai
```

```console vpnctl-doc-test id=client.export role=gateway
sudo vpnctl client export iphone clash
```

The profile contains explicit `standard` and `restricted` alternatives. The
person importing it into Clash Mi chooses one manually; vpnctl never changes
the selection in response to a health check. Selected traffic is
gateway-or-block, and unmatched traffic is direct. Retrieve the mode-`0600`
profile using the exact `scp` hint printed by vpnctl.

For a conventional full-tunnel WireGuard client, create it without presets and
export the WireGuard format:

```console vpnctl-doc-test id=client.add role=gateway
sudo vpnctl client add steamdeck
```

```console vpnctl-doc-test id=client.export role=gateway
sudo vpnctl client export steamdeck wireguard
```

Profiles are files, never stdout or JSON payloads. URL delivery, subscription
links, and QR delivery are outside v2.0.

## Happy path B: private VPS and webhook ingress

Create the invite on the gateway. Its opaque value is displayed once, expires
after 15 minutes, and is stored only as a hash. A dry run never creates a token.

```console vpnctl-doc-test id=invite role=gateway
sudo vpnctl invite bot-server
```

Install the signed release on the private-region VPS and initialize its local
role:

```console vpnctl-doc-test id=init.node role=uninitialized
sudo vpnctl init --node
```

Join from the private VPS. Enter the invite only in the hidden controlling-TTY
prompt. The transport and initial preset list are explicit and atomic.

```console vpnctl-doc-test id=join role=node
sudo vpnctl join restricted telegram
```

`restricted` makes selected node TCP, selected node UDP, internal control, and
the reverse tunnel use the DPI-resistant path. `standard` is also valid when
WireGuard is usable in the private region.

If a local application listens on `127.0.0.1:3000`, create an exact public
HTTPS route from the private VPS:

```console vpnctl-doc-test id=expose role=node
sudo vpnctl expose 3000 --path /telegram/webhook
```

The result provides the IP-only URL
`https://203.0.113.10/telegram/webhook`, public certificate fingerprint/export
information, and an `scp` hint. Omitting `--path` creates a random 256-bit exact
path. `--prefix` must be chosen explicitly for subtree routing. A stopped local
application is a valid degraded expose and produces public `503` responses.

vpnctl owns the certificate, route, reverse-tunnel mapping, forwarding limits,
and status. It does not call Telegram, store a bot token, register or remove a
webhook, validate application semantics, or persist/retry request bodies. The
application owner registers the emitted URL and public certificate with
Telegram, handles the request, and removes or updates the external registration
before deleting or rotating the corresponding vpnctl resource.

Inspect an expose and refresh its public-only certificate copy when the gateway
is reachable:

```console vpnctl-doc-test id=expose.show role=node
sudo vpnctl expose show telegram-api
```

Remove the public route and its one tunnel mapping from the private VPS:

```console vpnctl-doc-test id=expose.remove role=node
sudo vpnctl expose remove telegram-api
```

The result deliberately reports a command-free `remove_external_webhook`
action. Other exposes remain serving.

## Presets, policy, and the classification boundary

Gateway init creates editable `telegram`, `openai`, and `anthropic` selector
documents under `/etc/vpnctl/presets.d/` only when absent. Operators may add or
delete unassigned preset files. Source edits do not silently become effective:

```console vpnctl-doc-test id=preset.validate role=gateway
sudo vpnctl preset validate
```

```console vpnctl-doc-test id=preset.diff role=gateway
sudo vpnctl preset diff
```

Node and client policy changes replace the complete assignment. There is no
incremental add/remove or automatic assignment:

```console vpnctl-doc-test id=policy.set.node role=node
sudo vpnctl policy set telegram --defer
```

```console vpnctl-doc-test id=policy.set.gateway role=gateway
sudo vpnctl policy set telegram openai --client iphone
```

Review and apply intentionally deferred node changes:

```console vpnctl-doc-test id=plan role=node
sudo vpnctl plan
```

```console vpnctl-doc-test id=apply role=node
sudo vpnctl apply
```

The fail-closed promise begins only after classification. A selected TCP or UDP
flow either uses the manually active gateway transport or is blocked; it never
becomes direct. A flow which does not match a selector remains direct.

Classic UDP/TCP port-53 DNS is managed, allowing ordinary selected-domain
queries to use the gateway DNS path. Independent application DoH/DoT hides the
name, and a hardcoded IP has no DNS name to observe. Such traffic remains
unmatched/direct unless an explicit IP/CIDR selector also selects it. vpnctl
does not inspect generic TLS or globally block third-party DoH/DoT. Selected
IPv6 is blocked because v2.0 has an IPv4-only data plane; unmatched IPv6 keeps
the host's existing behavior. See
[CLASSIFICATION_BOUNDARY.md](CLASSIFICATION_BOUNDARY.md) for the exact boundary.

DNS upstream scope follows the host role: the gateway owns selected-path IPv4
upstreams, while a node owns direct-path IPv4 upstreams.

```console vpnctl-doc-test id=dns.show role=gateway
sudo vpnctl dns show
```

```console vpnctl-doc-test id=dns.set role=gateway
sudo vpnctl dns set 1.1.1.1 8.8.8.8
```

```console vpnctl-doc-test id=dns.reset role=node
sudo vpnctl dns reset
```

A selected-DNS failure remains fail-closed while unrelated direct DNS and
traffic continue independently.

## Manual transport operations and restricted UDP

Testing a standby transport is isolated and does not change active routing,
state generation, or the current tunnel:

```console vpnctl-doc-test id=transport.test role=node
sudo vpnctl transport test restricted
```

Switching is always a manual, confirmed make-before-break operation:

```console vpnctl-doc-test id=transport.switch role=node
sudo vpnctl transport switch restricted
```

The target must pass control, tunnel, selected TCP, and selected UDP readiness.
Failure preserves the old active path. Success drains it within the bounded
window and then leaves exactly one active transport. There is no automatic
fallback, health-test selection, or fail-direct behavior. `--defer` records the
choice for later `plan`/`apply` instead of activating it immediately.

Restricted UDP uses Mihomo UoT v2 inside Shadowsocks/ShadowTLS TCP. It is
functionally accepted as best-effort selected UDP on a healthy path for
request/response probes up to 1200-byte application datagrams at the measured
rates. That is not a latency, throughput, concurrency, or availability SLO.
TCP head-of-line blocking can amplify loss and latency after a short outer-path
fault. v2.0 makes no restricted-transport performance guarantee for voice or
video calls, games, QUIC/HTTP3, sustained high-rate/bulk UDP, path disruption,
or application datagrams above 1200 bytes. Choose standard WireGuard manually
when predictable latency-sensitive UDP matters. Detailed measurements are in
[spikes/RESTRICTED_UDP_BENCHMARK.md](spikes/RESTRICTED_UDP_BENCHMARK.md).

## Status, doctor, and temporary logging

`status` is passive: it reads state, drift, cached runtime metadata, component
versions, certificate/backup warnings, and pending actions without creating
traffic or changing the host.

```console vpnctl-doc-test id=status role=gateway
sudo vpnctl status
```

```console vpnctl-doc-test id=status role=node
sudo vpnctl status --all
```

Exit `0` includes healthy warnings/pending intent, `2` is validation failure,
`3` is owned drift/conflict, and `4` is a required unavailable/degraded
dependency. `--json` always contains the complete safe result; `--all` only
expands human tables.

`doctor` is the explicit bounded active-probe boundary. With no scope it runs
the role-applicable set; use a scope to reduce impact:

```console vpnctl-doc-test id=doctor role=node
sudo vpnctl doctor transport
```

```console vpnctl-doc-test id=doctor role=gateway
sudo vpnctl doctor ingress
```

Ingress doctor uses only vpnctl's reserved health path, never a real expose or
webhook path. An optional `--probe-url` performs one credential-free HTTPS GET
with no redirect following. No external URL means no hidden third-party call.

Expanded logging is off by default and is enabled only by a local explicit,
temporary opt-in. The duration is required and cannot exceed one hour.

```console vpnctl-doc-test id=log.enable role=gateway
sudo vpnctl log enable ingress --level trace --for 10m
```

```console vpnctl-doc-test id=log.status role=gateway
sudo vpnctl log status
```

```console vpnctl-doc-test id=log.disable role=gateway
sudo vpnctl log disable ingress
```

The absolute expiry survives restarts. Journald is the default destination;
`--file` chooses only `/var/log/vpnctl/<scope>.log` with bounded rotation.
Tokens, credentials, authorization headers, bodies, URLs, and webhook paths are
never eligible fields, even at trace level.

## Backup, restore, update, and removal

Create a portable encrypted gateway backup. A new passphrase is entered twice
through the controlling terminal; it never appears in argv.

```console vpnctl-doc-test id=backup role=gateway
sudo vpnctl backup /srv/backups/vpnctl.backup
```

The authenticated archive includes gateway state/trust and required client
material, but excludes node private keys and application data. Existing output
is never overwritten.

Restore is non-merging and always requires an explicit public IPv4. Use
`--replace` only after reviewing replacement of an initialized gateway:

```console vpnctl-doc-test id=restore role=uninitialized
sudo vpnctl restore vpnctl.backup --public-ip 203.0.113.10
```

A changed public IP makes node/profile/webhook/certificate actions explicit;
vpnctl does not claim seamless continuity. Downtime is acceptable.

Updates are local, explicit, whole-bundle operations. Update the gateway first,
then SSH to each private node and run the same local command there. vpnctl never
updates another host or checks in the background.

```console vpnctl-doc-test id=update role=gateway
sudo vpnctl update 2.1.0
```

The plan lists affected components and interruption. Unchanged healthy data
plane units are not restarted. A compatible retained snapshot can be restored
locally without a release-network request:

```console vpnctl-doc-test id=update.rollback role=gateway
sudo vpnctl update rollback
```

`uninstall` removes only validated vpnctl runtime and restores owned DNS/network
state while preserving recoverable state, secrets, presets, exports, backups,
and managed-swap ownership metadata:

```console vpnctl-doc-test id=uninstall role=node
sudo vpnctl uninstall
```

An online node revokes itself on the gateway first. `--local-only` is the
explicit offline exception and returns the mandatory gateway-side revoke
action. A gateway with active resources additionally requires `--force`.

`purge` is different: it irreversibly removes runtime, state, secrets,
certificates, exports, and managed swap. It requires the exact role-specific
typed phrase; `--yes` cannot bypass it. Portable backups remain unless the
gateway's separately confirmed `--include-backups` is used.

```console vpnctl-doc-test id=purge role=gateway
sudo vpnctl purge --force
```

## One-time v1 migration

Migration is a separate maintenance executable, not a permanent vpnctl
command. Copy the signed v2 bundle and `vpnctl-v1-migrate` to the existing v1
gateway, run the read-only plan, accept the maintenance window, and retain the
rollback package until migrated clients have been checked. The exact resumable
dry-run/apply/confirm/accept/rollback procedure is in
[V1_MIGRATION.md](V1_MIGRATION.md). Downtime is explicitly allowed; a failed or
unaccepted migration can restore the captured v1 binary, workspace,
WireGuard/UFW/network files, and unit state.

## Troubleshooting

| Symptom | Interpretation and next action |
| --- | --- |
| Init reports `confirm` | Keep the old SSH session open, connect again through the real listener, and confirm from that new session before the 120-second watchdog expires. |
| `status` exits `3` | vpnctl-owned drift exists. Inspect `plan`, then preview `repair --dry-run`; repair never touches foreign resources. |
| `status` or `doctor` exits `4` | A mandatory dependency is degraded. Run the narrowest doctor scope and inspect stable check codes before changing state. |
| A selected domain goes direct | Classification probably never observed the name because the application used DoH/DoT or a hardcoded IP. Add reviewed IP/CIDR selectors where appropriate; do not assume universal domain interception. |
| Selected traffic cannot connect | This is expected fail-closed behavior while its manually active gateway path is unavailable. vpnctl does not switch transport or reinterpret it as direct. |
| Restricted UDP is slow after loss | TCP head-of-line blocking is expected. Test and manually switch to standard if the workload needs predictable UDP latency. |
| Public request is `404` | The path is unknown, disabled, or reserved. Inspect the expose identity and application-owned webhook registration. |
| Public request is `413` | The body exceeds the expose or gateway hard limit; review the bounded expose configuration. |
| Public request is `503` | The tunnel/mapping/local application is unavailable or capacity admission rejected the request. Check `doctor tunnel`, `doctor ingress`, then the application itself. |
| Public request is `504` | The single upstream attempt exceeded its configured timeout. vpnctl does not replay the request. |
| Certificate is expiring | Rotate it manually, retrieve the new public certificate, and re-register every affected external webhook. Control/node trust is independent. |
| Gateway controller is down | Existing compatible data planes continue. Management returns unavailable and must not tear them down or silently mutate state. |

Preview owned-drift repair before consenting:

```console vpnctl-doc-test id=repair role=gateway
sudo vpnctl repair --dry-run
```

## Explicit v2.0 limits

v2.0 does not provide domain/ACME ingress, generic TCP/UDP ingress, HTTP/3,
WebSocket/SSE/gRPC guarantees, multiple gateways, simultaneous active node
transports, automatic fallback, full IPv6 transport, URL/subscription/QR
profile delivery, remote logging, telemetry, background update checks, or
provider webhook management. None of these are implied by the implementation-
neutral expose/transport boundaries. They require a later explicit contract.
