# Node routing engine

Tasks 10.2 through 10.4 turn the shared matcher IR into the production node
configuration for the pinned Mihomo `v1.19.30` process, its independent kernel
fail-closed guard, and exactly one manually active transport binding.

## Host-wide boundary

The node runs one system `vpnctl-routing.service` process, one independent
`vpnctl-routing-guard.service`, and one TUN named `vpnctl0`. The render requests
have no process, UID, user, systemd-unit, container, cgroup, package,
interface-inclusion, or network-namespace scope.
The generated configuration likewise contains none of those matchers or
filters. Mihomo uses the system TUN stack with `auto-route: false`; the guard
owns the kernel policy route that sends classified host traffic into this TUN
and keeps the pre-engine boundary closed until readiness is accepted.

The process opens no mixed, SOCKS, redir, TProxy, LAN, or controller listener.
Its only listener is the managed resolver on `127.0.0.1:1053`, for both UDP and
TCP. Logging is `silent`, geodata update is disabled, and the root-only config
and state directory are rejected if they are symlinks or accessible to group
or other users.

## DNS modes

`policy` is the default and renders the accepted `policy-redir-host` behavior:
selected domain queries use exactly `udp://<gateway-dns>:53#VPNCTL-GATEWAY`,
while unmatched queries and explicit direct exceptions use only the ordered
node-direct IPv4 resolvers. There is no resolver list containing both paths.

`direct` is the explicit compatibility mode. It omits `nameserver-policy` and
uses the node-direct resolver list for every lookup, without changing traffic
routing rules. Fake IP remains disabled in both modes. An empty policy renders
an explicit empty policy map in policy mode and a single final `MATCH,DIRECT`.

Fresh node initialization reads the underlying IPv4 nameservers from
systemd-resolved's non-stub resolver file, excludes loopback and IPv6 entries,
and records that ordered list as node-owned `direct` DNS state. Gateway state
owns a separate `gateway` list initialized to `1.1.1.1` and `8.8.8.8`; the two
scopes cannot coexist in one host state or serve as fallback for one another.

`vpnctl dns show`, `vpnctl dns set <IPv4>...`, and `vpnctl dns reset` infer that
scope from the initialized host role. Gateway reset restores `1.1.1.1` and
`8.8.8.8`; node reset rereads the current systemd-resolved non-stub resolver
source, falls back to `/etc/resolv.conf`, and refuses the operation when no
non-loopback IPv4 resolver can be found. A node update rewrites only the direct
DNS references in its generated Mihomo file and preserves its current
`policy`/`direct` renderer mode. A gateway update rewrites and restarts only the
shared forwarder, so it does not change node configs or previously exported
client profiles.

Runtime activation and authoritative-state commit form one compensating
transaction. A restart failure restores the exact previous root-only config;
an authoritative-state write failure after activation also restores and
restarts the previous runtime. Existing config drift is a conflict instead of
being overwritten. `--dry-run` performs discovery and validation but writes no
state, config, or service state.

Every node config contains a non-selectable `VPNCTL-DIRECT-DNS` provider
outbound. Direct upstream queries use this outbound and its fixed direct socket
mark; gateway upstream queries use the active standard/restricted outbound and
its recovery mark. Neither outbound is a fallback member of the other path.
The marks let the provider's own upstream sockets bypass classic port-53
capture without introducing a process, UID, or cgroup routing scope.

## systemd-resolved and classic port 53

The node keeps `/etc/resolv.conf` on
`/run/systemd/resolve/stub-resolv.conf`. While the routing guard is active, an
owned runtime drop-in at
`/run/systemd/resolved.conf.d/50-vpnctl-node.conf` selects
`127.0.0.1:1053`, global route domain `~.`, no fallback resolver, and
`Cache=no`. The ordinary underlay's route domains are temporarily replaced by
the inert `~vpnctl-underlay.invalid`, so its DNS server cannot race the managed
global route.

Before the first nftables, resolved, or link mutation, vpnctl durably records
the exact underlay DNS list, domain list, default-route bit, and resolv.conf
target in root-only `/var/lib/vpnctl/routing/resolved-original.json`. A failed
activation and the guard stop/uninstall path remove only the owned runtime
drop-in and `table inet vpnctl_dns`, restart resolved, restore those exact link
values, and remove the snapshot last. Missing snapshots, changed symlink
targets, foreign tables, and drifted owned files cause refusal instead of
destructive replacement.

`table inet vpnctl_dns` has an output NAT hook at priority `-151`, immediately
before the routing guard at `-150`. It preserves traffic to the loopback resolved stub,
bypasses only the direct/recovery provider socket marks, and redirects all
other local UDP and TCP destination-port-53 traffic to `1053`. This covers
applications that open classic DNS sockets directly. DoH, DoT, and embedded
IP literals remain outside this capture boundary.

## Kernel fail-closed guard

The node guard owns only `table inet vpnctl`, route tables `20001`/`20002`,
RPDB priorities `10000`/`10010`/`10020`, and the explicitly snapshotted
`src_valid_mark`/`rp_filter` sysctls. It rejects a pre-existing table without
the `vpnctl:v2:node-routing-guard` ownership marker and never flushes the global
ruleset or another table.

Only the high byte of packet and conntrack marks belongs to vpnctl. The fixed
mask is `0xff000000`; `0x01000000` means retained direct,
`0x02000000` selected, `0x03000000` recovery/active outbound, and
`0x04000000` ingress response. Every assignment preserves `0x00ffffff`, and
only those four exact high-byte values are restored from conntrack. Both the
prerouting and route-output hooks use priority `-150`, after conntrack
association.

The recovery allowlist consists only of the configured gateway IPv4 plus exact
TCP/UDP ports. There is no CIDR, hostname, arbitrary destination, or raw nft
input. Optional exact ingress interface/protocol/port tuples attach the
ingress-response mark, so response routing is symmetric. Static IP/CIDR
decisions come from the same matcher IR as Mihomo; selected resolver answers
have dedicated IPv4/IPv6 sets for the managed DNS integration.

The selected table always contains `unreachable default metric 42760`. For an
active binding, the gateway table always contains one exact public-gateway
`/32` recovery route over the ordinary underlay. Standard adds a default via
`vpnctl-wg`; restricted adds an unreachable default because its only valid
recovery-marked outer destination is that exact public gateway. The three
high-byte marks select these tables at fixed RPDB priorities. This means a
selected route has a kernel block if the TUN or active provider disappears,
and a marked provider packet cannot silently use an arbitrary direct target.

## Boot, readiness, and crash order

`vpnctl-routing-guard.service` is a controller-independent oneshot unit that
remains active after loading the not-ready policy. It is ordered before and
required by `vpnctl-routing.service`. The routing unit runs these hidden,
systemd-only phases:

1. `node-routing-not-ready` closes the nftables readiness chain before process
   start.
2. Mihomo starts and opens `vpnctl0` plus both loopback DNS listeners.
3. `node-routing-wait-ready` observes all three resources, installs
   `default dev vpnctl0 metric 10 table 20001`, and only then atomically changes
   the readiness jump to `ready`.
4. `ExecStopPost` changes the jump back to `not_ready` before deleting the TUN
   route, including after an unexpected process exit.

While not ready, loopback and exact recovery traffic remain possible and only
established/related flows with a retained direct decision may continue. Every
other new application packet is dropped. In ready state, selected IPv4 is
marked for the TUN, selected IPv6 is marked and dropped because v2 has no full
IPv6 data plane, and unmatched traffic receives a retained direct mark.

## IPv6 boundary

Version 2.0 does not carry IPv6 through either gateway transport. A selected
IPv6 literal or CIDR is therefore always marked selected and dropped by the
independent kernel guard. An IPv6 address placed in
`selected_resolved_v6` after a selected AAAA classification receives the same
verdict. Retained selected conntrack traffic is checked by address family and
dropped before the general retained-selected rule, so it cannot bypass the
IPv6 boundary.

These paths share the named `selected_ipv6_drop` packet/byte counter. The
passive internal diagnostic reports mode `selected-block-only`,
`full_data_plane=false`, the counter values, the number of current resolved
selected entries, and unmatched behavior `preserve-system`. It reads only the
owned nftables objects; it does not generate traffic, resolve a name, update a
set, or repair policy.

Unmatched IPv6 is not globally disabled. vpnctl leaves it to the host's
existing IPv6 addresses, routes, and upstream availability, so
`preserve-system` is not a promise that the host has working IPv6. The managed
resolver integration supplies selected AAAA entries; DoH,
DoT, and hardcoded-address classification limits remain explicit task-10.10
diagnostics rather than a claim of universal interception.

Guard installation snapshots the prior vpnctl-owned network scope first. Any
failure while setting sysctls, routes, rules, or the atomic nftables batch
restores that snapshot. Readiness activation follows the inverse-safe order:
route before open; close before route removal.

## One active outbound

An unbound staging artifact contains no proxy and gives `VPNCTL-GATEWAY` only
Mihomo's built-in `REJECT-DROP`. A production bundle cannot be unbound. It
derives both the engine and guard from the node's one authoritative manual
active-transport record and credential generation:

- `standard` gives `VPNCTL-GATEWAY` exactly one direct proxy, with UDP enabled,
  interface fixed to `vpnctl-wg`, and recovery mark `0x03000000`;
- `restricted` gives it exactly one Shadowsocks-2022 proxy using public
  `8443/TCP`, ShadowTLS v3 strict mode, UoT v2, and the same recovery mark.

The standby provider and `DIRECT` are never members of the active group; there
is no fallback, health-test selector, or automatic choice. The exact gateway
overlay `/32` is the first system rule, so selected DNS, control RPCs, and the
reverse-tunnel connection all use that same group. User-selected rules follow
in canonical order. Unmatched host packets never enter the selected routing
table/TUN, and the defensive terminal rule remains `MATCH,DIRECT`.

If the active provider or gateway fails while the routing engine remains
ready, that group remains selected and new selected TCP and UDP flows fail in
place. The failure does not close the global readiness gate, change the active
transport, try standby, or reinterpret selected traffic as direct. Unmatched
new flows retain their independent `DIRECT` decision and ordinary uplink.
Once the same active path recovers, new selected flows resume without an
automatic switch or routing-engine restart. An engine failure is deliberately
different: the independent not-ready guard blocks every new application flow
until the engine is ready again.

The bundle composer overwrites the guard matcher, active kind, and public and
overlay gateway addresses from the same validated routing input. This removes
an API path for binding the userspace engine and kernel guard to different
transports. Restricted credentials are loaded only through the two exact
authoritative secret references and are emitted solely into the root-only
routing config.

## Routing-engine staging and readiness

The service validates the vpnctl schema, the exact bundled Mihomo version, and
Mihomo's native parser before starting. Readiness is bound to the candidate
config SHA-256 and passively requires all of:

- `vpnctl-routing.service` active;
- `vpnctl0` present and up;
- exactly loopback `127.0.0.1:1053` owned by Mihomo over UDP;
- exactly loopback `127.0.0.1:1053` owned by Mihomo over TCP.

The candidate readiness gate performs no DNS request, application probe,
service action, route change, or automatic transport choice. A missing member
returns not-ready and cannot yield an activatable candidate. The systemd
post-start phase uses the same TUN and listener shape before opening the kernel
guard. When standard is scheduled at boot, the guard is ordered after its
WireGuard unit so the active gateway-table default can be installed safely.

Task-10.4 acceptance re-ran the disposable nftables capture gates. Standard
selected TCP and UDP used only the gateway path while unrelated IPv4/IPv6
remained direct. Restricted selected TCP and UDP produced `43` protected
`8443/TCP` packets and zero native/direct UDP or direct TCP packets. The
reverse tunnel recorded `53` standard `17000/TCP` packets, then `21`
ShadowTLS packets and zero steady-state direct `17000/TCP` packets after the
manual restricted switch, with logical identity preserved. These are Linux
gateway/node development gates; actual supported Clash Mi remains the task
16.11 deployed-service gate.

Task-10.5 fault acceptance keeps that routing process and config generation
unchanged while first stopping the isolated gateway backend and then dropping
only the simulated gateway interface. In both cases fresh selected TCP and UDP
are blocked, the duplicate selected destination on the direct link is never
reached, and fresh unrelated TCP and UDP continue over direct. Restoring the
same failed component recovers both selected protocols without restarting the
routing engine or selecting another transport.
