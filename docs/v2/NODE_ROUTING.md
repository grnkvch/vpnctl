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
have dedicated IPv4/IPv6 sets for the managed DNS integration in task 10.7.

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
