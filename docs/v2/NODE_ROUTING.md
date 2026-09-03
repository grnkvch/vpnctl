# Node routing engine

Task 10.2 turns the shared matcher IR into the production base configuration
for the node's pinned Mihomo `v1.19.30` process. It does not yet install kernel
marks, policy routes, the independent leak guard, or a concrete active
transport binding; those boundaries belong to tasks 10.3 and 10.4.

## Host-wide boundary

The node runs one system `vpnctl-routing.service` process and one TUN named
`vpnctl0`. The public render request has no process, UID, user, systemd-unit,
container, cgroup, package, interface-inclusion, or network-namespace scope.
The generated configuration likewise contains none of those matchers or
filters. Mihomo uses the system TUN stack with `auto-route: false`; task 10.3
owns the kernel policy route that sends all classified host traffic into this
TUN and keeps the pre-engine guard closed until readiness is accepted.

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

## Fail-closed staging and readiness

Until task 10.4 supplies the manually active standard or restricted outbound,
the only member of `VPNCTL-GATEWAY` is Mihomo's built-in `REJECT-DROP`. Selected
rules can therefore block but cannot accidentally become direct while a
generation is staged. Exact-domain and more-specific suffix/CIDR decisions
remain ahead of their parent rules, and unmatched traffic ends in direct.

The service validates the vpnctl schema, the exact bundled Mihomo version, and
Mihomo's native parser before starting. Readiness is bound to the candidate
config SHA-256 and passively requires all of:

- `vpnctl-routing.service` active;
- `vpnctl0` present and up;
- exactly loopback `127.0.0.1:1053` owned by Mihomo over UDP;
- exactly loopback `127.0.0.1:1053` owned by Mihomo over TCP.

Readiness performs no DNS request, application probe, service action, route
change, or automatic transport choice. A missing member returns not-ready and
cannot yield an activatable candidate. Task 10.3 uses this boundary when it
orders TUN routes and the independent nftables guard; task 10.4 then proves the
selected TCP/UDP path through each manually active transport.
