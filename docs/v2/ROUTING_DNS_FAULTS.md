# Routing and DNS fault matrix

Task 10.11 keeps one repeatable matrix for the production fail-closed
boundaries and the disposable Ubuntu 24.04 namespace lab. It does not replace
the deployed-service release tests in section 16.

| Fault | Automated layer | Required observation | Recovery |
|---|---|---|---|
| routing engine crash | production manager tests and routing lab | readiness changes to `not-ready`; every new application TCP/UDP/IPv4/IPv6 flow is blocked except exact gateway recovery; an established direct flow is retained only through conntrack | systemd restarts the engine, TUN readiness is proven, the selected route is installed, then readiness opens |
| routing engine restart | production manager tests and routing lab storms | selected IPv4 TCP/UDP never receives the direct backend response and selected IPv6 never reaches the direct backend during the whole transition | selected and unrelated direct probes succeed on their original paths after readiness returns |
| gateway or active-path loss | routing lab | new selected TCP/UDP blocks, unrelated direct TCP/UDP continues, the engine/config/active transport identity does not change, and standby is never activated | restoring the same path recovers selected traffic without an engine restart |
| local resolver loss | DNS lab | managed stub and captured classic UDP/TCP port-53 queries cannot bypass the absent classifier; neither direct nor gateway upstream sees the unique blocked names | restarting the same resolver restores selected gateway DNS and unrelated direct DNS independently |
| component replacement | routing lab | an atomic same-version Mihomo binary replacement plus restart runs concurrent selected TCP/UDP/IPv6 storms with zero forbidden direct responses | the replacement process becomes ready and both selected and direct post-update probes recover |
| manual transport switch | production transport workflow and routing-bundle tests | every injected prepare, validate, probe, activate, health, drain, or state-commit failure restores exactly the previously selected transport; both standard and restricted bundle candidates retain the same matcher, permanent selected-route unreachable fallback, IPv6 drop, DNS capture, and no `DIRECT` gateway member | a successful switch commits one target only after target probes and bounded old-path drain; no automatic fallback exists |
| uninstall/restoration | production managers and both labs | guard removal happens only in the controlled restore phase; DNS snapshot restores exact link DNS/domains/default-route and the original resolver setup; foreign nftables/rules and root networking remain byte-for-byte equivalent | formerly selected traffic follows ordinary host networking only after the guard is removed; all exact owner-scoped lab resources are absent |

The selected-flow invariant is protocol-independent: after classification,
selected TCP and UDP are either carried by the manually active gateway path or
blocked. When the classifier itself is unavailable, the stronger crash rule
blocks all new application egress; it does not reinterpret traffic as direct.
Independent DoH/DoT and unmatched hardcoded addresses remain subject to the
separate [classification boundary](CLASSIFICATION_BOUNDARY.md).

The VM checks are run sequentially because routing and DNS fixtures
intentionally claim overlapping node data-plane resources:

```bash
./scripts/v2routing-spike.sh prepare
./scripts/v2routing-spike.sh verify artifacts/v2lab/routing-spike/task-10.11-fault-matrix

./scripts/v2dns-spike.sh prepare
./scripts/v2dns-spike.sh verify artifacts/v2lab/dns-spike/task-10.11-fault-matrix
```

Both `verify` commands arm cleanup before applying host integration. They
accept only the pinned, exact-name 1-vCPU/512-MiB/10-GiB Lima fixtures and
owner-marked paths. Their final phase performs full uninstall, compares the
saved root network/resolver state, and rejects a leftover namespace, unit,
table, route, rule, drop-in, service user, or owned path.
