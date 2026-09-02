# 0020: Fix the v2 Fail-Closed Routing and Split-DNS Internals

Status: Accepted.

## Context

Selected node traffic must be gateway-or-block for both TCP and UDP, while unrelated traffic remains direct. A userspace routing process alone cannot enforce this during boot, crash, or reload. DNS classification must use the same boundary without allowing a selected lookup to fall back to a direct resolver.

## Decision

- Use an independent nftables/systemd guard before Mihomo startup. Reserve the high-byte mark mask `0xff000000` with direct `0x01000000`, selected `0x02000000`, recovery `0x03000000`, and ingress-response `0x04000000`, preserving the lower 24 bits in conntrack state.
- Use nftables output/prerouting priority `-150`; RPDB priorities `10000/10010/10020`; selected/gateway tables `20001/20002`; an unreachable selected default at metric `42760`; and a ready TUN default at metric `10`. Every value is conflict-checked internal state, not public CLI API.
- Activate routes before switching classification to ready, and switch classification back before removing routes. IPv6 selected traffic is carried equivalently or blocked; it never becomes a direct bypass.
- Select Mihomo `policy-redir-host` for normal policy DNS and `direct-redir-host` only for explicit v1-compatible direct mode. Keep systemd-resolved's stub, route global `~.` to `127.0.0.1:1053`, disable its second cache, and capture/restore existing link DNS state exactly.
- Redirect ordinary local TCP/UDP port 53 through the managed resolver. Only its dedicated UID and systemd loopback stubs bypass capture.
- Accept pinned Mihomo stale-while-revalidate only for an answer previously validated through gateway DNS: it is returned at TTL 1 while refresh remains gateway-only. A new selected name fails during gateway-DNS outage; a new direct name continues. The cache remains capacity-bounded to 4096 entries.
- Reject the fake-IP whitelist mode because it can synthesize a fresh selected answer without an eager gateway DNS lookup. Do not hard-code a future fake-IP range; the usual range collided with the lab underlay and would require conflict detection.

## Alternatives considered

- Mihomo TUN auto-route alone was rejected because a process failure can expose a direct route.
- A selected-to-direct DNS fallback was rejected because it crosses the same fail-closed boundary as traffic routing.
- A separate gateway DNS daemon per node was rejected because logical separation is sufficient for the expected node count and avoids extra processes.

## Consequences

The exact mark, route, DNS, and cache parameters are pinned in [COMPONENT_LIMITS.v1.json](../v2/COMPONENT_LIMITS.v1.json). Linux development evidence is sufficient to implement them; actual Clash Mi import/DNS behavior remains a task 16.11 release gate.
