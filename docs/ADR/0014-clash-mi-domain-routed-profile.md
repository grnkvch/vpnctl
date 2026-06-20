# 0014: Generate Domain-Routed Clash Mi Profile For MVP

## Context

The MVP must generate a Clash Mi-compatible profile for iPhone. The operator
does not want all traffic to go through the VPN. Only selected domains should
use the WireGuard proxy, but matching traffic for those domains should use the
VPN across supported protocols, including TCP and UDP.

Observed Clash Mi logs showed TCP traffic for `ios.chat.openai.com` matching
the domain rule and using VPN, while UDP traffic for the same domain fell
through to `MATCH,DIRECT`. That is not acceptable for selected VPN domains.

Mihomo routing rules are evaluated from top to bottom. `MATCH` catches all
remaining traffic. Mihomo documentation also notes that if a UDP request matches
a proxy node without UDP support, matching can continue to lower rules.

## Decision

Generate a domain-routed Clash/Mihomo profile for Clash Mi by default.

The MVP profile should:

- use a WireGuard proxy named `DO-WG` by default;
- set `udp: true` on the WireGuard proxy;
- set WireGuard proxy `allowed-ips` to `['0.0.0.0/0']` so the proxy can carry
  any destination IP selected by rules;
- use a proxy group named `VPN`;
- route configured domain rules to `VPN`;
- end rules with `MATCH,DIRECT`, so non-matching traffic stays direct.

Minimal target shape:

```yaml
mode: rule

dns:
  enable: true
  nameserver:
    - 1.1.1.1
    - 8.8.8.8

proxies:
  - name: DO-WG
    type: wireguard
    server: 198.211.99.116
    port: 51820
    ip: 10.66.0.2
    private-key: "XXXXX"
    public-key: "YYYYYY"
    allowed-ips:
      - 0.0.0.0/0
    udp: true
    mtu: 1420

proxy-groups:
  - name: VPN
    type: select
    proxies:
      - DO-WG

rules:
  - DOMAIN-SUFFIX,chatgpt.com,VPN
  - DOMAIN-SUFFIX,openai.com,VPN
  - DOMAIN-SUFFIX,api.openai.com,VPN
  - DOMAIN-SUFFIX,claude.ai,VPN
  - DOMAIN-SUFFIX,anthropic.com,VPN
  - MATCH,DIRECT
```

## Alternatives Considered

- Full tunnel profile with final `MATCH,VPN`.
- TCP-only domain routing.
- Requiring users to hand-write Clash rules for MVP.

## Tradeoffs

Domain-routed Clash profiles keep unrelated traffic direct while routing the
selected domains through VPN. This matches the desired iPhone Clash Mi workflow
better than full tunnel.

The cost is that domain routing can only match traffic that Mihomo can associate
with a domain. IP-only connections or auxiliary app domains require additional
rules if they should use VPN.

## Consequences

- The MVP Clash renderer should generate domain rules followed by `MATCH,DIRECT`.
- The MVP Clash renderer must set `udp: true` on the WireGuard proxy.
- The WireGuard proxy should use `allowed-ips: ['0.0.0.0/0']` so selected
  domain traffic can reach any destination through the tunnel.
- Golden tests should verify domain rules, final `MATCH,DIRECT`, `udp: true`,
  and WireGuard proxy `allowed-ips`.
- Full tunnel Clash routing remains a future route mode.
