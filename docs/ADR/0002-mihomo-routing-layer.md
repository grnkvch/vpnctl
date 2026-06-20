# 0002: Use Mihomo / Clash Mi For Client Routing

## Context

Some supported clients need routing behavior beyond a simple full-tunnel or
split-tunnel WireGuard profile. The project identifies Mihomo / Clash Mi as the
routing layer.

## Decision

Generate Mihomo / Clash-compatible configuration as the first routing-layer
output format.

## Alternatives Considered

- WireGuard-only routing through AllowedIPs
- OS-specific routing scripts
- A custom local proxy or routing daemon

## Tradeoffs

Mihomo / Clash configs provide a familiar ruleset model and are portable across
several client environments.

The cost is an additional configuration format and more testing around rules,
proxy groups, and DNS behavior.

## Consequences

- ClashConfig and Ruleset are first-class domain concepts.
- WireGuard config generation remains separate from routing policy generation.
- The first implementation should keep rulesets simple and deterministic.
- OS-specific routing automation remains out of scope for the initial version.
