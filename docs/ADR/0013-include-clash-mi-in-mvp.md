# 0013: Include iPhone Clash Mi Configuration In MVP

## Context

The MVP must support iPhone usage not only through a WireGuard client profile,
but also through the Clash Mi app. Mihomo / Clash-compatible configuration is
therefore part of the first usable product, not only a future routing feature.

## Decision

Include basic Mihomo / Clash-compatible configuration generation in the MVP,
with iPhone Clash Mi as the first target client workflow.

For the MVP:

- WireGuard config generation remains required.
- Clash/Mihomo config generation is also required.
- The first Clash/Mihomo output should be a simple deterministic client profile.
- Advanced ruleset management remains out of scope.

## Alternatives Considered

- Ship WireGuard-only MVP and add Clash Mi later.
- Treat Clash/Mihomo support as documentation-only for the first version.
- Build advanced ruleset management before basic client profile generation.

## Tradeoffs

Including Clash Mi in MVP makes the first version more useful for the target
iPhone workflow. It also validates the routing-layer architecture early.

The cost is a larger MVP surface: one more config format, more golden tests, and
more delivery behavior to verify.

## Consequences

- `ClashConfig` remains a first-class domain concept for MVP.
- The implementation plan must include basic Clash/Mihomo rendering before MVP
  completion.
- Config delivery must support exporting Clash/Mihomo profiles in addition to
  WireGuard configs.
- Advanced rules, remote ruleset providers, and platform-specific Clash profiles
  remain backlog items.
