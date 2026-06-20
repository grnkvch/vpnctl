# 0017: Use Explicit Default DNS For Clash Mi Profiles

## Context

WireGuard client configs and Clash Mi profiles have different DNS needs.
WireGuard configs can safely omit DNS by default and let the client use system
DNS. Clash Mi domain routing benefits from explicit DNS behavior because rules
depend on domain-aware routing and diagnostics should be predictable.

The operator wants the MVP to use a practical default for Clash Mi while warning
when that default is injected automatically.

## Decision

Use this DNS behavior:

- WireGuard client configs follow ADR 0011: omit `DNS` by default.
- If `vpnctl server init --dns <servers>` is configured, use those DNS servers
  in both WireGuard client configs and Clash Mi profiles.
- If no custom DNS is configured, generated Clash Mi profiles include:

```yaml
dns:
  enable: true
  nameserver:
    - 1.1.1.1
    - 8.8.8.8
```

- When `vpnctl client export <client> --type clash` injects the default Clash Mi
  DNS, it must print a non-secret warning.

Suggested warning:

```text
warning: no custom DNS configured; Clash Mi profile uses default DNS servers 1.1.1.1, 8.8.8.8
```

## Alternatives Considered

- Do not include DNS in Clash Mi profiles by default.
- Use only `vpnctl server init --dns` and fail if it is absent.
- Add a separate `--clash-dns` setting immediately.
- Always use the same DNS behavior for WireGuard and Clash Mi profiles.

## Tradeoffs

This gives Clash Mi predictable default behavior while keeping the behavior
visible to the operator. It avoids adding a separate Clash DNS setting before it
is clearly needed.

The cost is that the MVP uses opinionated public DNS servers for Clash Mi when
the operator does not configure DNS explicitly.

## Consequences

- Clash Mi rendering must choose DNS from state when custom DNS is configured.
- Clash Mi rendering must fall back to `1.1.1.1` and `8.8.8.8` when no custom
  DNS is configured.
- Clash Mi export must warn when fallback DNS is used.
- Tests should cover custom DNS, fallback DNS, and warning behavior.
