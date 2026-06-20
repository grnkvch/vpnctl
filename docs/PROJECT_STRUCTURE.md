# Proposed Project Structure

This structure assumes a small Go CLI application with local state and generated
artifacts. Go is selected in ADR 0006.

```text
vpnctl/
  docs/
    ADR/
    ARCHITECTURE.md
    ARCHITECTURE_REVIEW.md
    DOMAIN_MODEL.md
    IMPLEMENTATION_PLAN.md
    PROJECT.md
    PROJECT_STRUCTURE.md
    REQUIREMENTS.md
  cmd/
    vpnctl/
  internal/
    cli/
    domain/
    state/
    wireguard/
    mihomo/
    delivery/
    ssh/
  tests/
    unit/
    integration/
  examples/
    state/
```

## Module Boundaries

cli:

- parse commands
- validate user input
- call application services
- format output without exposing secrets

domain:

- server, client, key, config, and ruleset models
- lifecycle rules
- validation

state:

- load and save local state
- maintain schema versions
- handle file permissions for secrets

wireguard:

- generate server configs
- generate client configs
- validate key and address data

mihomo:

- generate Clash/Mihomo configs
- render rules and proxy groups

delivery:

- write local files
- render QR codes
- manage short-lived delivery artifacts

ssh:

- run remote commands
- apply idempotent server changes
- collect non-secret diagnostics

## Suggested CLI Shape

```text
vpnctl init
vpnctl setup
vpnctl server init
vpnctl server show
vpnctl ruleset add
vpnctl client create
vpnctl client list
vpnctl client show
vpnctl client revoke
vpnctl client rotate-keys
vpnctl client delete
vpnctl client export
vpnctl apply
```

## State Layout

```text
.vpnctl/
  state.json
  rulesets/
    default.json
  secrets/
    server.key
    clients/
      <client-id>.key
      <client-id>.psk
  generated/
    wireguard/
    mihomo/
    delivery/
```

The `.vpnctl/secrets` directory should be ignored by Git by default unless the
operator explicitly chooses encrypted secret storage later.

Applied server configuration is separate from vpnctl state. For the default
WireGuard interface, `vpnctl apply` writes the rendered server config to
`/etc/wireguard/wg0.conf`.

By default, `vpnctl server init` uses WireGuard subnet `10.66.0.0/24`; custom
subnets can be supplied with `--subnet`.
