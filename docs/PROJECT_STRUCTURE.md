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
vpnctl server add
vpnctl server render
vpnctl server apply
vpnctl client create
vpnctl client revoke
vpnctl client rotate-keys
vpnctl client regenerate-config
vpnctl client delete
vpnctl delivery export
```

## State Layout

```text
.vpnctl/
  state.yaml
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
