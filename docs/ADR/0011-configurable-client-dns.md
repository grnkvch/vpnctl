# 0011: Use System DNS By Default With Configurable Client DNS

## Context

WireGuard client configs can include a `DNS` field. Setting DNS by default can
make behavior consistent, but it also means choosing a third-party DNS provider
for the user.

## Decision

Do not set explicit DNS servers in generated client configs by default.

By default:

- `vpnctl server init` stores no custom DNS servers;
- generated WireGuard client configs omit the `DNS` field;
- clients continue using their system DNS behavior.

Custom DNS remains configurable:

```text
vpnctl server init --dns 1.1.1.1,1.0.0.1
```

stores custom DNS servers in state and generated client configs include:

```text
DNS = 1.1.1.1, 1.0.0.1
```

## Alternatives Considered

- Always use Cloudflare DNS by default.
- Always use Google DNS by default.
- Always use AdGuard DNS by default.
- Require DNS to be provided during `vpnctl server init`.

## Tradeoffs

Using system DNS by default avoids making a privacy or provider choice for the
operator. A `--dns` flag keeps the first-run workflow simple while allowing
explicit DNS configuration when needed.

The cost is that default DNS behavior can vary between client platforms and
network environments.

## Consequences

- The state model should allow an empty DNS server list.
- The WireGuard client renderer should omit `DNS` when no custom DNS servers
  are configured.
- `vpnctl server init --dns <servers>` should validate and store custom DNS
  server addresses.
- Tests should cover both omitted DNS and configured DNS output.
