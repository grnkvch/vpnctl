# 0012: Use Full Tunnel Client Routing By Default For MVP

## Context

The MVP should generate simple WireGuard client configs that route client
traffic through the VPN. The operator provided this target client config shape:

```text
[Interface]
PrivateKey = XXXXX
Address = 10.10.10.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = YYYYYYY
Endpoint = 198.211.99.116:51820

AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

The main safety requirement is that configuring the remote VPN server must not
break the operator's active SSH session to that server.

## Decision

Use full tunnel routing for generated WireGuard client configs by default in
the MVP:

```text
AllowedIPs = 0.0.0.0/0
```

Use:

```text
PersistentKeepalive = 25
```

by default for client configs.

DNS remains governed by ADR 0011:

- omit `DNS` when no custom DNS is configured;
- include `DNS = ...` when the server state has custom DNS servers.

Server apply safety remains separate from client routing defaults. MVP server
apply must avoid changing server routing or firewall behavior in a way that can
drop the active SSH session.

## Alternatives Considered

- Split tunnel by default with only the WireGuard subnet in `AllowedIPs`.
- Platform-specific defaults.
- Requiring route mode for every client.

## Tradeoffs

Full tunnel client configs are simple and match the common personal VPN use
case: route all client traffic through the VPS.

The cost is that full tunnel configs can disrupt connectivity when installed on
a remote Linux client or VM over SSH. The MVP accepts this for client configs,
but server-side apply remains SSH-safe by default.

## Consequences

- The WireGuard client renderer should default to `AllowedIPs = 0.0.0.0/0`.
- The WireGuard client renderer should default to `PersistentKeepalive = 25`.
- Route mode can become configurable later if split tunnel client configs are
  needed.
- Linux VM split routing remains a future enhancement unless explicitly
  promoted into MVP.
