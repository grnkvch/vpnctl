# 0010: Use Configurable Default WireGuard Subnet

## Context

vpnctl needs a default WireGuard subnet for a smooth first-run experience. The
tool should also support advanced users who need to avoid conflicts with
existing private networks.

## Decision

Use `10.66.0.0/24` as the default WireGuard subnet for the initial MVP.

By default:

- the server address is `10.66.0.1`;
- client allocation starts at `10.66.0.2`;
- the default interface remains `wg0`.

Subnet selection remains configurable:

```text
vpnctl server init
```

uses `10.66.0.0/24`.

```text
vpnctl server init --subnet 10.10.10.0/24
```

uses `10.10.10.0/24`.

## Alternatives Considered

- `10.8.0.0/24`
- `172.27.0.0/24`
- requiring the user to always provide a subnet

## Tradeoffs

`10.66.0.0/24` gives a simple default and is less likely to collide with common
home LAN ranges than `192.168.0.0/16`. Allowing `--subnet` keeps the first-run
experience simple while preserving control for users with existing network
constraints.

The cost is that the implementation must validate custom subnets and prevent
invalid or too-small networks.

## Consequences

- `vpnctl server init` should default to `10.66.0.0/24`.
- `vpnctl server init --subnet <cidr>` should store the custom subnet in state.
- IP allocation must derive server and client addresses from the configured
  subnet.
- The tool should reject invalid CIDR input and networks too small for the
  expected server and client addresses.
