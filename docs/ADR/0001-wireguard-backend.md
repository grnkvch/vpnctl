# 0001: Use WireGuard As VPN Backend

## Context

vpnctl manages a personal VPN infrastructure for one operator and a small number
of clients. The project requires a secure default, simple operations, and broad
client support across iPhone, macOS, Arch Linux, Ubuntu, and Linux VMs.

## Decision

Use WireGuard as the only VPN backend for the initial implementation.

## Alternatives Considered

- OpenVPN
- IPsec/IKEv2
- Supporting multiple VPN backends from the start

## Tradeoffs

WireGuard has a small configuration surface, strong client availability, and
fits deterministic config generation well.

The main cost is that routing policy, DNS behavior, and split tunneling must be
handled outside WireGuard configuration when clients need more advanced routing.

## Consequences

- The domain model can treat a client as a WireGuard peer.
- Server application can focus on one interface and one peer model.
- Key generation and rotation can be designed around WireGuard key material.
- Non-WireGuard VPN backends are out of scope until a future ADR changes this.
