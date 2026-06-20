# Architecture

Core concepts:

- Server
- Client
- KeyPair
- WireGuardConfig
- ClashConfig
- ConfigDelivery
- Ruleset

Principles:

- Single source of truth
- Git-friendly state
- Idempotent operations
- CLI first
- Secure by default

Linux VM requirement:

VPN connectivity must not break SSH access.
Split routing strategy required.
