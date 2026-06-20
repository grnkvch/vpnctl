# Domain Model

## Entities

### Server

Represents one SSH-accessible VPN host.

Fields:

- id
- name
- public_endpoint
- ssh_host
- ssh_user
- wireguard_interface
- wireguard_port
- wireguard_subnet
- wireguard_server_ip
- dns_servers
- allowed_client_routes

### Client

Represents one VPN consumer device or VM.

Fields:

- id
- name
- platform
- status
- assigned_ip
- public_key
- private_key_ref
- preshared_key_ref
- created_at
- revoked_at
- tags

Statuses:

- active
- revoked
- deleted

### KeyPair

Represents cryptographic material generated for WireGuard peers.

Fields:

- public_key
- private_key
- created_at
- rotated_at

Private keys must be stored with restricted permissions and must never be logged.

### WireGuardConfig

Generated configuration for the server or a client.

Server config includes:

- interface address
- listen port
- server private key reference
- peer public keys
- peer allowed IPs

Client config includes:

- client private key
- assigned address
- DNS when custom DNS servers are configured
- server public key
- endpoint
- allowed IPs, defaulting to `0.0.0.0/0` for MVP client configs
- persistent keepalive, defaulting to `25`

### ClashConfig

Generated Mihomo / Clash-compatible routing configuration. Basic iPhone Clash
Mi profile generation is part of the MVP.

Fields:

- proxies
- proxy_groups
- rules
- rulesets
- dns
- mode

MVP Clash Mi configs should route configured domains through the WireGuard proxy
and leave non-matching traffic direct with a final `MATCH,DIRECT`.

If custom DNS servers are configured, Clash Mi configs use them. Otherwise they
use fallback DNS `1.1.1.1` and `8.8.8.8` and export must warn the operator.

### Ruleset

Represents reusable routing rules for Clash/Mihomo.

Fields:

- id
- name
- type
- domains

MVP rulesets are editable JSON files under `.vpnctl/rulesets/`. The only
supported MVP type is `domain-suffix`; unsupported types must fail validation.

### ConfigDelivery

Represents a short-lived way to expose generated client config.

Supported candidates:

- local file
- QR code
- temporary link
- signed URL
- one-time link

The first implementation should support local files and QR codes. Link-based
delivery should require a separate ADR before implementation.

## Relationships

- One Server has many Clients.
- One Client has one active WireGuard KeyPair.
- One Client may have generated WireGuardConfig and ClashConfig artifacts.
- One ClashConfig may reference many Rulesets.
- One ConfigDelivery references one generated artifact.

## Lifecycle Rules

Create:

- allocate a unique client IP
- allocate from the configured WireGuard subnet
- generate key material
- update local state
- regenerate server and client configs

Revoke:

- mark the client as revoked
- remove the peer from generated server config
- preserve historical metadata

Rotate keys:

- generate replacement key material
- update peer public key
- regenerate configs

Regenerate config:

- read state
- rewrite deterministic generated artifacts
- do not mutate identity or key material

Delete:

- remove active client state only after explicit confirmation
- prefer revoke for normal deactivation

## Invariants

- Client IDs are stable.
- Client names are human-readable but not primary identifiers.
- Assigned client IPs must be unique per server.
- Generated files must be reproducible from state except for secret material.
- Private keys must not appear in logs.
- Applying the same desired state twice must be safe.
