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
- DNS
- server public key
- endpoint
- allowed IPs
- persistent keepalive

### ClashConfig

Generated Mihomo / Clash-compatible routing configuration.

Fields:

- proxies
- proxy_groups
- rules
- rulesets
- dns
- mode

### Ruleset

Represents reusable routing rules for Clash/Mihomo.

Fields:

- id
- name
- source
- format
- rules

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
