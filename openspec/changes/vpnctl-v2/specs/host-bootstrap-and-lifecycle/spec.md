## Purpose

Defines how vpnctl safely initializes, owns, validates, and removes gateway and private-node hosts without locking the operator out or overwriting unrelated host resources.

## ADDED Requirements

### Requirement: Supported host contract
vpnctl v2 SHALL support Ubuntu 24.04 LTS on Linux amd64 with systemd and root privileges. Before any mutation, initialization SHALL verify `/dev/net/tun`, kernel WireGuard, nftables, policy-routing and conntrack-mark support, systemd-resolved, and gateway IPv4-forwarding capability; a missing mandatory capability MUST produce an actionable error without partial initialization.

#### Scenario: Unsupported virtualized host
- **WHEN** the operator initializes a host without `/dev/net/tun` or required kernel networking capabilities
- **THEN** vpnctl reports each missing capability and makes no system change

### Requirement: Explicit immutable host role
The installer SHALL install one `vpnctl` binary without selecting a role. `vpnctl init --gateway` and `vpnctl init --node` SHALL be mutually exclusive role choices, exactly one SHALL be required, and a successfully initialized role SHALL be persisted. Repeating init with the same role SHALL be idempotent; changing roles through repeated init SHALL be rejected and require a separate migration or reinitialization flow.

#### Scenario: Idempotent gateway initialization
- **WHEN** the operator repeats `vpnctl init --gateway` with the same effective inputs on an initialized gateway
- **THEN** vpnctl validates the existing installation and produces no duplicate resources or credential changes

#### Scenario: Accidental role change
- **WHEN** the operator runs `vpnctl init --node` on an initialized gateway
- **THEN** vpnctl rejects the request before mutation and explains that an explicit migration or reinitialization is required

### Requirement: Gateway initialization inputs and port contract
Gateway initialization SHALL require a manually supplied public IPv4 address and MUST NOT discover it through an external service. It SHALL default the client pool to `10.66.0.0/24` and node pool to `10.67.0.0/24`, allow only `--client-cidr`, `--node-cidr`, `--external-interface`, and `--ssh-port` as advanced init overrides, and reserve `443/TCP`, `8443/TCP`, and `51820/UDP`. The public listener ports SHALL NOT be configurable in v2.0; `443/UDP` and `8443/UDP` SHALL remain closed.

#### Scenario: Minimal gateway initialization
- **WHEN** the operator runs `vpnctl init --gateway --public-ip 203.0.113.10` on a compatible clean host
- **THEN** the plan uses the default pools, discovered interface and SSH listener, and the fixed public port contract

#### Scenario: Missing public IP
- **WHEN** gateway initialization omits `--public-ip`
- **THEN** vpnctl rejects the command before mutation and does not attempt external IP discovery

### Requirement: Role-scoped component installation
Initialization SHALL install and start only the components required by the selected role. The presence of both roles in one binary MUST NOT start gateway services on a node or node data-plane services on a gateway.

#### Scenario: Node initialization
- **WHEN** a clean host is initialized with `vpnctl init --node`
- **THEN** gateway controller, public ingress, and public transport listeners are not installed or started

### Requirement: Host ownership boundaries
The gateway SHALL be treated as dedicated to vpnctl, and conflicts on reserved ports or with incompatible reverse-proxy, WireGuard, routing, or firewall configurations SHALL fail preflight rather than be merged implicitly. vpnctl SHALL manage only its own nftables table and MUST NOT flush the global ruleset or delete provider-managed resources. A private node SHALL remain an application host: vpnctl SHALL own only its files, units, TUN, routing, DNS integration, tunnel, and named nftables resources and MUST NOT alter unrelated applications, listeners, Docker configuration, services, or firewall rules.

#### Scenario: Existing gateway reverse proxy
- **WHEN** port `443/TCP` is occupied by an unmanaged reverse proxy during gateway init
- **THEN** vpnctl reports the conflict and makes no attempt to reconfigure or replace that service

#### Scenario: Foreign nftables table
- **WHEN** vpnctl applies its firewall on a host containing unrelated nftables tables
- **THEN** only vpnctl-owned resources are changed and the unrelated tables remain intact

### Requirement: Gateway firewall baseline
The gateway firewall SHALL default-deny unsolicited inbound traffic, allow established and related flows, loopback, the verified SSH listener, and only required vpnctl listeners, and SHALL implement vpnctl forwarding and NAT without exposing internal control or reverse-tunnel endpoints publicly. The SSH listener SHALL be allowed from `0.0.0.0/0`; vpnctl MUST NOT change sshd configuration, keys, or authentication methods.

#### Scenario: Public listener audit
- **WHEN** gateway initialization completes
- **THEN** only the detected SSH port plus `443/TCP`, `8443/TCP`, and `51820/UDP` are admitted by vpnctl for unsolicited public inbound traffic

### Requirement: Fail-closed SSH listener detection
An explicit `--ssh-port` SHALL be checked against an active sshd or systemd listener. Without the override, vpnctl SHALL derive the server port from the current `SSH_CONNECTION`, cross-check it with an active listener, and show its source in the plan. If the command is not running over SSH, the sources disagree, or listeners are ambiguous, vpnctl MUST NOT assume port 22 and SHALL stop before mutation.

#### Scenario: Ambiguous SSH listeners
- **WHEN** gateway init cannot unambiguously match the current SSH connection to a server listener and no `--ssh-port` is provided
- **THEN** vpnctl requires an explicit verified port and leaves the firewall unchanged

### Requirement: Independent lockout watchdog
Every firewall or routing operation classified as lockout-risk SHALL save the previous vpnctl-managed network state, start a controller-independent watchdog, apply changes atomically, and remain uncommitted for exactly 120 seconds. Confirmation SHALL require `vpnctl confirm <transaction-id>` from a newly established SSH session; an existing session and `--yes` MUST NOT satisfy this check. Missing confirmation, process failure, or failed post-apply checks SHALL restore the prior vpnctl rules, routes, and sysctls.

#### Scenario: Successful reconnect confirmation
- **WHEN** the operator establishes a new SSH connection after a lockout-risk change and confirms the active transaction within 120 seconds
- **THEN** vpnctl commits the network state and cancels the watchdog rollback

#### Scenario: New SSH login fails
- **WHEN** the original SSH session remains open but no confirmation arrives from a new session before the deadline
- **THEN** the independent watchdog restores the previous vpnctl-managed network state

#### Scenario: Expired confirmation
- **WHEN** the operator confirms a transaction after its watchdog already rolled it back
- **THEN** vpnctl reports the transaction as expired and rolled back and performs no new mutation

### Requirement: System-owned installation layout and permissions
vpnctl SHALL keep editable presets under `/etc/vpnctl/presets.d`, durable state, secrets, exports, and backups under `/var/lib/vpnctl`, and runtime sockets under `/run/vpnctl`. Secret directories SHALL use mode `0700` and secret files mode `0600`; runtime state SHALL be independent of the current working directory.

#### Scenario: Invocation from another directory
- **WHEN** the operator invokes vpnctl from any working directory after initialization
- **THEN** vpnctl locates the same system-owned role and state without creating cwd-local state

### Requirement: Low-memory swap offer
On a low-memory target, gateway initialization SHALL include an optional managed 1 GB swap creation in its plan and SHALL require explicit confirmation before creating it. Declining swap SHALL not by itself fail initialization if mandatory capacity preflight passes.

#### Scenario: Operator accepts swap
- **WHEN** a 512 MB gateway has no adequate swap and the operator confirms the proposed swap action
- **THEN** vpnctl creates and records a managed 1 GB swap resource that lifecycle operations can identify

### Requirement: Uninstall and purge separation
`vpnctl uninstall` SHALL remove managed runtime resources and remove an installer-managed binary last while preserving state, presets, identities, secrets, certificates, exports, and backups. `vpnctl purge` SHALL additionally remove preserved state and credentials after typed confirmation, while portable backup archives SHALL remain unless `--include-backups` receives a second typed confirmation. A gateway with active nodes, clients, or exposes SHALL require `--force` after presenting the full impact and external follow-up actions.

#### Scenario: Recoverable uninstall
- **WHEN** the operator uninstalls vpnctl without purge
- **THEN** managed networking and services stop, the binary is removed last, and durable state remains available for recovery

#### Scenario: Purge preserving archives
- **WHEN** the operator confirms purge without `--include-backups`
- **THEN** runtime and state are irreversibly removed but portable backup archives remain

### Requirement: Node uninstall coordinates revocation
An online node uninstall SHALL first obtain gateway confirmation that the node has been revoked, then remove local runtime. If the gateway is unavailable, ordinary uninstall SHALL stop; `vpnctl uninstall --local-only` SHALL explicitly remove local runtime and return a mandatory gateway-side revoke action.

#### Scenario: Offline local cleanup
- **WHEN** a node cannot reach its gateway and the operator uses `uninstall --local-only`
- **THEN** local vpnctl runtime is removed and the result clearly states that gateway credentials remain valid until separately revoked
