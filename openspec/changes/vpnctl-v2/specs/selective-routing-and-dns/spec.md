## Purpose

Defines explicit reusable traffic selectors, host-wide private-node routing, split DNS, and fail-closed guarantees that prevent selected TCP or UDP traffic from escaping directly.

## ADDED Requirements

### Requirement: Separate IPv4 address pools
The gateway SHALL use separate configurable IPv4 pools for personal clients and private nodes, defaulting to `10.66.0.0/24` and `10.67.0.0/24`. It SHALL allocate the next free address, preserve an identity's address across credential rotation, and reject initialization when either pool overlaps host interfaces, routes, detected container networks, or the other pool. Changing a pool after init SHALL be treated as a disruptive migration with rebind and re-export actions.

#### Scenario: Pool collision at init
- **WHEN** the default node pool overlaps a route already present on the gateway
- **THEN** initialization stops before mutation and requires an explicit non-overlapping CIDR

### Requirement: Explicit selective-routing policy
For private nodes and selective personal clients, traffic matching at least one explicitly assigned preset SHALL use the gateway; unmatched traffic SHALL remain direct. No built-in preset SHALL be assigned automatically during init, join, or client creation. Node policy commands SHALL target the current node, while gateway client policy commands SHALL require an explicit client target.

#### Scenario: Empty node assignment
- **WHEN** a joined node has no assigned presets
- **THEN** ordinary application traffic follows its direct path and no service preset is inferred

### Requirement: Editable versioned preset documents
Initialization SHALL create editable `telegram`, `openai`, and `anthropic` preset documents under `/etc/vpnctl/presets.d/*.yaml`. The public versioned YAML schema SHALL describe selectors only and MUST NOT permit routing actions, outbound names, or raw Mihomo configuration. Unknown selector types SHALL fail validation. Once initialized, preset files SHALL be user state and upgrades MUST NOT restore, modify, or fetch them remotely without explicit review and application.

#### Scenario: User deletes an unassigned built-in preset
- **WHEN** the operator removes an unassigned built-in preset and later updates vpnctl
- **THEN** the preset remains absent until the operator explicitly accepts a template update

### Requirement: Preset validation and activation
The gateway SHALL provide preset list, show, validate, diff, and reviewed built-in update operations. Manual file edits SHALL not affect active routing until an explicit apply validates the entire set, shows a diff and affected nodes/clients, and atomically publishes a new effective generation. An assigned preset SHALL not be deletable until unassigned. Failed validation or an unsafe template merge SHALL leave the last valid effective generation active.

#### Scenario: Invalid manual edit
- **WHEN** one preset file contains an unknown selector and the operator runs validate or apply
- **THEN** the whole candidate set is rejected and all nodes and clients keep the previous effective generation

### Requirement: Deterministic preset composition
Within one preset, the selected set SHALL equal includes minus excludes, with exclusions taking precedence regardless of rule order. Multiple assigned presets SHALL be combined by union after each preset is evaluated; an include in one preset SHALL therefore reselect traffic excluded by another preset. File and rule ordering MUST NOT change the result.

#### Scenario: Cross-preset include and exclude
- **WHEN** preset A excludes a domain and assigned preset B explicitly includes that domain
- **THEN** the union classifies the domain as selected

### Requirement: Atomic policy replacement
`policy set <preset>...` SHALL replace the entire target assignment atomically, `policy clear` SHALL explicitly empty it, and incremental add/remove SHALL not be part of v2.0. Empty `set`, unknown names, or invalid presets SHALL fail without changing the active assignment. Node changes SHALL apply immediately by default and MAY be registered with `--defer` while the gateway is reachable.

#### Scenario: Deferred node policy
- **WHEN** a node registers a valid policy replacement with `--defer`
- **THEN** gateway desired state records a pending assignment while applied routing remains on the previous generation until `apply`

### Requirement: Host-wide private-node classification
On a private node, the routing policy SHALL apply to traffic from all host processes through the managed routing engine and TUN. v2.0 SHALL not scope policy by process, Linux user, systemd unit, container, or network namespace.

#### Scenario: Application process matches Telegram selector
- **WHEN** any process on the private node opens traffic classified by its assigned Telegram preset
- **THEN** that flow is routed through the node's active gateway transport

### Requirement: Fail-closed selected traffic
After traffic is classified as selected, both TCP and UDP SHALL either traverse the active gateway transport or be blocked; neither protocol SHALL ever fail over to direct. If the gateway or active transport is unavailable while classification is healthy, selected traffic SHALL be blocked and unrelated direct traffic SHALL continue.

#### Scenario: Gateway becomes unreachable
- **WHEN** an established node cannot reach the gateway and opens a new selected TCP or UDP flow
- **THEN** the selected flow is blocked and a new unmatched direct flow can still use the ordinary uplink

### Requirement: Routing-engine crash guard
A fail-closed guard independent of routing-engine readiness SHALL activate before classification starts and survive routing-engine crash or restart. If the engine is not ready, all new application egress on the private node SHALL be blocked except minimum vpnctl recovery traffic to the gateway. Previously classified direct connections MAY continue only when their direct decision is reliably retained by connection state. Explicit uninstall MAY remove the guard only as part of controlled restoration of ordinary networking.

#### Scenario: Routing engine crashes
- **WHEN** the private-node routing engine exits unexpectedly
- **THEN** new application egress cannot bypass policy through direct networking and recovery traffic needed to restore vpnctl remains possible

### Requirement: IPv4 support and IPv6 leak prevention
IPv4 SHALL be the only fully supported data-plane address family in v2.0. IPv6 MUST NOT provide a bypass for selected traffic; when equivalent safe classification and gateway routing are unavailable, selected IPv6 attempts SHALL be blocked rather than sent direct.

#### Scenario: Selected hostname returns IPv6
- **WHEN** a selected domain resolves to an IPv6 address on a v2.0 node
- **THEN** traffic to that address is not allowed to escape through the direct IPv6 uplink

### Requirement: Split DNS modes
Private nodes and compatible Clash profiles SHALL support `policy` DNS mode as the v2 default and `direct` as a v1-compatibility mode. In policy mode, queries needed to classify selected domains SHALL use a shared gateway DNS path, while unrelated queries SHALL use the node's direct resolvers. Selected DNS MUST NOT fall back to direct when the gateway path fails; unrelated direct DNS SHALL continue.

#### Scenario: Gateway DNS outage
- **WHEN** the shared gateway DNS path is unavailable in policy mode
- **THEN** selected-domain resolution fails closed while unrelated direct-domain resolution remains available

### Requirement: Configurable independent DNS paths
The gateway SHALL expose show/set/reset operations for gateway-path IPv4 upstreams, defaulting and resetting to `1.1.1.1` and `8.8.8.8`. A private node SHALL expose show/set/reset for direct-path IPv4 upstreams, with reset rediscovering the underlying system resolvers while excluding the vpnctl stub. Changes to gateway upstreams SHALL not require node reconfiguration or client re-export, and neither path SHALL automatically fall back to the other.

#### Scenario: Reset node direct DNS
- **WHEN** the operator runs direct DNS reset on a private node
- **THEN** vpnctl rediscovers the host's non-vpnctl resolvers and keeps gateway-path upstreams unchanged

### Requirement: Managed host DNS integration
On a private node, vpnctl SHALL act as the managed host resolver path, integrate with systemd-resolved, and capture ordinary port-53 DNS traffic within vpnctl-owned routing/firewall resources. It SHALL preserve the original host DNS configuration and restore it during uninstall. The gateway SHALL provide one shared internal DNS forwarder for nodes and clients rather than a process per identity.

#### Scenario: Node uninstall restores DNS
- **WHEN** a node is uninstalled after successful DNS integration
- **THEN** its saved underlying resolver configuration is restored and the vpnctl local stub is removed

### Requirement: Classification limitations are explicit
vpnctl SHALL document and diagnose that domain selectors cannot reliably classify traffic that uses independent DoH/DoT, hardcoded IPs, or hidden resolution. Such traffic SHALL remain unmatched/direct unless an IP or CIDR selector also selects it; v2.0 SHALL not globally block third-party DoH/DoT. Fail-closed SHALL be claimed only after classification, not as universal application recognition.

#### Scenario: Application uses an unselected hardcoded address
- **WHEN** an application bypasses ordinary DNS and its destination matches no configured IP selector
- **THEN** vpnctl treats the flow as unmatched/direct and diagnostics can explain the classification boundary
