# Implementation Plan

Status: Draft. This plan is being agreed step by step.

## Goal

Build `vpnctl`: a small Go CLI for managing a personal self-hosted WireGuard VPN
server and its clients.

The first stable version should let one operator connect to a server manually,
run `vpnctl` directly on that server, manage 1-20 clients, generate client
configs, and apply local WireGuard server configuration safely.

The first target server platform is Ubuntu 24.04 LTS x64.

## Accepted Decisions

The following decisions are fixed for the current implementation track:

- Use WireGuard as the VPN backend. See ADR 0001.
- Generate basic Mihomo / Clash-compatible routing configs in the MVP. See ADR
  0002 and ADR 0013.
- Use Git-friendly local state as the source of truth. See ADR 0003.
- Defer remote SSH apply for the initial MVP. See ADR 0004 and ADR 0007.
- Support local file export, WireGuard QR codes, and `scp` hints for MVP config
  delivery. See ADR 0005.
- Implement the tool as a Go CLI. See ADR 0006.
- Run `vpnctl` locally on the server for the initial MVP. See ADR 0007.
- Target Ubuntu 24.04 LTS x64 for the first server implementation. See ADR
  0007.
- Require `root` execution for server-changing MVP commands. See ADR 0007.
- Use JSON for the MVP state file. See ADR 0008.
- Keep vpnctl state in `.vpnctl/` and apply rendered WireGuard config to system
  paths such as `/etc/wireguard/wg0.conf`. See ADR 0009.
- Use `10.66.0.0/24` as the configurable default WireGuard subnet. See ADR
  0010.
- Use system DNS by default and support configurable client DNS. See ADR 0011.
- Use full tunnel client routing by default for the MVP. See ADR 0012.
- Include basic iPhone Clash Mi configuration generation in the MVP. See ADR
  0013.
- Generate domain-routed Clash Mi profiles with UDP-capable WireGuard proxy.
  See ADR 0014.
- Store editable validated JSON rulesets under `.vpnctl/rulesets/`. See ADR
  0015.
- Use a minimal built-in `default` ruleset. See ADR 0016.
- Use explicit fallback DNS for Clash Mi profiles with a warning. See ADR 0017.
- Provide one-shot Ubuntu server setup. See ADR 0018.
- Follow the MVP CLI API in `docs/CLI_SPEC.md`.

## Initial MVP Workflow

The first supported workflow is server-local:

```text
# On the operator machine:
GOOS=linux GOARCH=amd64 go build -o vpnctl ./cmd/vpnctl
scp vpnctl root@server:/usr/local/bin/vpnctl

# On the server:
ssh root@server
mkdir -p ~/vpnctl-state
cd ~/vpnctl-state
vpnctl setup --endpoint IP_СЕРВЕРА --dry-run
vpnctl setup --endpoint IP_СЕРВЕРА
vpnctl client create iphone
vpnctl client export iphone --type wireguard --qr
vpnctl client export iphone --type clash
vpnctl apply
```

The exact binary delivery command is not final yet. The MVP should support a
manual copy flow first; release automation can come later.

## Non-Negotiable Constraints

- Never log private keys.
- Do not print private keys unless the user explicitly exports a config.
- Keep secret files out of Git by default.
- Operations that change server state must be idempotent.
- Apply must have a render-before-apply or dry-run path.
- Server-local apply must not break the active SSH access to the server.
- Prefer explicit behavior over hidden automation.
- Server-local apply must avoid disrupting the active SSH session.
- MVP commands that mutate server state must fail clearly when not run as root.

## Feature Scope

### Core CLI

Required:

- `vpnctl help`
- `vpnctl version`
- predictable exit codes
- human-readable errors
- no secret values in errors by default

Later:

- structured JSON output for automation
- shell completion

### Local State

Required:

- `vpnctl init`
- `.vpnctl/state.json`
- `.vpnctl/rulesets/`
- `.vpnctl/secrets/`
- `.vpnctl/generated/`
- state rooted in the current working directory
- generated `.gitignore` rules for secrets and generated delivery artifacts
- state schema version
- load, validate, and save state atomically
- editable ruleset files validated on load

Later:

- encrypted secret storage
- migration framework for multiple schema versions

### Server-Local Management

Required:

- `vpnctl setup`
- `vpnctl server init`
- detect basic server facts locally
- support Ubuntu 24.04 LTS x64 first
- store WireGuard interface settings
- default to WireGuard subnet `10.66.0.0/24`
- support `vpnctl server init --subnet <cidr>`
- omit client DNS by default
- support `vpnctl server init --dns <servers>`
- support external interface override
- store public endpoint
- apply local server configuration only after explicit command

Later:

- remote SSH apply from operator machine
- multiple servers
- server import from existing WireGuard config

### Server Bootstrap

Required:

- inspect local server prerequisites
- detect Ubuntu 24.04 LTS x64 compatibility
- install `wireguard`, `qrencode`, and `ufw`
- report missing packages or kernel support when setup has not fixed them
- enable IPv4 forwarding through `/etc/sysctl.d/99-vpnctl.conf`
- detect external interface with `ip route get 1.1.1.1`
- add UFW allow rules for SSH and WireGuard UDP
- enable UFW by default during `setup`
- support `--no-enable-ufw`
- avoid `apt upgrade -y`
- require root execution for server-changing commands

Later:

- non-root execution with sudo
- distribution-specific package installation
- automatic firewall setup

### Client Lifecycle

Required:

- create client
- revoke client
- rotate client keys
- delete client with explicit confirmation
- prevent duplicate client IDs
- allocate unique client IPs
- allocate from the configured WireGuard subnet

Later:

- client groups
- metadata templates per platform

### WireGuard Config Generation

Required:

- generate server config from state
- generate client config from state
- default client configs to full tunnel with `AllowedIPs = 0.0.0.0/0`
- omit DNS by default and render custom DNS when configured
- default client configs to `PersistentKeepalive = 25`
- deterministic output for tests and review

Later:

- IPv6
- multiple subnets
- configurable split tunnel client routing
- advanced per-client routing

### Mihomo / Clash Config Generation

Required:

- keep WireGuard config generation separate from routing config generation
- model rulesets as editable JSON files
- create built-in editable `default` ruleset
- default ruleset domains: `chatgpt.com`, `openai.com`, `claude.ai`,
  `anthropic.com`
- support `vpnctl ruleset add default --domain chatgpt.com,openai.com,claude.ai`
- apply the `default` ruleset to Clash client exports unless `--ruleset` is
  provided
- WireGuard client exports do not use rulesets
- validate ruleset `type` against the MVP whitelist
- support `domain-suffix` ruleset type for MVP
- generate a basic Mihomo / Clash config for iPhone Clash Mi
- route configured domains through the WireGuard proxy by default
- use final `MATCH,DIRECT` so non-matching traffic stays direct
- enable UDP on the WireGuard proxy
- use configured DNS when available
- use Clash Mi fallback DNS `1.1.1.1`, `8.8.8.8` when DNS is not configured
- make output deterministic for review and tests

Later:

- remote ruleset updates
- provider-specific profiles
- UI-assisted ruleset editing

### Config Delivery

Required:

- export local client config files
- generate QR codes for WireGuard client configs
- export basic Clash/Mihomo profiles for Clash Mi
- write delivery artifacts under `.vpnctl/generated/delivery/`
- print generated file path after export
- print an `scp` hint after file export

Later:

- web-based delivery
- temporary links
- signed URLs
- one-time links

Web/link-based delivery requires a new ADR before implementation and is a
required post-MVP direction.

### Server-Local Apply

Required:

- generate intended server config during apply
- write config to `/etc/wireguard/wg0.conf` safely by default
- include NAT and forwarding `PostUp` and `PostDown` rules
- validate generated config before activation when possible
- enable and start `wg-quick@wg0`
- apply idempotently
- avoid logging secrets
- avoid routing changes that can break SSH access

Later:

- automatic rollback
- remote state drift detection
- remote SSH apply
- non-root SSH with sudo policy detection

## Implementation Phases

### Phase 1: Foundation

Status: started.

Already done:

- architecture review
- domain model document
- project structure document
- ADR 0001-0007
- Go module
- minimal `vpnctl` entrypoint
- `help` and `version`
- initial CLI tests
- initial Server and Client domain types

Next:

- finish agreeing MVP scope
- add `vpnctl init`
- create state package
- create filesystem layout
- add `.gitignore` management for `.vpnctl/secrets`

Acceptance criteria:

- `go test ./...` passes
- `vpnctl init` creates the expected local structure
- `vpnctl init` creates `.vpnctl/rulesets/default.json`
- default ruleset contains `chatgpt.com`, `openai.com`, `claude.ai`, and
  `anthropic.com`
- rerunning `vpnctl init` is safe
- initialized state is rooted in the current working directory
- no external Go dependencies unless justified

### Phase 2: State Model

Deliverables:

- typed state model
- state serialization
- schema version field
- JSON load and save through Go's standard library
- validation for server, clients, IPs, and duplicate IDs
- atomic file writes

Acceptance criteria:

- invalid state fails with clear errors
- valid state round-trips through load and save
- tests cover duplicate client IDs and IP allocation conflicts
- tests cover default and custom subnet validation

### Phase 3: Server-Local Definition

Deliverables:

- `vpnctl setup`
- `vpnctl server init`
- server validation
- default WireGuard interface settings
- configurable WireGuard subnet with `10.66.0.0/24` default
- configurable DNS with no explicit DNS by default
- local prerequisite inspection
- Ubuntu 24.04 LTS x64 detection
- package installation for `wireguard`, `qrencode`, and `ufw`
- IPv4 forwarding configuration
- external interface detection and override
- UFW SSH and WireGuard allow rules
- UFW enablement by default with opt-out

Acceptance criteria:

- `vpnctl setup --dry-run` shows planned system changes without mutation
- `vpnctl setup --endpoint <host>` performs one-shot initial server setup
- a server can be initialized from the server itself
- `vpnctl server init` stores `10.66.0.0/24` by default
- `vpnctl server init --subnet 10.10.10.0/24` stores the custom subnet
- `vpnctl server init` stores an empty DNS server list by default
- `vpnctl server init --dns 1.1.1.1,1.0.0.1` stores custom DNS servers
- missing required fields produce actionable errors
- running outside Ubuntu 24.04 LTS x64 reports a clear compatibility warning or
  error, depending on command risk
- server-changing commands fail clearly when not run as root
- setup installs `wireguard`, `qrencode`, and `ufw`
- setup does not run `apt upgrade -y`
- setup allows detected SSH port before enabling UFW
- setup allows WireGuard UDP port before enabling UFW

### Phase 4: Key Management

Deliverables:

- WireGuard key generation
- preshared key generation
- secret file storage
- restricted file permissions
- secret-safe test helpers

Acceptance criteria:

- generated public/private keys are valid WireGuard keys
- key generation uses system `wg`
- private keys are written only under `.vpnctl/secrets`
- private keys never appear in test failure messages or command output

### Phase 5: Client Lifecycle

Deliverables:

- `vpnctl client create`
- `vpnctl client revoke`
- `vpnctl client rotate-keys`
- `vpnctl client delete`

Acceptance criteria:

- client create allocates a unique IP and key material
- first default-subnet client receives `10.66.0.2`
- revoke removes the peer from rendered server config
- rotate changes key material without changing client identity
- client export regenerates artifacts from current state without rotating keys
- delete requires explicit confirmation or force flag

### Phase 6: WireGuard Rendering

Deliverables:

- server WireGuard renderer
- client WireGuard renderer
- deterministic formatting

Acceptance criteria:

- rendered server config includes only active clients
- rendered client config contains the expected endpoint and routes
- rendered client config uses `AllowedIPs = 0.0.0.0/0` by default
- rendered client config uses `PersistentKeepalive = 25` by default
- rendered client config omits `DNS` by default
- rendered client config includes `DNS` when custom DNS is configured
- golden-file tests cover representative configs

### Phase 7: Mihomo / Clash Rendering

Deliverables:

- basic Clash/Mihomo config model
- ruleset JSON model
- ruleset validation
- `vpnctl ruleset add`
- basic iPhone Clash Mi profile renderer
- deterministic formatting
- golden-file tests

Acceptance criteria:

- `.vpnctl/rulesets/default.json` is valid after `vpnctl init`
- generated default rules do not duplicate `api.openai.com`
- `vpnctl ruleset add default --domain chatgpt.com,openai.com` writes a valid
  ruleset
- Clash export uses `default` ruleset when `--ruleset` is omitted
- unsupported ruleset `type` values fail with clear errors
- generated config parses as JSON or YAML, depending on selected output format
- generated rules are deterministic
- generated rules include configured domain rules routed to `VPN`
- generated rules end with `MATCH,DIRECT`
- generated WireGuard proxy has `udp: true`
- generated WireGuard proxy has `allowed-ips: ['0.0.0.0/0']`
- generated profile uses configured DNS when present
- generated profile uses `1.1.1.1` and `8.8.8.8` fallback DNS when DNS is not
  configured
- WireGuard and Mihomo concerns remain separate in code
- generated profile can be exported for Clash Mi

### Phase 8: Config Delivery

Deliverables:

- `vpnctl client export`
- local file export
- QR code export
- Clash/Mihomo profile export

Acceptance criteria:

- exported artifacts are written under `.vpnctl/generated/delivery`
- file exports print the generated path
- file exports print an `scp` hint
- QR output can be generated without logging private keys unexpectedly
- Clash Mi export warns when fallback DNS is injected
- delivery artifacts can be regenerated from state

### Phase 9: Server-Local Apply

Deliverables:

- local apply command
- dry-run preview flow
- safe write path for `/etc/wireguard/wg0.conf`
- local service integration
- local safety checks

Acceptance criteria:

- apply is idempotent
- dry-run shows intended changes
- generated server config contains NAT and forwarding `PostUp` and `PostDown`
- apply enables and starts `wg-quick@wg0`
- command output redacts secrets
- active SSH session safety is considered before routing changes

### Phase 10: Hardening And Release

Deliverables:

- command documentation
- examples
- build instructions
- release build script or Makefile
- end-to-end smoke test plan

Acceptance criteria:

- fresh checkout can run tests with only Go installed
- binary can be built with `go build ./cmd/vpnctl`
- README explains the first usable workflow

## Out Of Scope For First Stable Version

- multi-operator concurrency
- hosted web UI
- long-running server daemon
- multiple VPN backends
- temporary links, signed URLs, and one-time links
- web-based config delivery
- automatic firewall mutation without explicit review
- IPv6-first support
- managing multiple VPN servers
- remote SSH apply from the operator machine
- non-root server execution unless explicitly promoted into MVP
- split tunnel client routing unless explicitly promoted into MVP
- full tunnel Clash Mi routing unless explicitly promoted into MVP
- public `server render` command unless explicitly promoted into MVP

## Dependency Policy

Global dependencies:

- Go only on the development machine.
- The server should only need the `vpnctl` binary before setup.
- Setup installs server runtime tools: `wireguard`, `qrencode`, and `ufw`.

Project dependencies:

- Prefer the Go standard library.
- Add external libraries only when they remove meaningful risk or complexity.
- Every new dependency should have a clear reason in the commit or ADR when it
  affects architecture.

Expected future candidates:

- SSH package for future remote apply

## Testing Strategy

Required from the start:

- unit tests for domain rules
- unit tests for CLI behavior
- golden tests for generated configs
- filesystem tests for state and permissions

Later:

- integration tests for local server apply against a controlled Linux target
- smoke tests for real WireGuard config validation
- remote SSH integration tests after remote apply is added
