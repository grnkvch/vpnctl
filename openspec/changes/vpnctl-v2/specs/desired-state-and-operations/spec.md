## Purpose

Defines safe convergence, durable state, diagnostics, CLI automation contracts, and temporary observability for all vpnctl-owned resources.

## ADDED Requirements

### Requirement: Immediate, dry-run, and deferred mutations
Reversible mutating commands SHALL apply immediately after validation by default. A mutating command with `--dry-run` SHALL model only that unregistered operation without prompting or changing desired state. Supported commands with `--defer` SHALL register pending desired state on a reachable gateway without changing applied state; general `plan` and `apply` SHALL inspect and converge those pending changes.

#### Scenario: Dry-run expose
- **WHEN** the operator dry-runs a new expose
- **THEN** vpnctl reports its proposed effects and no expose, tunnel mapping, certificate, or pending record is created

### Requirement: Distinct status, doctor, plan, apply, and repair
`status` SHALL be passive; `doctor` SHALL perform explicit bounded probes without mutation; `plan` SHALL show pending desired-state diff separately from detected drift; `apply` SHALL converge only registered pending changes; and `repair` SHALL reconcile vpnctl-owned drift only after preview and confirmation. Apply MUST NOT overwrite drift in a resource it needs to change, and repair MUST NOT alter unknown external resources.

#### Scenario: Drift conflicts with apply
- **WHEN** a pending change targets a vpnctl resource whose applied configuration has drifted
- **THEN** apply reports a conflict and directs the operator to repair rather than overwriting the drift

### Requirement: Transactional local convergence
Every local application SHALL validate a complete candidate, stage derived artifacts, activate atomically where the host permits, perform health checks, and restore the prior local generation on confirmed failure. A failed validation MUST NOT disturb the last valid data plane.

#### Scenario: Generated configuration is invalid
- **WHEN** candidate configuration fails validation before activation
- **THEN** the active generation and running services remain unchanged

### Requirement: Convergent cross-host operations
Changes spanning gateway and private node SHALL use a recoverable `validate → stage → activate → confirm` transaction with a unique operation ID and at least `pending`, `active`, `degraded`, and `failed` states. Public ingress SHALL activate last after tunnel readiness. If connectivity is lost and outcome is uncertain, vpnctl SHALL not blindly roll back or replay; later status/apply SHALL reconcile generations and continue toward authoritative desired state.

#### Scenario: Response lost during cross-host activation
- **WHEN** connection loss makes the final operation outcome unknown
- **THEN** the operation remains reconcilable and the next command determines actual state by ID and generation before taking another effect

### Requirement: Durable versioned JSON state
v2.0 SHALL use validated system-owned JSON state rather than SQLite. The gateway controller SHALL be the only authoritative writer; writes SHALL use temporary files, fsync, and atomic rename, include a monotonic generation, and preserve at least one prior version for local rollback. Preset source files SHALL become effective only after validated apply. Manual state editing SHALL be unsupported except a documented break-glass flow after controller stop followed by validate and repair.

#### Scenario: Process exits during state write
- **WHEN** the writer terminates before atomic rename
- **THEN** the last complete state generation remains readable and no partially written authoritative document is accepted

### Requirement: Default status view and exit behavior
`vpnctl status` SHALL report role, binary/protocol/component versions, overall health, gateway/control connectivity, active transport and data-plane health, resource counts, pending, drift, active invites and log opt-ins, certificate and backup warnings, and only problematic resources with required actions. `--all` SHALL expand all resource tables; JSON SHALL always include the full structure. Healthy warnings or intentional pending changes SHALL retain success exit category, while degraded components, drift, unavailable mandatory dependencies, and invalid state SHALL use stable distinct categories.

#### Scenario: Healthy state with expiring certificate warning
- **WHEN** all mandatory components are healthy but a certificate is inside its warning window
- **THEN** status reports the warning and required action while retaining the success exit category

### Requirement: Bounded active doctor probes
`vpnctl doctor [dns|transport|tunnel|ingress]` SHALL run only on explicit request and perform bounded safe probes with individual timeouts and an overall deadline. The default suite SHALL be role-aware; DNS SHALL test direct and gateway paths independently, transport SHALL test only active transport, tunnel SHALL test internal multiplexed reachability, and ingress SHALL test public-IP TLS, reserved health path, tunnel, and local upstreams. Doctor SHALL not switch, apply, repair, register webhooks, or invoke real webhook paths.

#### Scenario: Explicit user probe URL
- **WHEN** the operator supplies `doctor --probe-url <https-url>`
- **THEN** vpnctl performs only a safe GET without body or credentials to that explicit endpoint

#### Scenario: Probe needs unknown external service
- **WHEN** a diagnostic cannot run safely without an unspecified third-party endpoint
- **THEN** it returns `SKIPPED` with an explanation rather than using hidden vpnctl telemetry

### Requirement: Consistent human and JSON CLI contract
Operational and mutating commands SHALL support global `--json` and otherwise return concise human-readable results. JSON stdout SHALL contain exactly one document with stable major-version fields including `schema_version`, resource/result identifiers, status, warnings, and `requires_action`; progress and diagnostics SHALL go to stderr. Secret-bearing values and sensitive webhook paths MUST NOT appear in JSON. Exit codes SHALL have stable categories at least for success, validation, conflict, unavailable/degraded, and internal error.

#### Scenario: Automation output with diagnostics
- **WHEN** a JSON-mode command emits progress and completes with a validation error
- **THEN** stdout remains one parseable result document, progress is on stderr, and the validation exit category is used

### Requirement: Impact-based confirmation
Ordinary validated reversible operations SHALL apply without a prompt. Availability-impacting or destructive operations, including init, join, revoke/delete/rotate, expose removal, transport switch, certificate rotation, repair, restore, update/rollback, uninstall/purge, and destructive apply, SHALL require confirmation as defined by their workflow. `--yes` SHALL skip only ordinary yes/no prompts; it MUST NOT provide invite tokens or backup passphrases, bypass typed purge confirmations, or satisfy the SSH watchdog. `--json` SHALL never imply consent.

#### Scenario: Non-interactive destructive JSON command
- **WHEN** a destructive operation requiring consent runs non-interactively in JSON mode without an allowed `--yes` or required typed confirmation
- **THEN** vpnctl exits before mutation and reports the missing consent action

### Requirement: Logging is disabled by default
Without an active opt-in, vpnctl components SHALL emit no expanded operational logging. `log enable <scope> --level <level> --for <duration>` SHALL require one of `control`, `transport`, `routing`, `dns`, `tunnel`, `ingress`, or `all`, one of `error`, `info`, `debug`, or `trace`, and a duration no longer than one hour. The absolute expiration SHALL survive restarts and automatically disable the session.

#### Scenario: Logging session expires during restart
- **WHEN** a 15-minute routing debug session spans a controller restart
- **THEN** it remains active only until its original absolute expiration and then disables automatically

### Requirement: Logging destinations and redaction
An opted-in session SHALL use journald by default. A separately requested file destination SHALL use mode `0600` and bounded rotation; remote destinations SHALL not be supported. Secrets, authorization headers, request/response bodies, and webhook paths MUST NOT be logged at any level or destination. `log status` SHALL display active opt-ins and remaining time only, and `log disable <scope|all>` SHALL stop them explicitly.

#### Scenario: Trace ingress logging
- **WHEN** ingress trace logging is enabled during an authenticated webhook request
- **THEN** operational trace data can be emitted but the path, authorization headers, and request/response bodies remain redacted

### Requirement: No telemetry or hidden calls
vpnctl SHALL not send telemetry or contact a project-operated endpoint automatically. Network calls SHALL occur only for documented operation needs such as explicit update, configured DNS, transport handshake validation, or operator-requested diagnostics.

#### Scenario: Idle gateway
- **WHEN** no operator command or data-plane traffic requires an external service
- **THEN** vpnctl sends no analytics, update check, or hidden diagnostic request
