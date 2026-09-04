# vpnctl v2 CLI contract

This document freezes the public v2.0 command tree. Internal systemd service modes are not public commands.
The initialized host role supplies context: node-local commands always target the current node, while gateway collection commands name only the managed resource.

## Global rules

- `--json` is accepted by every operational and mutating command. It writes exactly one result document to stdout; progress stays on stderr. `help` and `version` remain plain text.
- `--dry-run` is accepted only where the table says `yes`. It validates and renders the proposed operation without writing state, files, services, or pending operations. It skips consent prompts, but may still request hidden token/passphrase input when that input is necessary to validate the operation.
- `--defer` is accepted only where the table says `yes`. It records authoritative pending desired state for a later `plan` and `apply`; it is not an alias for `--dry-run`.
- `--yes` satisfies a `confirm` prompt and the confirming branch of `conditional`. It never supplies a secret and never bypasses `typed` consent.
- Invite and recovery tokens and backup passphrases never appear in argv. Commands that require them read hidden input from a TTY according to the stdin contract.
- `gateway/node` means both initialized roles. `all` also includes an uninitialized host. An unsupported role fails validation before mutation.
- No unlisted aliases are public API, except `-h`/`--help` for `help` and `-v`/`--version` for `version`.

## Consent classes

| Class | Behavior |
| --- | --- |
| `none` | No prompt after validation. |
| `confirm` | A yes/no impact prompt is required; `--yes` is allowed. |
| `conditional` | The rendered plan decides whether a yes/no prompt is required; `--yes` is allowed when it is. |
| `confirm+typed-if-irreversible` | Normal execution uses yes/no consent; an irreversible migration additionally requires typed consent that `--yes` cannot bypass. |
| `typed` | Typed destructive consent is always required and cannot be bypassed by `--yes`. |

## Process exit codes

The numeric mapping is stable for the whole v2 major version. Warnings and intentionally deferred pending changes remain successful; a failed mandatory health dependency uses the unavailable/degraded category.

| Code | Category | Meaning |
| --- | --- | --- |
| `0` | `success` | The command completed, including healthy results with warnings or deliberate pending state. |
| `1` | `internal` | vpnctl violated an invariant or encountered an unclassified internal failure. |
| `2` | `validation` | Arguments, input, role, state schema, or preconditions are invalid; no mutation occurred. |
| `3` | `conflict` | Valid intent conflicts with drift, generation, ownership, allocation, or concurrent state. |
| `4` | `unavailable` | A required controller, component, transport, probe, or dependency is unavailable or degraded. |

## Frozen command registry

The options column excludes the applicable global flags described above. `node only` in the Defer column means the same grammar supports deferral only when run on a private node.

| Command | JSON result | Roles | Arguments and options | Consent | Dry-run | Defer | Example |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `vpnctl help [command...]` | `plain-text` | all | optional command path | none | no | no | `vpnctl help transport switch` |
| `vpnctl version` | `plain-text` | all | none | none | no | no | `vpnctl version` |
| `vpnctl init --gateway` | `operation-v1:init.gateway` | all | `--public-ip <IPv4>` required; optional `--client-cidr`, `--node-cidr`, `--external-interface`, `--ssh-port` | confirm | yes | no | `sudo vpnctl init --gateway --public-ip 203.0.113.10` |
| `vpnctl init --node` | `operation-v1:init.node` | all | no role-specific arguments | confirm | yes | no | `sudo vpnctl init --node` |
| `vpnctl confirm <transaction-id>` | `operation-v1:confirm` | gateway | one positional short transaction ID | none | no | no | `sudo vpnctl confirm fw-7K3M2P` |
| `vpnctl status` | `status-v1:status` | gateway/node | optional `--all` | none | no | no | `sudo vpnctl status --all` |
| `vpnctl doctor [scope]` | `diagnostic-v1:doctor` | gateway/node | optional `dns`, `transport`, `tunnel`, or `ingress`; optional `--probe-url <https-url>` | none | no | no | `sudo vpnctl doctor ingress` |
| `vpnctl validate` | `validation-v1:validate` | gateway/node | none | none | no | no | `sudo vpnctl validate` |
| `vpnctl plan` | `plan-v1:plan` | gateway/node | none | none | no | no | `sudo vpnctl plan` |
| `vpnctl apply` | `operation-v1:apply` | gateway/node | none | conditional | no | no | `sudo vpnctl apply` |
| `vpnctl repair` | `operation-v1:repair` | gateway/node | none | confirm | yes | no | `sudo vpnctl repair --dry-run` |
| `vpnctl invite <node-name>` | `secret-issue-v1:invite` | gateway | unique node name | none | yes | no | `sudo vpnctl invite bot-server` |
| `vpnctl invite cancel <invite-id>` | `operation-v1:invite.cancel` | gateway | one invite ID | none | yes | no | `sudo vpnctl invite cancel inv-7K3M2P` |
| `vpnctl join <transport> [preset...]` | `operation-v1:join` | node | transport is `standard` or `restricted`; zero or more initial presets; invite via hidden prompt | confirm | yes | no | `sudo vpnctl join restricted telegram` |
| `vpnctl node list` | `collection-v1:node.list` | gateway | none | none | no | no | `sudo vpnctl node list` |
| `vpnctl node show <name-or-id>` | `resource-v1:node.show` | gateway | one node reference | none | no | no | `sudo vpnctl node show bot-server` |
| `vpnctl node revoke <name-or-id>` | `operation-v1:node.revoke` | gateway | one node reference | confirm | yes | no | `sudo vpnctl node revoke bot-server` |
| `vpnctl node delete <name-or-id>` | `operation-v1:node.delete` | gateway | one revoked node reference | confirm | yes | no | `sudo vpnctl node delete bot-server` |
| `vpnctl node rotate` | `operation-v1:node.rotate` | node | none | confirm | yes | no | `sudo vpnctl node rotate` |
| `vpnctl node recover <name-or-id>` | `secret-issue-v1:node.recover` | gateway | one active node reference; recovery token is shown once through the secret flow | confirm | yes | no | `sudo vpnctl node recover bot-server` |
| `vpnctl node recover` | `operation-v1:node.recover` | node | recovery token via hidden prompt; current node identity is implicit | confirm | yes | no | `sudo vpnctl node recover` |
| `vpnctl client add <name> [preset...]` | `operation-v1:client.add` | gateway | unique client name; zero or more initial presets | none | yes | no | `sudo vpnctl client add iphone telegram openai` |
| `vpnctl client list` | `collection-v1:client.list` | gateway | none | none | no | no | `sudo vpnctl client list` |
| `vpnctl client show <name-or-id>` | `resource-v1:client.show` | gateway | one client reference | none | no | no | `sudo vpnctl client show iphone` |
| `vpnctl client revoke <name-or-id>` | `operation-v1:client.revoke` | gateway | one client reference | confirm | yes | no | `sudo vpnctl client revoke iphone` |
| `vpnctl client delete <name-or-id>` | `operation-v1:client.delete` | gateway | one revoked client reference | confirm | yes | no | `sudo vpnctl client delete iphone` |
| `vpnctl client rotate <name-or-id>` | `operation-v1:client.rotate` | gateway | one active client reference | confirm | yes | no | `sudo vpnctl client rotate iphone` |
| `vpnctl client export <name-or-id> <format>` | `export-v1:client.export` | gateway | format is `clash` or `wireguard`; optional `--output <path>`, `--force` | none | yes | no | `sudo vpnctl client export iphone clash` |
| `vpnctl preset list` | `collection-v1:preset.list` | gateway | none | none | no | no | `sudo vpnctl preset list` |
| `vpnctl preset show <name>` | `resource-v1:preset.show` | gateway | one preset name | none | no | no | `sudo vpnctl preset show telegram` |
| `vpnctl preset validate` | `validation-v1:preset.validate` | gateway | validates the complete source set | none | no | no | `sudo vpnctl preset validate` |
| `vpnctl preset diff` | `plan-v1:preset.diff` | gateway | compares source and active normalized sets | none | no | no | `sudo vpnctl preset diff` |
| `vpnctl preset update <name>` | `operation-v1:preset.update` | gateway | one built-in template name | none | yes | yes | `sudo vpnctl preset update telegram --defer` |
| `vpnctl policy show` | `resource-v1:policy.show` | node | current node is implicit | none | no | no | `sudo vpnctl policy show` |
| `vpnctl policy show --client <name-or-id>` | `resource-v1:policy.show` | gateway | one client target | none | no | no | `sudo vpnctl policy show --client iphone` |
| `vpnctl policy set <preset...>` | `operation-v1:policy.set` | node | one or more presets replace the full node assignment | none | yes | yes | `sudo vpnctl policy set telegram --defer` |
| `vpnctl policy set <preset...> --client <name-or-id>` | `operation-v1:policy.set` | gateway | one or more presets replace the full client assignment | none | yes | no | `sudo vpnctl policy set telegram openai --client iphone` |
| `vpnctl policy clear` | `operation-v1:policy.clear` | node | current node is implicit | none | yes | yes | `sudo vpnctl policy clear --defer` |
| `vpnctl policy clear --client <name-or-id>` | `operation-v1:policy.clear` | gateway | one client target | none | yes | no | `sudo vpnctl policy clear --client iphone` |
| `vpnctl dns show` | `resource-v1:dns.show` | gateway/node | gateway shows selected-path upstreams; node shows direct-path upstreams | none | no | no | `sudo vpnctl dns show` |
| `vpnctl dns set <IPv4...>` | `operation-v1:dns.set` | gateway/node | one or more IPv4 resolvers; scope follows host role | none | yes | no | `sudo vpnctl dns set 1.1.1.1 8.8.8.8` |
| `vpnctl dns reset` | `operation-v1:dns.reset` | gateway/node | scope follows host role | none | yes | no | `sudo vpnctl dns reset` |
| `vpnctl transport test <transport>` | `diagnostic-v1:transport.test` | node | transport is `standard` or `restricted` | none | no | no | `sudo vpnctl transport test restricted` |
| `vpnctl transport switch <transport>` | `operation-v1:transport.switch` | node | transport is `standard` or `restricted` | confirm | yes | yes | `sudo vpnctl transport switch restricted` |
| `vpnctl transport host show` | `resource-v1:transport.host.show` | gateway | shows active candidate, health, pending change, and rollback availability | none | no | no | `sudo vpnctl transport host show` |
| `vpnctl transport host prepare <host>` | `operation-v1:transport.host.prepare` | gateway | candidate hostname; creates one staged replacement | none | yes | no | `sudo vpnctl transport host prepare www.example.com` |
| `vpnctl transport host commit` | `operation-v1:transport.host.commit` | gateway | commits the single prepared replacement | confirm | yes | no | `sudo vpnctl transport host commit` |
| `vpnctl transport host rollback` | `operation-v1:transport.host.rollback` | gateway | restores the bounded previous-host snapshot | confirm | yes | no | `sudo vpnctl transport host rollback` |
| `vpnctl transport host recover <host>` | `operation-v1:transport.host.recover` | node | emergency SSH alignment to the explicitly gateway-authorized active host | confirm | yes | no | `sudo vpnctl transport host recover www.example.com` |
| `vpnctl expose <upstream>` | `operation-v1:expose` | node | port or `host:port`; optional `--name`, `--path`, `--prefix`, `--allow-non-loopback`, `--body-limit`, `--timeout` | none | yes | yes | `sudo vpnctl expose 3000 --path /telegram/webhook` |
| `vpnctl expose list` | `collection-v1:expose.list` | node | none | none | no | no | `sudo vpnctl expose list` |
| `vpnctl expose show <name-or-id>` | `resource-v1:expose.show` | node | one expose reference; refreshes the public certificate copy when reachable | none | no | no | `sudo vpnctl expose show telegram-api` |
| `vpnctl expose remove <name-or-id>` | `operation-v1:expose.remove` | node | one expose reference | confirm | yes | yes | `sudo vpnctl expose remove telegram-api` |
| `vpnctl cert show` | `resource-v1:cert.show` | gateway | public ingress certificate metadata only | none | no | no | `sudo vpnctl cert show` |
| `vpnctl cert export [output-path]` | `export-v1:cert.export` | gateway | optional path; default is the managed gateway certificate export | none | yes | no | `sudo vpnctl cert export /tmp/gateway.crt` |
| `vpnctl cert rotate` | `operation-v1:cert.rotate` | gateway | no arguments | confirm | yes | no | `sudo vpnctl cert rotate` |
| `vpnctl trust show` | `resource-v1:trust.show` | gateway | internal control CA generations and rotation state; no private material | none | no | no | `sudo vpnctl trust show` |
| `vpnctl trust rotate` | `operation-v1:trust.rotate` | gateway | starts the single staged control-CA rotation | confirm | yes | no | `sudo vpnctl trust rotate` |
| `vpnctl trust commit` | `operation-v1:trust.commit` | gateway | commits the staged control-CA rotation | confirm | yes | no | `sudo vpnctl trust commit` |
| `vpnctl trust rollback` | `operation-v1:trust.rollback` | gateway | rolls back the staged control-CA rotation | confirm | yes | no | `sudo vpnctl trust rollback` |
| `vpnctl log status` | `status-v1:log.status` | gateway/node | none | none | no | no | `sudo vpnctl log status` |
| `vpnctl log enable <scope>` | `operation-v1:log.enable` | gateway/node | scope is `control`, `transport`, `routing`, `dns`, `tunnel`, `ingress`, or `all`; required `--level`, `--for`; optional `--file` | none | yes | no | `sudo vpnctl log enable ingress --level trace --for 10m` |
| `vpnctl log disable <scope>` | `operation-v1:log.disable` | gateway/node | a logging scope or `all` | none | yes | no | `sudo vpnctl log disable all` |
| `vpnctl backup [archive-path]` | `artifact-v1:backup` | gateway | optional output path; passphrase and confirmation via hidden prompts | none | yes | no | `sudo vpnctl backup /srv/backups/vpnctl.backup` |
| `vpnctl restore <archive-path>` | `operation-v1:restore` | all | required `--public-ip <IPv4>`; optional `--replace` on an initialized gateway; passphrase via hidden prompt | confirm | yes | no | `sudo vpnctl restore vpnctl.backup --public-ip 203.0.113.10` |
| `vpnctl update [version]` | `operation-v1:update` | gateway/node | optional stable version; omitted means latest stable | confirm+typed-if-irreversible | yes | no | `sudo vpnctl update 2.1.0` |
| `vpnctl update rollback` | `operation-v1:update.rollback` | gateway/node | no arguments | confirm | yes | no | `sudo vpnctl update rollback` |
| `vpnctl uninstall` | `operation-v1:uninstall` | gateway/node | gateway optional `--force`; node optional `--local-only` | confirm | yes | no | `sudo vpnctl uninstall --local-only` |
| `vpnctl purge` | `operation-v1:purge` | gateway/node | optional gateway `--include-backups` with a second typed confirmation | typed | yes | no | `sudo vpnctl purge --include-backups` |

## Deliberate omissions and simplifications

- There is no repeated `--gateway`, `--node`, node target, DNS scope, or transport status argument after initialization. Host role and current node identity supply that context.
- There is no `invite list`, `node status`, `transport status`, incremental `policy add/remove`, transport enable/disable, or automatic fallback command. Their behavior is covered by `status`, full policy replacement, and explicit test/switch operations.
- Public certificate commands use `cert`; internal control-CA lifecycle uses `trust`, so rotating webhook trust cannot accidentally rotate node identity trust.
- `expose list` never creates a certificate export; `expose show` idempotently refreshes the public-only gateway copy when reachable. Offline inspection keeps local non-secret expose state visible with unknown certificate availability.
- `expose remove` stops the selected public route, waits the fixed ten-second drain bound, removes only its tunnel mapping, and releases its port. Its `remove_external_webhook` action intentionally has no command because external registration remains application/operator-owned.
- Handshake-host replacement is nested under `transport host` because it is restricted-transport state, not a general DNS or certificate setting.
- v1 migration remains a standalone one-time script and therefore is not part of this command registry.
