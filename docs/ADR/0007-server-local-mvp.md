# 0007: Use Server-Local Execution For The Initial MVP

## Context

The operator wants a simple first workflow:

1. Connect to the server manually with `ssh root@server`.
2. Deliver the `vpnctl` binary to the server.
3. Run `vpnctl` directly on the server to configure WireGuard and manage
   clients.

This avoids implementing remote SSH orchestration inside `vpnctl` before the
core state and configuration model is stable.

## Decision

The initial MVP runs `vpnctl` locally on the VPN server.

For the first implementation:

- the operator connects to the server manually;
- `vpnctl` is installed or copied onto the server;
- server configuration changes are performed locally by the process running on
  the server;
- the first target server platform is Ubuntu 24.04 LTS x64;
- running as `root` is required for the first version;
- remote SSH apply from the operator machine is deferred.

## Alternatives Considered

- Run `vpnctl` on the operator machine and apply changes over SSH.
- Run a long-lived daemon or API on the server.
- Only generate configs locally and require fully manual server changes.

## Tradeoffs

Server-local execution removes the need for remote command orchestration,
remote privilege handling, SSH upload logic, and SSH quoting concerns in the
first version.

The cost is that the server must receive the `vpnctl` binary, state initially
lives on the server, and client configuration export must account for moving
artifacts from the server to client devices.

## Consequences

- The MVP does not need an SSH execution abstraction.
- Server apply commands operate on local files and local system services.
- Server checks and apply behavior can initially target Ubuntu 24.04 LTS x64,
  systemd, and the standard WireGuard package layout.
- MVP commands that need system changes should fail clearly when not run as
  root.
- Deployment of the binary becomes part of the user workflow.
- Remote SSH apply remains a future feature in the backlog.
- The implementation must still avoid changes that can break the active SSH
  session.
