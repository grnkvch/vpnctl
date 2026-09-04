# Controller-outage fault injection

The gateway controller is a management process, not a forwarding-process
supervisor. Applied standard and restricted transports, routing, DNS, reverse
tunnels, and HTTPS ingress have independent lifecycles and immutable-at-
generation configurations. A controller outage makes management unavailable;
it does not apply, repair, restart, or rewrite the data plane.

The reverse-tunnel authorization endpoint follows the same boundary. It is
co-supervised with `frps` by `vpnctl-tunnel-server.service`, starts before the
provider child, and reads authoritative state and root-only credentials for
every `Login`, `NewProxy`, and `Ping`. It is therefore available during a
controller restart while remaining fail-closed on unreadable state or
credentials.

Run the repeatable local fault suite with:

```bash
go test ./internal/cli ./internal/tunnel ./internal/controller \
  ./internal/platform/linux ./internal/regression \
  -run 'TestControllerOutage|TestGatewayTunnel|TestRenderGatewayRoleInstallation|TestSystemUnitObserver|TestControllerAndTunnelAuthorization' \
  -count=5
```

The suite starts a real controller on a temporary root-only Unix socket plus
six independently owned forwarding subprocesses. It records each data-plane
PID and exact configuration bytes/SHA-256, verifies forwarding, stops the
controller, and requires a JSON `gateway_unavailable` management result. It
then verifies all forwarding endpoints and snapshots again, restarts the
controller, and repeats the checks. PIDs, configuration bytes/hashes, and the
authoritative generation must remain unchanged across all three phases.

Additional contracts verify that controller startup performs passive
observation only, every rendered gateway data-plane unit is free of a
`vpnctl-controller.service` dependency, and the tunnel entrypoint owns both
authorization and `frps`. The suite uses only Go-owned temporary paths and
loopback listeners; it does not mutate systemd or host/VM networking.
