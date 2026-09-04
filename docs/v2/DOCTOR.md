# Bounded active doctor

`vpnctl doctor [dns|transport|tunnel|ingress]` is the explicit active
diagnostic boundary. Unlike passive `status`, it may emit synthetic network
traffic, but it cannot change desired state, apply or repair resources, switch
transport, register a webhook, or call a user expose path.

With no scope, `default` runs the union of the role-applicable checks. An
explicit scope runs only that scope. Plans are deterministic and every network
attempt receives a unique `<run-uuid>-<sequence>` probe ID for traffic and log
correlation.

## Role-aware checks

| Scope | Gateway | Private node |
| --- | --- | --- |
| `dns` | Every configured upstream directly over UDP and TCP; both local gateway-DNS overlay listeners over UDP and TCP | Every configured direct resolver over UDP and TCP; the trusted gateway-DNS overlay address over UDP and TCP |
| `transport` | End-to-end TCP and UDP checks for each transport kind that is active for at least one resource | End-to-end TCP and UDP checks for the local node's selected transport |
| `tunnel` | Internal tunnel-server TCP readiness and every active expose mapping | Local multiplexed session and every active expose registration through the local frp status endpoint |
| `ingress` | Public-IP TLS, `GET /.well-known/vpnctl/health`, and every active gateway tunnel mapping | Gateway public-IP TLS, the same reserved health request, every active tunnel mapping, and every active node-local upstream |

Standby and disabled transports are structurally absent from the probe plan.
Disabled exposes are also omitted. A role/resource that is legitimately not
applicable is reported as `skipped`; missing configured DNS paths are failures.

The request type has a closed kind/protocol matrix. Its only built-in HTTP path
is the constant reserved health path. User expose paths, webhook URLs, provider
API endpoints, credentials, request bodies, and desired-state/mutation handles
are not fields of a built-in request. Execution endpoints are adapter-only and
are not copied into human or JSON results.

`--probe-url <https-url>` is the sole opt-in external target. The URL must be
absolute HTTPS, must not contain userinfo or a fragment, and is held in a
redacting, non-serializable value. It is exposed to the HTTP adapter through a
narrow callback only while constructing the request. The adapter performs one
direct `GET`: no request body, cookies, authorization, client certificate,
environment proxy, or redirect following. Its only explicit header is a
`User-Agent` carrying the synthetic probe ID. A 2xx response passes; a redirect
is reported but never followed, and any other status fails the check.

When ingress diagnostics have no explicit URL, the optional third-party check
is `skipped` with `external_endpoint_unspecified` and a human explanation.
This is successful, contacts nothing, and documents that vpnctl has no hidden
telemetry or provider-operated fallback endpoint.

## Bounds and results

The default overall deadline is 30 seconds and the default per-probe deadline
is 5 seconds. Both are fixed at construction, bounded between 10 milliseconds
and 5 minutes, and a probe cannot outlive the overall context. A caller's own
cancellation is returned as cancellation rather than rewritten as a network
failure. If vpnctl's overall deadline expires, the active check fails and
unstarted checks are marked `skipped` with `overall_deadline_exceeded`.

Every result contains role, requested scope, run ID, overall state, and the
complete ordered check list with scope, safe resource identity, kind,
protocol, status, stable code, and elapsed milliseconds. Endpoints and paths
are absent. Any failed check makes the command `degraded` with the stable
`unavailable` exit category; passed and not-applicable skipped checks remain
successful. Adapter error strings are never copied into the result.
