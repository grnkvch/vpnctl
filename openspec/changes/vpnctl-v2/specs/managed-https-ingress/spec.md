## Purpose

Defines a bounded IP-only HTTPS edge that publishes explicit private-node HTTP applications for webhook and ordinary API requests without becoming a general application gateway.

## ADDED Requirements

### Requirement: IP-only HTTPS endpoint
v2.0 SHALL publish managed ingress only as `https://PUBLIC_GATEWAY_IP/<path>` on `443/TCP`. Domain-based ingress, ACME, HTTP/3, `443/UDP`, generic TCP/UDP ingress, WebSocket, SSE, and gRPC guarantees SHALL not be part of v2.0. The authoritative expose model SHALL remain implementation-neutral so domain certificates can be added later without changing expose identity.

#### Scenario: Telegram webhook endpoint
- **WHEN** the gateway public IP is `203.0.113.10` and an expose uses `/telegram/webhook`
- **THEN** vpnctl reports `https://203.0.113.10/telegram/webhook` as the public URL

### Requirement: Private-node expose creation
`vpnctl expose <port|host:port>` SHALL run on a joined private node. A port-only value SHALL normalize to `127.0.0.1:<port>`; a non-loopback address SHALL require `--allow-non-loopback` and a warning. An optional unique node-local name SHALL label the immutable expose ID. Creating an expose SHALL require gateway availability but no confirmation after validation and SHALL apply immediately unless `--defer` is supplied.

#### Scenario: Port shorthand
- **WHEN** the operator runs `vpnctl expose 3000 --path /telegram/webhook`
- **THEN** vpnctl creates an expose whose local upstream is `127.0.0.1:3000`

#### Scenario: Non-loopback without opt-in
- **WHEN** an expose targets a non-loopback host without `--allow-non-loopback`
- **THEN** vpnctl rejects it before registering gateway state

### Requirement: Exact paths by default
An expose SHALL use an exact path by default; `--prefix` SHALL explicitly request subtree matching. If no path is provided, vpnctl SHALL generate a unique high-entropy exact path. Ambiguous or overlapping routes SHALL be rejected, and the `/.well-known/vpnctl/` namespace SHALL be reserved for vpnctl internal endpoints.

#### Scenario: Overlapping prefix
- **WHEN** a requested prefix overlaps an existing exact or prefix route ambiguously
- **THEN** creation fails without changing either route

### Requirement: Stable public ingress certificate
Gateway initialization SHALL generate a stable self-signed RSA-2048/SHA-256 public certificate whose public IPv4 appears as an IP-type SAN and, for compatibility, in the CN. Its default lifetime SHALL be five years subject to the deployed-service Telegram compatibility gate. The private key SHALL remain root-only; `cert export` SHALL copy only the public certificate, defaulting to `/var/lib/vpnctl/exports/gateway.crt`.

#### Scenario: Export public certificate
- **WHEN** the operator runs `vpnctl cert export`
- **THEN** a public PEM certificate is written at the managed path and no private key is included or printed

### Requirement: Staged ingress-provider acceptance
Automated local development tests SHALL verify the pinned reverse proxy, RSA certificate shape and lifetime, IPv4 SAN/CN identity, TLS 1.2/1.3, HTTP/1.1/2 forwarding, and a token-safe Telegram registration harness before dependent ingress implementation continues. These tests MAY qualify the candidate for development but MUST NOT waive the v2.0 release gate. Before release, the harness SHALL run against an actually deployed gateway and node, register the exported public certificate through Telegram `setWebhook`, verify a real incoming request, and remove only the registration it created. Bot tokens MUST NOT be accepted through argv, environment variables, files, logs, or JSON output.

#### Scenario: Local ingress candidate passes
- **WHEN** all automated local ingress checks pass without contacting Telegram
- **THEN** dependent implementation may continue while the provider acceptance remains pending and nginx is not described as production-ready

### Requirement: Public certificate inspection and manual rotation
Gateway-only `cert show` SHALL display public IP, fingerprint, validity, and expiration warnings. `cert rotate` SHALL be manual-only, require confirmation, show all affected exposes, allow short downtime, issue a new public certificate, and return a required-action list to re-register external webhooks. It SHALL not support defer or automatically contact webhook providers.

#### Scenario: Rotate certificate with active webhooks
- **WHEN** the operator confirms rotation while exposes exist
- **THEN** all exposes use the new certificate and the result identifies every external webhook registration requiring update

### Requirement: TLS and HTTP protocol boundary
Public ingress SHALL accept only TLS 1.2 and 1.3 and SHALL not require client mTLS. It SHALL support HTTP/1.1 and HTTP/2 through ALPN with a bounded concurrent-stream limit; the internal proxy hop to the application SHALL use HTTP/1.1. TLS SHALL terminate on the gateway, while path, query string, request method, selected application headers, and streaming body SHALL reach the upstream without application-level rewriting.

#### Scenario: Obsolete TLS client
- **WHEN** an ingress client offers only TLS 1.0 or 1.1
- **THEN** the gateway rejects the TLS session before forwarding a request

### Requirement: Forwarding header safety
The gateway SHALL remove untrusted inbound forwarding headers and construct trusted proxy headers from the actual connection. Authorization headers and provider-specific application headers SHALL be forwarded when needed by the application but MUST NOT be recorded by vpnctl logging.

#### Scenario: Spoofed client address header
- **WHEN** an external request supplies a forged forwarding header
- **THEN** the upstream receives vpnctl's trusted connection-derived value rather than the untrusted one

### Requirement: Bounded proxy limits
Ingress SHALL enforce gateway hard limits for connections/requests, headers, request bodies, and timeouts. Every expose SHALL receive safe defaults and SHALL only override supported implementation-neutral parameters, including body size and upstream timeout, within gateway hard limits. Raw reverse-proxy directives, WAF, CAPTCHA, and per-IP rate limiting SHALL not be accepted.

#### Scenario: Expose exceeds hard body limit
- **WHEN** an expose requests a body-size override above the gateway maximum
- **THEN** validation fails and the active proxy configuration remains unchanged

### Requirement: Streaming stateless forwarding
The gateway SHALL stream request and response bodies without fully buffering them in memory, queuing them, persisting bodies to disk, or retrying an upstream request after tunnel failure. Recovery SHALL affect only new requests, preventing automatic duplication of non-idempotent webhook or API calls.

#### Scenario: Tunnel fails after upstream starts response
- **WHEN** the upstream response has started and the tunnel then breaks
- **THEN** the gateway closes the downstream connection and does not synthesize a replacement status or replay the request

### Requirement: Observable ingress outcomes
An unknown path SHALL return `404`; an unavailable tunnel or upstream before response start SHALL return `503`; an upstream timeout SHALL return `504`; a request beyond configured body limit SHALL return `413`. If the local application is stopped, an expose MAY remain registered as degraded and SHALL return `503` until the application becomes reachable.

#### Scenario: Application is stopped
- **WHEN** a valid expose path is requested while its local upstream is unavailable
- **THEN** the gateway returns `503` and the expose is visible as degraded

### Requirement: Application responsibility boundary
vpnctl SHALL not call Telegram Bot API, store bot tokens, register webhooks, validate Telegram secret tokens, implement application authentication, or own provider retry semantics. Paths SHALL not be treated as authentication secrets, and sensitive webhook paths SHALL not appear in JSON or diagnostic logs.

#### Scenario: Expose created for Telegram
- **WHEN** a Telegram webhook expose is ready
- **THEN** vpnctl provides URL and public certificate material while the operator or application remains responsible for `setWebhook` and request authentication

### Requirement: Expose inspection and removal
Private-node `expose list` and `expose show` SHALL report non-secret state and current gateway public certificate availability. `expose remove` SHALL require confirmation, support immediate or deferred removal, stop new routing, allow bounded drain, remove only that mapping, and return a required action to remove its external webhook registration.

#### Scenario: Remove one of several exposes
- **WHEN** the operator removes one expose from a node with multiple exposes
- **THEN** only that public route and mapping are drained and removed; the others continue serving
