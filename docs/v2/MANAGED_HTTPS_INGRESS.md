# Managed HTTPS ingress

This document records the provider-neutral expose contract. nginx consumes the
normalized model later; no nginx directive, frp name, or provider-specific
address is part of the public request grammar.

## Expose identity and upstream

Every expose receives an immutable collision-checked UUID. Its optional name is
case-insensitively unique within one node; another node may use the same name.
Names remain reserved while a disabled expose record exists, avoiding ambiguous
`show`/`remove` resolution.

The public upstream grammar is either a decimal port or `host:port`. A port
shorthand such as `3000` canonicalizes to `127.0.0.1:3000`. Canonical IPv4,
bracketed IPv6, `localhost`, and DNS hostnames are supported. Loopback is the
safe default. Any other address requires `--allow-non-loopback` and produces an
explicit warning; unspecified, multicast, mapped-IPv6, malformed, and
out-of-range endpoints are rejected.

## Paths and overlap

Routes are exact by default. `--prefix` requests subtree semantics and requires
an explicit path. Prefix `/api` matches `/api` and `/api/...`, but not `/apiv2`;
the canonical stored prefix has no trailing slash except root. Two routes
conflict whenever one request path could select both, including exact-inside-
prefix and ancestor/descendant prefix pairs. The check is symmetric and global
across active gateway routes. Disabled routes are not published and therefore
do not reserve a public path, but they retain identity, name, and tunnel-port
ownership until removal.

User paths are normalized ASCII HTTP paths without query, fragment, percent
escaping, backslashes, duplicate slashes, or dot segments. The exact
`/.well-known/vpnctl` root and all descendants are permanently reserved for
enrollment, recovery, and health endpoints.

When `--path` is omitted, vpnctl creates an exact `/hooks/<token>` route from
32 bytes (256 bits) of kernel CSPRNG entropy encoded as unpadded base64url. It
checks the complete active exact/prefix namespace and retries at most 32 times;
entropy failure or exhaustion fails closed without allocating state.

Normalization is a read-only plan step. It records expected state generation,
immutable identity, canonical upstream/path, non-loopback warning, and resolved
safe limits, but does not allocate the gateway tunnel port, persist state, or
contact the gateway. Those operations belong to the creation saga after the
remaining ingress contracts are implemented.

## Hard limits and expose overrides

The versioned measured gateway contract is provider-neutral: 256 edge
connections, 64 concurrent gateway requests, 64 HTTP/2 streams, 40 concurrent
requests per expose, an 8 MiB body ceiling, four 8 KiB large-header buffers, and
a 10-second graceful shutdown bound. An expose defaults to a 1 MiB body and a
15-second upstream timeout; the timeout ceiling is 60 seconds.

Only `--body-limit` and `--timeout` are public overrides. Body values accept
integer bytes or binary `KiB`/`MiB` units; timeout accepts a whole number of
seconds, a `s` duration, or `1m`. Both may narrow or widen the expose default but
cannot exceed the gateway hard ceiling. Per-expose concurrency, gateway totals,
HTTP/2 streams, buffers, retry, and shutdown behavior have no override.

The option parser is a strict whitelist. Duplicate/unknown options, fractional
or zero values, overflow, shell/directive separators, and names such as
`--proxy-read-timeout` or `--nginx-directive` fail before identity entropy,
state mutation, or provider rendering. A future limit change requires a new
versioned measured contract rather than an untracked configuration edit.

## Selected nginx renderer

The first provider pins Ubuntu nginx `1.24.0-2ubuntu7.17` and its accepted
`listen ... ssl http2` syntax. Rendering is pure and deterministic: canonical
state, expose records, public certificate/key paths, and an owned runtime path
produce one complete three-file candidate tree. All files are root-only and
the candidate hash covers relative path, mode, and content. The candidate is
not JSON-serializable because route and filesystem paths can be sensitive.

The public listener is IPv4 `443/TCP` only. It accepts TLS 1.2/1.3 and
HTTP/1.1 plus at most 64 concurrent HTTP/2 streams; there is no UDP, QUIC,
HTTP/3, WebSocket upgrade, client mTLS, domain, or ACME configuration. Every
published route proxies over HTTP/1.1 to its persisted
`127.0.0.1:<TunnelPort>` endpoint. The node application's upstream address is
never rendered on the gateway. `proxy_pass` has no URI suffix, preserving the
request method, normalized path, query, headers, and streaming body.

Exact paths compile to exact nginx locations. A segment-prefix `/api` compiles
to an exact `/api` location plus a `^~ /api/` location, so `/apiv2` cannot
match. Disabled exposes are absent; pending, ready, and degraded records remain
publishable while later saga/readiness work controls their lifecycle. A root
prefix replaces the ordinary `404` fallback without producing a duplicate
location.

The common proxy policy disables request/response buffering, response temp
files, storage, caching, redirect rewriting, and upstream retries. It clears
`Forwarded`, non-authoritative `X-Forwarded-*`, Upgrade, Connection, and TE,
then derives trusted address/protocol/host/port fields from the accepted
connection. Authorization and ordinary application/provider headers continue
to the application, while access and error logging remain off by default.

Each selected request has exactly one loopback `proxy_pass` target. Both
`proxy_next_upstream off` and a one-attempt ceiling prevent a failed POST from
being sent again; tunnel reconnect affects only later requests. nginx has no
application request queue: gateway/expose connection overflow is rejected with
`503`, and the sole enrollment rate limit uses `nodelay`. Backpressure is
carried to the client instead of spilling a request or response body to a temp
file.

Before an upstream response starts, an nginx/tunnel `502` is internally
translated to a fixed no-store JSON `503`, while a proxy timeout produces the
same fixed form with `504`. The named handlers are internal `return` locations
with no `proxy_pass`, so translation cannot create a second upstream attempt.
`proxy_intercept_errors` remains off: an explicit `502` or `504` response that
the application itself starts is not mistaken for a transport failure. Body
excess is rejected as `413`, and an unknown public path remains `404`.

Once upstream headers have been sent downstream, status replacement is no
longer possible. With response buffering disabled, a later tunnel/upstream
failure truncates and closes that downstream response; it never emits a second
status or replays the request. The opt-in native fault gate covers synthetic
nonce-bearing POSTs for pre-header abort, timeout, partial `200`, application
`502`, and body excess. Every admitted nonce reached the upstream exactly once,
the rejected body reached it zero times, the partial response ended with an
unexpected EOF, and both temp directories remained free of body files.

Both gateway and expose limits are repeated in every proxy location to avoid
nginx's child-limit inheritance trap. One 64 KiB expose zone is keyed by the
immutable expose UUID assigned inside the selected location; this enforces one
cap across both locations of a prefix route without allocating a fixed zone
per possible expose. Since the gateway admits at most 64 concurrent requests,
the shared zone contains only a bounded active-key set even when many inactive
routes exist.

Provider validation first requires the exact runtime version `1.24.0`, then
runs only `nginx -t -p <candidate-root>/ -c nginx.conf` against an already
staged tree. The activation transaction below owns staging, graceful reload,
drift handling, and rollback. The Ubuntu native parser accepted the task 12.4
tree; deployed Telegram compatibility remains deferred to task 16.11.

## Atomic tree activation

The gateway owns `/etc/vpnctl/generated/gateway/ingress`. Immutable complete
trees live under `generations/g<state-generation>-<tree-hash>` and the only
live selector is a relative `current` symlink. The state generation is
provenance; the hash covers every relative file path, mode, and byte. The
runtime path is the separate `/run/vpnctl-ingress`, keeping nginx worker paths
out of the controller's root-only `/run/vpnctl` namespace. Activation itself is
serialized by a root-only lock in `/run/vpnctl`.

Apply rejects an unsafe current link, a missing/unexpected entry, a symlink or
mode change inside the active tree, content/hash drift, a stale generation, or
different content at the same state generation before invoking nginx. It then
creates a same-filesystem private staging directory, writes every artifact with
no-follow/exclusive creation, fsyncs files and directories, verifies the tree
hash, runs pinned `nginx -t`, and verifies the hash again. Only after those
checks does one atomic symlink rename publish the complete generation.

An initial tree is left for the service lifecycle to start. A later changed
tree is already selected when `nginx -p <current>/ -c nginx.conf -s reload`
requests nginx's graceful worker handoff. A content-identical state-generation
advance switches provenance without an unnecessary reload. Successful change
removes only the previously validated owned tree.

If reload fails, vpnctl atomically restores the prior link and performs an
independent 15-second rollback reload of that exact tree. A successful rollback
removes the failed generation. If the rollback reload itself fails, both exact
trees remain and normal idempotence is disabled: the sole inactive newer tree
is a recovery snapshot, and only an explicit retry of that same generation and
hash may reconcile it. Stale staging entries, multiple inactive generations,
or a different requested candidate fail closed for later reconciliation.

## Reserved public namespace

The edge owns exact `/.well-known/vpnctl/enroll`,
`/.well-known/vpnctl/recover`, and `/.well-known/vpnctl/health` locations before
rendering any user expose. Enrollment and recovery share one fixed
`127.0.0.1:19092` HTTP/1.1 handler upstream; the handler remains private and
performs the authoritative path, method, query, token, body, and concurrency
checks. nginx adds a shared 64 KiB per-source request-rate zone, a four-request
burst, the 64 KiB body ceiling, and five-second upstream bounds.

Health is an nginx-owned, body-free `204` with no state or dependency details.
It allows ingress diagnostics to test the public-IP certificate, TLS listener,
and selected nginx generation without invoking enrollment or any real webhook.
The slashless namespace root and every otherwise unknown descendant return the
same fixed no-store JSON `404` before user routing.

Exact nginx locations win before the reserved `^~` subtree guard, and that
guard wins before every user prefix. Consequently even a valid user prefix
`/` can handle ordinary unmatched requests but can never shadow a vpnctl
reserved endpoint. The renderer also rejects a corrupt expose that attempts to
reuse loopback port `19092`.

## Creation transaction

Expose planning on a joined private node is read-only. The authoritative
gateway checks the active node identity, its global expose namespace, and
unavailable internal ports, then returns only the new node-owned plan, assigned
port, public IPv4, and public-certificate metadata. Existing webhook paths from
other nodes never cross this boundary. The generated path-bearing plan cannot
be serialized. A stale node/gateway generation, remapped persisted port,
inactive identity, route conflict, or certificate mismatch fails before either
host is changed.

Immediate creation then uses this strict order:

1. the gateway exports the public certificate and reserves the exact expose as
   authoritative `pending`, but does not render it into public ingress;
2. the node atomically activates its complete tunnel topology with the added
   mapping and persists the same expose as locally pending;
3. readiness must match the exact tunnel candidate and expose generation, with
   configuration, active connection, mapping set, and mapping registration all
   ready;
4. an available upstream yields `ready`; an unavailable local application is
   intentionally accepted as `degraded`, with public requests returning `503`;
5. the gateway publishes the HTTPS route last and commits the effective state,
   after which the node records the final gateway generation.

A known failure before publication reapplies the complete prior tunnel
topology, removes only the exact gateway reservation, and advances node state
through a compensating generation. A lost/ambiguous gateway response or a
node-state failure after publication is reported as uncertain and is not
blindly rolled back; later convergence owns that case.

`--defer` performs only the authoritative gateway pending registration. It
does not change node state, reload the tunnel, or publish ingress. The eventual
apply path reuses the same ordered transaction.

The normal human result shows the public URL, public-certificate export path
and fingerprint, and a copy-ready `scp` command. The URL is held in a dedicated
human-only sensitive-path field: JSON and generic result formatting contain no
webhook path or derived URL. JSON receives only safe identities, generations,
effective state, certificate metadata, and the SCP hint.
