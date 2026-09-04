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
