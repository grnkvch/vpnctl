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
