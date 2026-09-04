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
immutable identity, canonical upstream/path, and non-loopback warning, but does
not allocate the gateway tunnel port, apply limits, persist state, or contact the
gateway. Those operations belong to the creation saga after the remaining
ingress contracts are implemented.
