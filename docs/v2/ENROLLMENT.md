# vpnctl v2 enrollment invites

This document fixes the task-9.1 invite lifecycle and task-9.2 public protocol
boundary. Node-local key generation and the cross-host join saga follow in
tasks 9.3 and 9.4; the recovery-token lifecycle follows in task 9.9.

## Issuance and persistence

`vpnctl invite <node-name>` is gateway-only. Its read-only plan validates the
name, current gateway endpoint, current control protocol, stable enrollment
fingerprint, and authoritative generation without reading randomness or
writing state. The immediate commit generates a 256-bit random secret and a
collision-checked human-readable invite ID, then advances state once.

The token is emitted only through the preflighted controlling TTY as an
`output.Secret`. It never enters the ordinary human/JSON result. Non-interactive
issuance is refused before commit, while `--dry-run` creates and displays no
token. Invite-file, URL, subscription, and QR delivery remain out of scope.

Authoritative state stores the invite ID, node name, protocol, exact endpoint,
stable enrollment fingerprint, issued/expiry timestamps, terminal state, and a
domain-separated SHA-256 of the secret. It never stores the plaintext secret or
encoded token.

## Token format

The opaque v1 form is:

```text
vpnctl-invite-v1.<base64url canonical JSON>.<base64url HMAC-SHA-256>
```

The canonical payload binds schema version, `enroll` purpose, current
control protocol, exact IP-only HTTPS enrollment endpoint, enrollment identity
fingerprint, invite ID, 256-bit secret, node name, issue time, and expiry. Both
base64url values are unpadded and canonical. The HMAC detects accidental or
unmodified-secret payload tampering; the authoritative security check is the
constant-time secret-hash comparison plus exact comparison with every stored
metadata field. A token is also rejected if its endpoint, identity fingerprint,
or protocol is no longer accepted by the current gateway.

## Lifecycle and status

Persisted states are `active`, `cancelled`, and `consumed`. Expiry is derived:
an active invite is valid only while `issued_at <= now < expires_at`, with
`expires_at` exactly 15 minutes after issuance. At the exact expiry instant it
is invalid and cannot mutate state. Successful consumption is terminal, so a
second presentation is a replay and advances no generation.

The status projection deliberately omits the secret hash. General status will
use the active-only projection so only active, unexpired invite IDs, node names,
protocols, endpoints, and timestamps appear. The full internal projection can
distinguish derived `expired`, `cancelled`, and `consumed` records for future
diagnostics without revealing authentication material.

`vpnctl invite cancel <invite-id>` needs no confirmation. It immediately moves
an unused invite to terminal `cancelled`; repeated and concurrent duplicate
cancellation returns successful `changed=false` without another generation.
Cancellation of a consumed invite is rejected with an explicit direction to
revoke the enrolled node instead. A consumed invite continues to reserve its
node name until the corresponding immutable node record exists; cancelled and
expired unused invites do not prevent a fresh explicit issuance.

## Reserved public protocol

The public edge reserves exactly `/.well-known/vpnctl/enroll` and
`/.well-known/vpnctl/recover` ahead of user expose routes. nginx terminates the
ordinary public HTTPS connection on `443/TCP` and forwards only those paths to
the enrollment handler; the handler does not open another public listener and
does not expose a general management API. Its upstream contract is POST over
HTTP/1.1 with `application/json` and no query string.

Enrollment and recovery are separate protocol purposes and token namespaces:
`vpnctl-invite-v1` is accepted only with `purpose=enroll` on the enrollment
path, while `vpnctl-recovery-v1` is accepted only with `purpose=recover` on the
recovery path. A wrong path, purpose, prefix, unknown route, malformed token,
unknown token, terminal token, or replay returns the same fixed `404` response.
This avoids turning the endpoint into an invite-status oracle. Recovery routing
is implemented now, but issuing and authoritatively validating recovery tokens
remains task 9.9.

The request envelope contains schema version 1, purpose, the one-time token, a
canonical unpadded-base64url 128-bit node nonce, and one bounded JSON object.
The token is immediately wrapped in the non-serializable secret type and is
never logged or returned. Requests inherit the control-plane ceilings: 64 KiB
body, 8 KiB headers, JSON depth 32, five-second handler deadline, and at most 16
concurrent sessions. The public response is at most 256 KiB and always carries
`Cache-Control: no-store`; nginx supplies the edge read/header/idle bounds and
rate enforcement when the reserved routes are integrated in section 12.

## Signed response and atomic consumption

The gateway creates an independent non-zero 128-bit nonce for each accepted
request. The prepared transaction supplies a JSON response object plus all
public facts needed for the canonical transcript. The handler refuses to sign
unless purpose, exact IP-only endpoint, both nonces, 15-minute validity window,
and enrollment-key fingerprint match the authenticated transaction.

The `vpnctl-enrollment-transcript-v1` payload is a deterministic sequence of
32-bit big-endian length-prefixed name/value frames. It binds purpose, invite or
recovery ID, exact endpoint, immutable node ID, issue/expiry times, both nonces,
selected transport, canonical preset set, sorted named SHA-256 key/CSR hashes,
and normalized assignment SHA-256. The Ed25519 JSON envelope contains schema
version, algorithm, the `sha256:<DER-SPKI>` enrollment fingerprint, canonical
transcript bytes, and signature; binary values are canonical unpadded
base64url. The response exposes the gateway nonce so the node can reconstruct
the expected transcript, byte-compare it, verify the pinned key, enforce at
most 120 seconds of clock skew, and reject `now >= expires_at`.

The complete response is validated, signed, bounded, and serialized before the
transaction can commit. Commit stores the domain-separated transcript/signature
replay SHA-256 and moves the one-time invite to `consumed` in the same
compare-and-swap state generation. Exactly one concurrent presentation can
win; all stale authorizations and later replays fail without another state
transition. Invalid or oversized prepared responses are never consumed.
