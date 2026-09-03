# vpnctl v2 enrollment invites

This document fixes the task-9.1 invite boundary. The public enrollment HTTP
handler and signed enrollment transcript are added in task 9.2; node-local key
generation and the cross-host join saga follow in tasks 9.3 and 9.4.

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

The canonical payload binds schema version, `node-enrollment` purpose, current
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
