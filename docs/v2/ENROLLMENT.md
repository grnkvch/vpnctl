# vpnctl v2 enrollment invites

This document fixes the task-9.1 invite lifecycle, task-9.2 public protocol
boundary, task-9.3 node-owned credential boundary, task-9.4 initial join saga,
task-9.5 joined-node idempotency and gateway inspection, and task-9.9
same-node break-glass recovery.

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
uses the same bounded handler through a purpose mux, while issuance,
authorization, proof verification, and consumption remain separate from the
ordinary enrollment coordinator.

The request envelope contains schema version 1, purpose, the one-time token, a
canonical unpadded-base64url 128-bit node nonce, and one bounded JSON object.
The token is immediately wrapped in the non-serializable secret type and is
never logged or returned. Requests inherit the control-plane ceilings: 64 KiB
body, 8 KiB headers, JSON depth 32, five-second handler deadline, and at most 16
concurrent sessions. The public response is at most 256 KiB and always carries
`Cache-Control: no-store`; nginx supplies the edge read/header/idle bounds and
rate enforcement when the reserved routes are integrated in section 12.

## Node-owned credential material

Before enrollment, the node creates four independent generation-scoped
credential domains locally: an Ed25519 control private key and signed PKCS#10
CSR, a WireGuard private/public key pair, a 256-bit restricted-transport
identity credential, and a 256-bit reverse-tunnel credential. The four private
values are published only to owner-create-only references in the node's
mode-`0700` secret tree as mode-`0600` files. A failed or cancelled preparation
removes only the references created by that attempt and never replaces or
deletes a pre-existing value.

The strict schema-version-1 public exchange contains only the immutable node
ID, credential generation, canonical CSR PEM, canonical WireGuard public key,
and exactly four named SHA-256 commitments. The CSR must be Ed25519-signed and
request only the authoritative `urn:vpnctl:node:<uuid>` URI SAN. Unknown,
duplicate, non-canonical, oversized, identity-mismatched, or hash-mismatched
fields are rejected. Credential-reference and installation aggregates cannot
be serialized through ordinary JSON formatters.

The gateway needs the restricted and tunnel values because those are shared
authentication credentials. The node can expose exactly those two values to
the join coordinator only as a short-lived non-serializable secret
payload whose bytes must match the public commitments. There is no equivalent
path for the control or WireGuard private key: only their CSR/public key can
leave the node. Join carries the secret payload inside the authenticated HTTPS
enrollment transaction and publishes only public values, hashes, and opaque
references in authoritative gateway state.

## Initial join saga

`vpnctl join <standard|restricted> [preset...]` is node-only and accepts the
invite exclusively through the common hidden controlling-terminal input. Its
read-only CLI plan validates the explicit transport and present preset array;
key generation and network exchange begin only after availability-impact
confirmation. There is no automatic transport choice and no implicit preset.

The node must be initialized and have no joined identity. It allocates a fresh
UUID, stages its four generation-1 credentials locally, and sends a canonical
secret request containing the public exchange plus only the committed
restricted/tunnel values. A proven gateway rejection removes only credentials
created by that attempt. Unknown gateway presets are rejected before any
readiness call or gateway secret write, leaving the invite active and both
authoritative states without a node.

The gateway compares the authenticated invite generation, reserves the exact
case-insensitive name and immutable ID, allocates the next node-pool address,
and resolves requested names only against its applied effective presets. It
loads exactly one active control CA, issues the node leaf from the submitted
CSR, derives the gateway WireGuard public key, and returns only the restricted
server credential needed by the node—not the gateway ShadowTLS bootstrap
credential. Both standard and restricted records are built; the explicit
choice is active and the other is standby.

Before commit, the mandatory readiness boundary must report gateway staging,
control mTLS, standard transport, restricted TCP/UoT, and reverse tunnel as
healthy for the complete candidate. A missing result fails closed. After that
gate, the gateway owner-creates the node control certificate, restricted
identity, and tunnel token, then consumes the invite and appends the node,
optional explicit policy, both transports, and certificate in one validated
compare-and-swap state generation. A proven state-write failure removes only
the secrets created by that transaction. A write whose outcome cannot be
proven is retained for reconciliation rather than risking deletion of a
committed identity.

The signed response binds the assigned name/ID/IP, active transport, canonical
preset names and effective selectors, control protocol and trust roots,
handshake-host identity/version, gateway state generation, and exact hashes of
all delivered material. The node pins the enrollment DER-SPKI fingerprint from
the invite, reconstructs the transcript, verifies the CA and leaf profile plus
CSR public-key equality, and commits one local generation containing gateway
trust, both transports, the optional policy, and public certificate metadata.
The CA, enrollment public key, node certificate, and restricted server
credential use owner-create-only local references. Node control and WireGuard
private keys never have a gateway storage path.

This is a reconcilable saga, not distributed consensus. Once the gateway has
committed, a lost, malformed, or locally unpersistable response is explicitly
`uncertain`: node credentials are retained and no local authoritative node is
invented. The ordinary already-joined no-op does not claim to resolve that
ambiguous first-join outcome; retained material remains available to an
explicit repair/recovery workflow instead of being destructively deleted.
Pre-commit validation and readiness failures are definitive and roll back the
fresh node credentials immediately.

## Joined-node behavior and gateway inspection

Both join planning and apply first validate the local authoritative role and
identity. If the node is already joined, they return the typed
`ErrNodeAlreadyJoined` result with an explicit direction to
`vpnctl transport switch <standard|restricted>`. The check occurs before key
generation or any public gateway request. It neither consumes the supplied
invite input nor changes local/gateway generation, credential bytes, active
transport, or policy. A repeated join is therefore a safe rejection, not a
second enrollment attempt and never an implicit transport switch.

On a gateway, `node list` and `node show <name-or-id>` load and validate one
authoritative snapshot. Show accepts an exact immutable ID or a
case-insensitive name; list is stable by case-folded name and then ID. Deleted
records are not visible. The public node projection contains lifecycle,
overlay address, assigned presets and policy generation, manual active
transport plus safe transport protocol/port/state metadata, and current
control-certificate fingerprint/expiry. It deliberately excludes secret and
certificate references, config hashes, WireGuard public keys, all private or
shared credential bytes, tokens, and idempotency records.

Multiple nodes append independent immutable IDs, node-pool addresses, control
certificates, WireGuard peer keys, restricted identities, tunnel tokens,
transport records, and optional policies. A node-local store contains exactly
its own identity resources; the gateway retains only the public/as-required
shared half for that node. No node may adopt another node's reference or
credential during enrollment.

## Revocation and deletion

`vpnctl node revoke <name-or-id>` is a gateway-only, confirmed, immediate
security action with no deferred mode. Its plan binds the immutable node ID,
credential generation, affected expose IDs, exact gateway credential
references, and authoritative state generation without serializing that
layout. Commit first moves the node to `revoked`, disables both transport
records, and moves every owned expose to `disabled` in one state generation.
It deliberately retains the node, policy, transports, certificate metadata,
disabled exposes, address, and revocation time for diagnosis.

After the state commit, the gateway runtime must exhaustively confirm control,
WireGuard, restricted TCP, reverse-tunnel, and expose-mapping termination. The
gateway then removes its node certificate copy, restricted identity, and
tunnel token. Missing runtime confirmation or failed file cleanup returns a
pending repair action but never restores active authority. Control
authorization reloads lifecycle state per request, standard and restricted
renders omit every disabled/non-active identity, and the tunnel credential is
removed; an offline node therefore cannot regain a path merely by reconnecting
with its old generation. A repeated revoke advances no generation but repeats
runtime reconciliation and credential cleanup safely.

`vpnctl node delete <name-or-id>` is separately confirmed and is rejected
until the record is revoked. It does not contact or mutate the private VPS.
The gateway changes the retained record to `deleted`, clears assigned presets,
and removes its policies, transports, exposes, node certificates, and any
remaining credential files in one state transition plus runtime cleanup.
Other nodes and their credentials/configuration are preserved. Deleted records
remain as immutable lifecycle tombstones in authoritative state but are hidden
from ordinary `node list/show`.

## Full credential rotation

`vpnctl node rotate` runs only on the joined private node and requires explicit
confirmation. Its read-only plan binds the exact local state, immutable node
identity, active transport, current gateway generation, and the single next
credential generation. Apply durably records a request ID before generating a
new control key/CSR, WireGuard key pair, restricted identity, and reverse-
tunnel token locally. The asymmetric private keys never cross the node
boundary; the gateway receives only the public CSR/key plus the two necessarily
shared symmetric values through non-serializable callback-scoped aggregates.

The gateway verifies the authenticated active node and expected generation,
issues a new control leaf under the existing CA, prepares both transport
records and tunnel authorization, and records the request result in bounded
idempotency history. Gateway and node runtimes stage the complete new set next
to the old set. Both must report control, standard, restricted, and tunnel
readiness before either side may publish the next authoritative generation.
The manually selected active transport, node ID/name/overlay address, policy,
presets, and every expose remain unchanged; rotation never implies a transport
switch.

Before the gateway commit, any generation, staging, validation, health, or
parallel-activation failure rolls back only attempt-owned generation files and
runtime candidates, clears the pending request as failed, and leaves the
complete old generation active. After the gateway confirms the new generation,
the node converges to new rather than attempting an unsafe generation rollback.
A known transient local state-write failure is retried and reconciled; an
ambiguous outcome retains both generations and the request ID for inspection.
After both states select the new generation, node and gateway drain the old
generation concurrently under one 30-second default deadline, then remove its
control, standard, restricted, tunnel, and leaf-certificate files. Drain or
cleanup failures return explicit repair actions while the complete new set
stays active.

### Node certificate warning and expiry boundary

Node control leaves use one shared lifecycle calculation on both gateway and
private-node state. Before `not_after - 180 days` the certificate is
`healthy`. At the exact 180-day boundary it becomes `expiring`; `status` and
the control-certificate part of `doctor` emit `node_certificate_expiring` plus
the required `sudo vpnctl node rotate` action. The certificate remains usable,
the doctor check still passes, and an otherwise healthy command retains the
success exit category. There is no automatic node-certificate renewal.

At `now >= not_after` the condition is `expired`, doctor reports a failed
control-certificate check, and the focused status result is degraded. Ordinary
rotation is then unavailable because its authenticated mTLS prerequisite can
no longer be assumed. The node-side rotation plan, the pre-apply boundary, and
gateway request preparation all enforce the same exact cutoff. A plan made
before expiry but confirmed at or after expiry creates no operation, key, state
generation, or runtime candidate.

Recovery preserves the existing immutable identity and is deliberately a
two-host action: first run `sudo vpnctl node recover <node-id>` on the gateway
to issue the one-time token, then run `sudo vpnctl node recover` on the original
private node and enter that token through hidden input. The status/doctor
projection exposes only node/certificate identifiers, fingerprint, generation,
expiry and warning metadata; it has no credential-reference, token, private-key,
or public enrollment path.

## Same-node break-glass recovery

Gateway recovery-token issuance is confirmed, immediate, and available only
for an existing `active` node at or after the exact expiry of its current
control leaf. It is not a second enrollment path: a deleted name/ID is not
visible, a revoked node is ineligible, and an unexpired node must use ordinary
`node rotate`. The gateway stores a purpose-separated `rec-*` record containing
the immutable node ID, current credential generation, and expired leaf
fingerprint. The canonical `vpnctl-recovery-v1` token binds those fields, the
reserved IP-only recovery endpoint, stable enrollment fingerprint, protocol,
the issuing gateway generation, and an independent 256-bit secret. Its validity
is exactly 15 minutes and it is invalid at `now >= expires_at`. Any intervening
gateway mutation makes the conservative generation-bound token stale; the
operator must explicitly issue another one.

The token is necessary but not sufficient. The original node reads its current
generation control private key locally and signs a domain-separated recovery
proof. That proof binds the recovery ID, a fresh 128-bit node nonce, immutable
node ID, exact current/next generations, unique request ID, and all four new
credential commitments. The gateway verifies it against the public key in the
exact expired certificate fingerprint stored in the recovery record. A copied
token, another node identity, a freshly generated substitute key, or a cloned
state without the original private credential is rejected before credential
staging or token consumption. A byte-for-byte clone of the entire protected
secret store is cryptographically the same software identity and is outside
the software-only physical-host distinction; concurrent/replayed attempts are
still reduced to one winner by token consumption and generation CAS and such
cloning remains unsupported operationally.

After confirmation on the node, it generates a complete generation-scoped set
locally: a new Ed25519 control key/CSR, WireGuard key pair, restricted identity,
and reverse-tunnel token. Only the CSR/WireGuard public key and the two required
shared credentials cross to the gateway. The public `/.well-known/vpnctl/recover`
exchange uses the existing stable enrollment signing key and a `recover`
transcript, so nginx's current ingress certificate cannot substitute the
assignment. The signed assignment repeats the immutable ID/name/address,
manual active transport, presets, policy generation/hash, expose IDs, exact
next credential generation, gateway generation, control protocol, and hashes
of both new leaf bytes and metadata.

Gateway preparation reuses the complete four-member rotation readiness
boundary. Its one authoritative compare-and-swap both publishes the new node,
certificate, and transport generation and changes the exact recovery record to
`consumed` with the signed-transcript replay hash. There is no state containing
a consumed token with old credentials. Once that generation is known new, the
gateway returns the already signed response even if bounded old-generation
drain needs later repair; returning an HTTP rejection at that point could make
the node destroy the only matching fresh set.

The node pins the already stored enrollment public key, reconstructs the
recovery transcript, checks every stable field, verifies the new leaf against
its existing control CA and new CSR, stages and activates all new local
credentials, and commits one local generation. Before a possible gateway
commit, failures remove only attempt-owned generation files and leave the token
active. After a possible or known gateway commit, failures retain the complete
new set and report an uncertain/pending reconciliation instead of rolling back
to the expired identity. Successful completion drains and removes the complete
old generation on both hosts while name, ID, overlay IP, policy, exposes, and
manual transport selection remain unchanged.

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
