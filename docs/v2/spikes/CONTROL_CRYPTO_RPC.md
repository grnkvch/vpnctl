# Control crypto and RPC candidate — task 2.10

Status: **automated Ubuntu 24.04 amd64 Go/OpenSSL, PKI, transcript, mTLS, and bounded HTTP/1.1 gates passed**.

## Accepted PKI profile

- Internal control CA, gateway/node leaves, node CSR keys, and the independent enrollment signer use Ed25519.
- CA validity is 3650 days; leaf validity is 1825 days; gateway renewal starts at 180 days remaining. Positive serials contain at most 128 random bits.
- Keys are PKCS#8 PEM; certificates and CSRs are X.509/PKCS#10 PEM.
- A node CSR must be self-signed by an Ed25519 key and request exactly one canonical `urn:vpnctl:node:<uuid>` URI SAN. The gateway constructs the issued SAN from authoritative identity and ignores mutable CN for authorization.
- Gateway leaves use `urn:vpnctl:gateway:<uuid>` plus the current internal-overlay IP SAN. CA overlap uses a temporary old+new trust bundle; commit removes old trust. Public ingress RSA identity remains an independent trust domain.

Go 1.26.4 generated and parsed the fixture PKI. Ubuntu OpenSSL 3.0.13 verified the Go CA/leaves and URI SAN, generated an Ed25519 CSR accepted and signed by Go, verified the result, verified a Go enrollment signature, and produced an Ed25519 signature accepted by Go.

## Enrollment signature format

`vpnctl-enrollment-transcript-v1` is a domain-separated sequence of 32-bit big-endian length-prefixed field-name/value frames. It binds purpose, invite ID, exact endpoint, immutable node ID, issued/expiry, independent 16-byte node/gateway nonces, transport, sorted unique presets, sorted named SHA-256 hashes for each CSR/public credential, and normalized assignment SHA-256.

The response envelope carries `Ed25519`, the `sha256:<hex>` fingerprint of DER SPKI, and unpadded base64url transcript/signature. Verification reconstructs and byte-compares expected context, permits 120 seconds clock skew, rejects expiry or any substituted field, then atomically consumes the transcript/signature replay key with the independent single-use 32-byte invite secret.

## Control RPC limits

| Boundary | Accepted value |
| --- | ---: |
| TLS / ALPN | TLS 1.3 / HTTP/1.1 only, mandatory mTLS |
| Request / response | 64 KiB / 256 KiB |
| Request headers | 8 KiB |
| JSON nesting | 32 levels |
| Header deadline | 2 seconds |
| Body / write / idle deadlines | 5 seconds each |
| Accepted connections | 16 |

The server binds only its configured internal address and validates the CA chain, exact node URI identity, active node state, credential generation, protocol, expected state generation, timestamp/nonce, operation registry, and strict typed JSON before dispatch. Unknown/duplicate fields, trailing JSON, wrong method/path/media type, oversized bodies/responses, invalid/stale identity, TLS 1.2, missing client certificates, slow headers/bodies/writes/idle connections, and a 17th connection are bounded or rejected. Response JSON is encoded and size-checked before headers are committed.

## Reproduce and rollback

```bash
./scripts/v2control-spike.sh verify
./scripts/v2control-spike.sh status
./scripts/v2control-spike.sh uninstall
```

The script cross-compiles a disposable Linux/amd64 Go test binary, installs it only below root-owned `/var/lib/vpnctl-v2-spike-control`, runs it with all temp/key material below that directory, records sanitized ignored evidence, and removes the directory through an armed EXIT trap. It creates no package, service, persistent listener, firewall rule, or public endpoint.

The accepted ignored evidence is `artifacts/v2lab/control-spike/evidence-20260902T040621Z/summary.json`: the extended test peaked at 14336 KiB RSS, used zero swap, and left both the VM owner state/process and validated host build directory absent.
