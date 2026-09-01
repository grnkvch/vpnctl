# IP-only nginx ingress spike — tasks 2.5–2.6

Status: **tasks 2.5 and 2.6 development gates passed; nginx selected; real Telegram provider gate assigned to release task 16.11**.

The candidate uses Ubuntu 24.04 `nginx 1.24.0-2ubuntu7.17` from `noble-updates`, pinned with the package SHA-256 in `test/v2lab/ingress/manifest.json`. The Ubuntu build includes `ngx_http_v2_module`; because nginx 1.24 predates the standalone `http2 on` directive, this pinned configuration uses `listen 443 ssl http2`.

The prototype owns a separate configuration tree and two non-enabled test units. The distro `nginx.service` is prevented from starting during package installation and remains disabled/inactive. Guest `443/TCP` is explicitly ignored by Lima forwarding. An unrelated host `*:443` listener belongs to `realty-front-docker-vm` and is never a command target.

## Local acceptance

Evidence at `artifacts/v2lab/ingress-spike/evidence-local-final/summary.json` passed:

- manual IPv4 identity `192.168.104.1` in both SAN and compatibility CN;
- a self-signed RSA-2048/SHA-256 public certificate with an exact 1825-day lifetime;
- root-only mode `0600` for the private key, with no private-key export or evidence copy;
- nginx configuration validation and Ubuntu package/version checks;
- verified TLS 1.2 and TLS 1.3 connections from the node fixture;
- one synthetic Telegram-shaped POST over HTTP/1.1 and one over negotiated HTTP/2, both validated by the loopback-only upstream;
- exact request-counter delta of two, trusted forwarding metadata, and unknown-path `404`;
- `443/TCP` present during the test, `443/UDP` absent, and no vpnctl host forwarding.

The final point snapshot measured approximately 8 MiB RSS for each nginx master/worker process, 20 MiB for the test-only Python receiver, 285 MiB total gateway guest RSS, and 284 MiB total node guest RSS. These are idle/functional point observations. Streaming, body-file behavior, concurrency, limits, reload, error semantics, and safe defaults are measured separately by task 2.6.

Reproduce the local fixture with the gateway lab address supplied explicitly:

```bash
./scripts/v2ingress-spike.sh prepare 192.168.104.1
./scripts/v2ingress-spike.sh verify
./scripts/v2ingress-spike.sh stress
./scripts/v2ingress-spike.sh stop
```

`uninstall` removes only owner-marked units, configuration, certificate/key, helper executables, and the two apt packages that this spike recorded as newly installed. Apt metadata and ignored evidence remain; deleting the exact lab VMs is the complete fallback.

## Stress acceptance and selected defaults

Evidence at `artifacts/v2lab/ingress-spike/stress-final-v2/summary.json` passed on the same 1 vCPU/512 MiB/10 GiB fixtures. The selected implementation-neutral defaults are:

- 256 nginx worker connections, 64 simultaneous gateway ingress requests, and 64 HTTP/2 streams;
- 40 simultaneous requests per expose by default; excess requests return `503` without an application queue;
- 8 MiB gateway body maximum and 1 MiB expose default;
- 15-second default and 60-second maximum upstream timeout;
- four 8 KiB large-header buffers and a 10-second graceful worker drain.

The renderer must emit both gateway and per-expose `limit_conn` directives in every proxy location. nginx inherits parent limits only when the child declares none; emitting only the expose limit silently disables the gateway limit in that location.

Measured outcomes:

- a throttled 3 MiB upload reached the upstream before the client completed sending it; 1237 filesystem samples observed zero regular files in both request and response temp directories;
- the safe 40-request run returned 40×`200`; a 45-request single-expose overload returned 40×`200` plus 5×`503`; a 72-request two-expose overload returned 64×`200` plus 8×`503`;
- unknown path, body excess, unavailable upstream, and upstream timeout returned exactly `404`, `413`, `503`, and `504`;
- an in-flight generation-A request completed across reload while a new request used generation B; the master PID stayed stable, and the fixture restored generation A afterward;
- ingress cgroup peak was 6,025,216 bytes, the test-only receiver peak was 14,802,944 bytes, `MemAvailable` during hard load was about 284 MiB, and both cgroups recorded zero OOM events;
- the owner-checked uninstall removed nginx packages, units, configuration, certificate/key, helpers, listeners, and node temp inputs. Both lab VMs remain running; the intentional Lima port-443 ignore and apt metadata remain.

The Caddy fallback is not activated. nginx is accepted for continued implementation, but it is not production-ready until the deployed Telegram gate passes. The relevant nginx behavior is documented in the official [proxy module](https://nginx.org/en/docs/http/ngx_http_proxy_module.html), [connection-limit module](https://nginx.org/en/docs/http/ngx_http_limit_conn_module.html), [HTTP/2 module](https://nginx.org/en/docs/http/ngx_http_v2_module.html), and [graceful reload control flow](https://nginx.org/en/docs/control.html).

## Real Telegram gate

The local address is not reachable by Telegram, so local POSTs cannot satisfy the real provider gate. The test-only `telegram-webhook-gate` is ready for an equivalent actually deployed gateway. It:

- requires a manually supplied global IPv4;
- reads the bot token only through a hidden TTY prompt, never argv, environment, file, log, or JSON;
- refuses to replace an existing webhook;
- uploads only the public PEM certificate as multipart `certificate` data;
- validates `getWebhookInfo` in memory without emitting its URL/path;
- waits for the loopback receiver counter to increase after a real Telegram update;
- calls `deleteWebhook` in cleanup and emits only sanitized booleans.

On the deployed test gateway, the gate command is:

```bash
sudo /usr/local/libexec/vpnctl-v2-spike/telegram-webhook-gate \
  --public-ip 203.0.113.10
```

The example address must be replaced manually. Use a dedicated bot with no existing webhook and send it one message while the helper waits. A bot token is strictly test input and remains outside vpnctl's product responsibility.

Telegram documents that `setWebhook` sends HTTPS POST updates, requires the public certificate to be uploaded as an `InputFile` for self-signed TLS, and accepts webhook ports 443, 80, 88, and 8443. Its self-signed guide shows RSA-2048/SHA-256 PEM generation and says only the public PEM is uploaded. Telegram does not document a maximum certificate lifetime, so the accepted five-year value still needs the real gate. Primary references: [Telegram Bot API `setWebhook`](https://core.telegram.org/bots/api#setwebhook), [Telegram self-signed certificate guide](https://core.telegram.org/bots/self-signed), [nginx HTTP/2 module](https://nginx.org/en/docs/http/ngx_http_v2_module.html), and [nginx HTTPS configuration](https://nginx.org/en/docs/http/configuring_https_servers.html).

OpenSpec task 2.5 is complete on the local development gate. The real registration/request/cleanup evidence remains mandatory and is explicitly assigned to task 16.11 against the actually deployed gateway and node.
