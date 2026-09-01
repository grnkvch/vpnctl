# IP-only nginx ingress spike — task 2.5

Status: **local development gates passed; real Telegram registration/request gate pending**.

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

The final point snapshot measured approximately 8 MiB RSS for each nginx master/worker process, 20 MiB for the test-only Python receiver, 285 MiB total gateway guest RSS, and 284 MiB total node guest RSS. These are idle/functional point observations. Streaming, body-file behavior, concurrency, limits, reload, error semantics, and safe defaults remain task 2.6.

Reproduce the local fixture with the gateway lab address supplied explicitly:

```bash
./scripts/v2ingress-spike.sh prepare 192.168.104.1
./scripts/v2ingress-spike.sh verify
./scripts/v2ingress-spike.sh stop
```

`uninstall` removes only owner-marked units, configuration, certificate/key, helper executables, and the two apt packages that this spike recorded as newly installed. Apt metadata and ignored evidence remain; deleting the exact lab VMs is the complete fallback.

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

OpenSpec task 2.5 remains unchecked until this real deployed registration/request/cleanup evidence exists or the user explicitly moves that provider gate to the deployed-service release task.
