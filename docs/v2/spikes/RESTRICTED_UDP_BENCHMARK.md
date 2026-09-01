# Restricted UDP-over-TCP workload benchmark — task 2.4

Status: **development benchmark passed; functional bounds accepted without a performance SLA**.

The benchmark ran on 2026-09-01 with the pinned task 2.3 candidate and two Ubuntu 24.04 amd64 fixtures, each constrained to 1 vCPU, 512 MiB configured RAM, 10 GiB configured disk, and 1 GiB swap. It used a single SOCKS5 UDP association per profile through Mihomo UoT v2, Shadowsocks 2022, ShadowTLS v3 strict, and gateway `8443/TCP`. No test used `8443/UDP` or native node-to-gateway UDP.

## Telegram scope

Telegram Bot API calls and webhook delivery are TCP/HTTPS workloads, not UDP. This spike therefore used 50 sequential selected-TCP requests with a 491-byte synthetic Bot API-shaped response. It did not contact Telegram, use a bot token, reproduce Telegram's application TLS endpoint, exercise webhook ingress, or replace the real Telegram and Clash Mi release gates.

All 50 requests succeeded. The point measurement was 5.26 requests/s with 187.671 ms p50, 203.950 ms p95, and 256.348 ms maximum latency. Every request deliberately opened a fresh proxy connection, so these values are transport observations rather than a capacity claim. Tasks 2.5-2.7 cover actual HTTPS ingress and reverse-tunnel behavior; task 16.9 covers the several-hundred-user capacity target.

## UDP results

| Profile | Application payload | Offered rate | Sent / received | Loss | p50 / p95 / max RTT |
|---|---:|---:|---:|---:|---:|
| DNS-sized steady | 64 B | 50 pps | 150 / 150 | 0% | 3.254 / 67.812 / 193.367 ms |
| Small interactive steady | 256 B | 20 pps | 100 / 100 | 0% | 5.904 / 10.723 / 176.841 ms |
| MTU-safe steady | 1200 B | 20 pps | 100 / 100 | 0% | 6.591 / 14.416 / 197.862 ms |
| High-rate observation | 1200 B | 1000 pps | 500 / 93 | 81.4% | 1313.362 / 1383.066 / 1396.149 ms for received packets |
| Head-of-line baseline | 256 B | 100 pps | 300 / 300 | 0% | 3.050 / 67.861 / 189.174 ms |
| 250 ms peer partition | 256 B | 100 pps | 300 / 264 | 12.0% | 4.646 / 911.094 / 1017.392 ms |
| Post-fault recovery | 256 B | 50 pps | 50 / 50 | 0% | 3.535 / 146.303 / 178.491 ms |

The 250 ms partition caused 88 received datagrams to exceed 100 ms, increased maximum RTT by 828.218 ms over the identical baseline, and lost 36 application datagrams within the bounded receive window. This is accepted evidence of TCP head-of-line impact: a short outer-path disruption delays later UoT datagrams far beyond the disruption itself. The post-fault profile returned to zero loss without restarting either Mihomo process.

The high-rate result is deliberately recorded as unsupported rather than tuned away. This spike cannot attribute each dropped datagram to one internal queue, but the end-to-end outcome is sufficient to reject a bulk/high-rate performance guarantee.

## Accepted functional boundary

Restricted UoT is functionally supported only as best-effort selected UDP on a healthy path. The development compatibility/health floor is one UoT association completing all request/response probes within the bounded validation timeout for each of these exact profiles:

- 64-byte application datagrams at 50 packets/s;
- 256-byte application datagrams at 20 packets/s;
- 1200-byte application datagrams at 20 packets/s.

These points prove functionality and define future regression probes; they are not latency, throughput, concurrency, or availability SLOs. Payloads larger than 1200 bytes were not accepted because fragmentation behavior was not tested.

There is explicitly no restricted-transport performance guarantee for voice/video calls, gaming, QUIC/HTTP3, bulk or sustained high-rate UDP, loss/reordering/congestion/path interruption, or application datagrams above 1200 bytes. Users needing predictable latency-sensitive UDP must manually select the standard WireGuard transport. vpnctl does not automatically switch transports.

## Safety and resources

The outer capture counted 2535 protected node-to-gateway TCP packets and zero native/direct UDP packets. The temporary capture and fault tables were absent after the run, selectors were restored to `RESTRICTED-VALID` and `RESTRICTED-UDP → RESTRICTED`, and no benchmark port was forwarded to the development host.

The final point snapshot measured approximately 44 MiB RSS for gateway Mihomo, 48 MiB for node Mihomo, 320 MiB total gateway guest RSS, and 282 MiB total node guest RSS. Both guests retained 453 MiB usable RAM and 1 GiB swap. These are post-workload point measurements, not peak-memory or sustained-load guarantees.

Raw ignored evidence is under `artifacts/v2lab/restricted-spike/benchmark-final/`. Reproduce it with:

```bash
./scripts/v2restricted-spike.sh prepare
./scripts/v2restricted-spike.sh benchmark
./scripts/v2restricted-spike.sh stop
```

Actual Clash Mi execution remains deferred to the deployed-service task 16.11 gate.
