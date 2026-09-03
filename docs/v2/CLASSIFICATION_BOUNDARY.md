# Policy classification boundary

vpnctl's fail-closed guarantee starts after traffic is classified as selected.
A selected TCP or UDP flow goes through the active gateway transport or is
blocked; it never falls back to direct. Traffic that does not match a selector
remains direct.

## What domain selectors can observe

On a private node, vpnctl manages classic UDP/TCP port-53 resolution through
the local Mihomo resolver. In `policy` DNS mode it can therefore associate an
ordinary selected-domain query with the gateway DNS path and populate the
selected routing decision. Compatible Clash profiles express the equivalent
split-DNS policy.

An application can bypass this observation boundary:

- Independent DNS-over-HTTPS hides the requested name inside HTTPS.
- Independent DNS-over-TLS hides the requested name inside TLS.
- A hardcoded destination IP performs no DNS query at all.
- Another private or embedded resolution mechanism can likewise hide the name.

In these cases a domain or domain-suffix selector alone cannot recognize the
application's intended hostname. The resulting destination remains unmatched
and direct unless an explicit IP/CIDR selector also matches it. Selecting the
resolver endpoint by IP/CIDR can select that endpoint's connection, but does
not reveal or selectively classify names carried inside the encrypted session.

## Deliberate v2.0 behavior

v2.0 does not maintain a global list of third-party DoH/DoT providers, block
all TCP/UDP port 853, block generic HTTPS, inspect TLS, or convert an unknown
destination into selected traffic. Those approaches would be incomplete,
fragile, and could disrupt unrelated applications. No routing, DNS, Clash, or
nftables renderer may generate such a global block.

The diagnostic representation is versioned and reports:

- `selected_action: gateway_or_block`;
- `unmatched_action: direct`;
- managed classic DNS;
- independently hidden DoH and DoT names;
- the need for an address selector for hardcoded IPs;
- `global_doh_dot_blocked: false`.

Policy results include one concise `classification_boundary` warning and the
structured representation whenever the effective policy is non-empty. The
status and doctor slices expose the same structure without network probes or
configuration changes. This intentional limitation is informational and does
not by itself degrade an otherwise healthy system.
