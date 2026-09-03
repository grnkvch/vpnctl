# Matcher IR and target projections

Task 10.1 introduces one versioned, provider-neutral matcher representation in
`internal/routing`. Preset YAML is still the editable source. Applied preset
ASTs are normalized into a `MatcherIR` whose clauses preserve each preset's
`includes - excludes` boundary; the final selected set is the union of those
clause results. This is required for cross-preset reselection: an include in
one preset can select a destination excluded inside another preset.

The IR contains only exact-domain, domain-suffix, IPv4-CIDR, and IPv6-CIDR
predicates. It has no action, outbound, provider, or fallback field. At the
product boundary, an IR match always means `gateway-or-block`; a miss means
direct. All arrays and clauses are canonical, strictly sorted, independently
owned, and validated against schema version 1 before target compilation.

Four projections are compiled from the same IR:

- node routing gets ordered domain and longest-prefix address decisions for
  the Mihomo TUN renderer;
- the nftables leak guard gets static IPv4/IPv6 decisions plus the same domain
  decisions for resolver-populated protected address sets;
- gateway DNS gets domain decisions only, because an IP/CIDR selector cannot
  choose a DNS path before the answer exists;
- Clash gets the same ordered domain and address decisions used by its rules
  and `nameserver-policy` sections.

Exact domains precede suffix rules, more-specific suffixes precede their
parents, and longer network prefixes precede shorter ones. Direct exceptions
are therefore target output, not policy input. A fully shadowed boundary is
omitted. Empty compiled IR is a valid all-direct policy, while an uncompiled
zero-value target is rejected instead of silently becoming all-direct.

Task 10.1 does not install a TUN, nftables rule, resolver, route, or systemd
unit. Task 10.2 renders the node TUN/resolver base; tasks 10.3-10.9 complete and
activate the remaining projections. The kernel cannot
recover the original hostname from an ordinary IP packet; the managed resolver
must feed addresses learned for selected domains into the leak guard. Static
IP/CIDR matchers remain independently enforceable without DNS.
