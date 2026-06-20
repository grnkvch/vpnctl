# 0005: Keep Config Delivery Local First

## Context

Client configuration must be delivered to iPhone, macOS, Arch Linux, Ubuntu, and
Linux VM clients. Candidate delivery modes include QR codes, local files,
temporary links, signed URLs, and one-time links.

## Decision

Support local file export and QR code generation first. Defer temporary links,
signed URLs, and one-time links until the threat model and hosting model are
defined in a later ADR.

## Alternatives Considered

- Implement all delivery mechanisms from the start
- Only print configs to stdout
- Host a built-in local web server for temporary delivery
- Upload generated configs to object storage

## Tradeoffs

Local files and QR codes cover the most immediate personal-use workflows while
keeping secret exposure limited and understandable.

The cost is less convenience for remote enrollment until link-based delivery is
designed.

## Consequences

- Delivery artifacts should be short-lived and clearly separated from state.
- Export commands must avoid writing secrets to unexpected locations.
- Link-based delivery requires a future ADR covering expiration, authentication,
  revocation, and logging.
