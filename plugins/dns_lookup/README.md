# DNS Lookup Plugin

Enriches domains, hostnames, IPv4 addresses, and IPv6 addresses with DNS records.

## Configuration

Optional settings:

- `DNS_LOOKUP_RECORD_TYPES`: comma-separated record types to resolve for domains and hostnames. Defaults to `A,AAAA,MX,NS,CNAME`.
- `DNS_LOOKUP_RESOLVERS`: comma-separated DNS resolver IP addresses. Defaults to the system resolver configuration.
- `DNS_LOOKUP_TIMEOUT`: per-query timeout in seconds. Defaults to `3.0`.
- `DNS_LOOKUP_MAX_RESULTS`: maximum records to keep per lookup before Clue result limiting. Defaults to `50`.

TXT records are supported, but are not enabled by default because they can be noisy.

## Supported Types

- `domain`
- `hostname`
- `ipv4`
- `ipv6`