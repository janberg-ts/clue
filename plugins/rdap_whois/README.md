# RDAP Whois Plugin

Enriches IPv4 and IPv6 addresses with RDAP registration data.

RDAP is the HTTP/JSON replacement for traditional Whois. This plugin uses the configured RDAP bootstrap endpoint to find registration information for IP addresses.

## Configuration

Optional settings:

- `RDAP_API_URL`: RDAP IP lookup endpoint. Defaults to `https://rdap.org/ip`.
- `RDAP_FRONTEND_URL`: web lookup URL used for result links. Defaults to `https://search.arin.net/rdap/?query=`.
- `RDAP_VERIFY`: TLS verification setting. Defaults to `true`. Set to `false`, `0`, or a CA bundle path if needed.
- `RDAP_USER_AGENT`: HTTP user agent. Defaults to `Clue RDAP Whois Plugin`.

## Supported Types

- `ipv4`
- `ipv6`