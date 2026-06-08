# Team Cymru ASN Plugin

Enriches IPv4 and IPv6 addresses with BGP origin ASN context using Team Cymru's public IP to ASN DNS service.

Team Cymru's IP to ASN mapping is not a GeoIP service. The country and registry data describe the assigned BGP prefix registration, not the physical location of an IP address.

## Configuration

Optional settings:

- `TEAM_CYMRU_RESOLVERS`: comma-separated DNS resolver IP addresses. Defaults to the system resolver configuration.
- `TEAM_CYMRU_TIMEOUT`: DNS lookup timeout in seconds. Defaults to `3.0`.
- `TEAM_CYMRU_INCLUDE_AS_NAME`: set to `false` or `0` to skip the second ASN description lookup. Defaults to `true`.
- `TEAM_CYMRU_FRONTEND_URL`: link used for annotations. Defaults to `https://www.team-cymru.com/ip-asn-mapping`.

## Supported Types

- `ipv4`
- `ipv6`