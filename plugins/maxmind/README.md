# MaxMind GeoLite2 Plugin

Enriches IPv4 and IPv6 addresses with local MaxMind GeoLite2 database context.

This plugin uses local `.mmdb` files and does not call MaxMind's web API. You need to download GeoLite2 databases with your own MaxMind account and keep them current according to MaxMind's license terms.

## Configuration

Optional settings:

- `MAXMIND_ASN_DB`: path, or comma-separated fallback paths, to `GeoLite2-ASN.mmdb`. Defaults to `/data/maxmind/GeoLite2-ASN.mmdb,/usr/share/GeoIP/GeoLite2-ASN.mmdb,/var/lib/GeoIP/GeoLite2-ASN.mmdb`.
- `MAXMIND_COUNTRY_DB`: path, or comma-separated fallback paths, to `GeoLite2-Country.mmdb`. Defaults to `/data/maxmind/GeoLite2-Country.mmdb,/usr/share/GeoIP/GeoLite2-Country.mmdb,/var/lib/GeoIP/GeoLite2-Country.mmdb`.
- `MAXMIND_CITY_DB`: path, or comma-separated fallback paths, to `GeoLite2-City.mmdb`. Defaults to `/data/maxmind/GeoLite2-City.mmdb,/usr/share/GeoIP/GeoLite2-City.mmdb,/var/lib/GeoIP/GeoLite2-City.mmdb`.
- `MAXMIND_FRONTEND_URL`: link used for annotations. Defaults to `https://www.maxmind.com/en/geoip-demo`.

Mount your database directory at `/data/maxmind` in Docker, or override the paths above.

## Supported Types

- `ipv4`
- `ipv6`
