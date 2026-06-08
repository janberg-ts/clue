# Shodan Plugin

Enriches IP selectors with Shodan host information.

## Configuration

Required settings:

- `SHODAN_API_KEY`: Shodan API key. `SHODAN_KEY` is also accepted.

Optional settings:

- `SHODAN_API_URL`: Shodan API base URL. Defaults to `https://api.shodan.io`.
- `SHODAN_FRONTEND_URL`: Shodan host page base URL. Defaults to `https://www.shodan.io/host`.
- `SHODAN_VERIFY`: TLS verification setting. Defaults to `true`; can be `false`, `0`, or a CA bundle path.

## Supported Types

- `ipv4`
- `ipv6`
