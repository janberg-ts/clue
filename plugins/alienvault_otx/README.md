# AlienVault OTX Plugin

Enriches IP, domain, URL, and hash selectors with AlienVault OTX indicator context.

## Configuration

Required settings:

- `OTX_API_KEY`, `ALIENVAULT_OTX_API_KEY`, or `ALIENVAULT_API_KEY`: AlienVault OTX API key.

Optional settings:

- `OTX_API_URL`: OTX API base URL. Defaults to `https://otx.alienvault.com/api/v1`.
- `OTX_FRONTEND_URL`: OTX web UI base URL. Defaults to `https://otx.alienvault.com/indicator`.
- `OTX_VERIFY`: TLS verification setting. Defaults to `true`; can be `false`, `0`, or a CA bundle path.

## Supported Types

- `ipv4`
- `ipv6`
- `domain`
- `hostname`
- `url`
- `md5`
- `sha1`
- `sha256`
