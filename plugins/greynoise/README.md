# GreyNoise Plugin

Enriches IPv4 selectors with GreyNoise Community API context.

## Configuration

Required settings:

- `GREYNOISE_API_KEY`: GreyNoise API key. `GN_API_KEY` is also accepted.

Optional settings:

- `GREYNOISE_API_URL`: GreyNoise API base URL. Defaults to `https://api.greynoise.io/v3`.
- `GREYNOISE_FRONTEND_URL`: GreyNoise Visualizer base URL. Defaults to `https://viz.greynoise.io/ip`.
- `GREYNOISE_VERIFY`: TLS verification setting. Defaults to `true`; can be `false`, `0`, or a CA bundle path.

## Supported Types

- `ipv4`
