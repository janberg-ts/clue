# URLScan Plugin

Enriches URL, domain, and hostname selectors with existing URLScan search results.

This plugin is read-only by default. It searches existing scans and does not submit new scans, which avoids consuming scan submission quota or accidentally publishing sensitive URLs.

## Configuration

Required settings:

- `URLSCAN_API_KEY`: URLScan API key.

Optional settings:

- `URLSCAN_API_URL`: URLScan API base URL. Defaults to `https://urlscan.io/api/v1`.
- `URLSCAN_FRONTEND_URL`: URLScan web UI base URL. Defaults to `https://urlscan.io`.
- `URLSCAN_VERIFY`: TLS verification setting. Defaults to `true`; can be `false`, `0`, or a CA bundle path.
- `URLSCAN_DATE_RANGE`: date filter appended to searches. Defaults to `date:>now-30d`.
- `URLSCAN_MAX_RESULTS`: maximum results requested from URLScan. Defaults to `10`.

## Supported Types

- `url`
- `domain`
- `hostname`
