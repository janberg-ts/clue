"""AlienVault OTX Clue Plugin

Status: In Development

Clue plugin to query AlienVault OTX indicator information.
"""

import os
import textwrap
from typing import Any, Union
from urllib.parse import quote

import requests
from clue.common.exceptions import (
    ClueException,
    InvalidDataException,
    NotFoundException,
    TimeoutException,
    UnprocessableException,
)
from clue.common.logging import get_logger
from clue.models.network import Annotation, QueryEntry
from clue.plugin import CluePlugin
from clue.plugin.utils import Params
from pydantic_core import Url

logger = get_logger(__file__)

OTX_API_KEY = os.environ.get(
    "OTX_API_KEY", os.environ.get("ALIENVAULT_OTX_API_KEY", os.environ.get("ALIENVAULT_API_KEY", ""))
)
CLASSIFICATION = os.environ.get("CLASSIFICATION", "TLP:CLEAR")
API_URL = os.environ.get("OTX_API_URL", "https://otx.alienvault.com/api/v1").rstrip("/")
FRONTEND_URL = os.environ.get("OTX_FRONTEND_URL", "https://otx.alienvault.com/indicator").rstrip("/")
SUPPORTED_TYPES = {"ipv4", "ipv6", "domain", "hostname", "url", "md5", "sha1", "sha256"}

verify: Union[str, bool] = str(os.environ.get("OTX_VERIFY", "true"))
verify_bool = verify.lower()
if verify_bool in ("true", "1"):
    verify = True
elif verify_bool in ("false", "0"):
    verify = False
VERIFY = verify

TYPE_MAPPING = {
    "ipv4": "IPv4",
    "ipv6": "IPv6",
    "domain": "domain",
    "hostname": "hostname",
    "url": "url",
    "md5": "file",
    "sha1": "file",
    "sha256": "file",
}


def _indicator_url(otx_type: str, value: str) -> str:
    return f"{API_URL}/indicators/{otx_type}/{quote(value, safe='')}/general"


def _frontend_url(otx_type: str, value: str) -> Url:
    return Url(f"{FRONTEND_URL}/{otx_type}/{quote(value, safe='')}")


def lookup_indicator(type_name: str, value: str, params: Params) -> dict[str, Any]:
    """Lookup an indicator in AlienVault OTX."""
    if not OTX_API_KEY:
        raise UnprocessableException("No API key is provided. Set OTX_API_KEY, ALIENVAULT_OTX_API_KEY, or ALIENVAULT_API_KEY.")

    otx_type = TYPE_MAPPING[type_name]
    headers = {
        "Accept": "application/json",
        "X-OTX-API-KEY": OTX_API_KEY,
    }

    try:
        response = requests.get(_indicator_url(otx_type, value), headers=headers, verify=VERIFY, timeout=params.max_timeout)
    except requests.exceptions.Timeout as e:
        raise TimeoutException("AlienVault OTX failed to respond in time.", cause=e) from e

    if response.status_code == 404:
        raise NotFoundException("No result found")
    if response.status_code in {401, 403}:
        raise UnprocessableException("AlienVault OTX API key was rejected.")
    if response.status_code == 429:
        raise ClueException("AlienVault OTX rate limit was exceeded.")
    if response.status_code != 200:
        raise ClueException(f"Error querying AlienVault OTX [{response.status_code}]")

    data = response.json()
    if not data:
        raise NotFoundException("No result found")

    return data


def _pulse_info(data: dict[str, Any]) -> dict[str, Any]:
    pulse_info = data.get("pulse_info")
    return pulse_info if isinstance(pulse_info, dict) else {}


def _pulses(data: dict[str, Any]) -> list[dict[str, Any]]:
    pulses = _pulse_info(data).get("pulses")
    return pulses if isinstance(pulses, list) else []


def _pulse_count(data: dict[str, Any]) -> int:
    pulse_info = _pulse_info(data)
    count = pulse_info.get("count")
    if isinstance(count, int):
        return count
    return len(_pulses(data))


def _summary(data: dict[str, Any]) -> str:
    pulse_count = _pulse_count(data)
    names = [pulse.get("name") for pulse in _pulses(data)[:3] if pulse.get("name")]
    parts = [f"Pulses: {pulse_count}"]
    if names:
        parts.append(f"Top pulses: {', '.join(names)}")
    if reputation := data.get("reputation"):
        parts.append(f"Reputation: {reputation}")
    if data.get("validation"):
        parts.append("Validation data present")
    return "; ".join(parts)


def _details(type_name: str, value: str, data: dict[str, Any]) -> str:
    pulse_lines = "\n".join(f"- {pulse.get('name', 'Unnamed pulse')}" for pulse in _pulses(data)[:10])
    if not pulse_lines:
        pulse_lines = "- None"

    return textwrap.dedent(f"""\
        # AlienVault OTX

        Type: {type_name}

        Indicator: {value}

        Pulse count: {_pulse_count(data)}

        Reputation: {data.get('reputation', 'Unknown')}

        Pulses:
        {pulse_lines}
        """)


def enrich(type_name: str, value: str, params: Params, *_args) -> QueryEntry:
    """Run AlienVault OTX enrichment on an indicator selector."""
    if type_name not in SUPPORTED_TYPES:
        raise InvalidDataException(
            message=f"Type name `{type_name}` is invalid. Valid types are: {', '.join(sorted(SUPPORTED_TYPES))}"
        )

    logger.info(f"Enriching [{type_name}] {value} limit {params.limit} (annotate={params.annotate})")

    data = lookup_indicator(type_name, value, params)
    otx_type = TYPE_MAPPING[type_name]
    frontend_link = _frontend_url(otx_type, value)
    pulse_count = _pulse_count(data)
    verdict = "known" if pulse_count else "unknown"

    result = QueryEntry(
        classification=CLASSIFICATION,
        link=frontend_link,
        count=pulse_count,
        annotations=[],
        raw_data=data if params.raw else None,
    )

    if not params.annotate:
        return result

    result.annotations.append(
        Annotation(
            analytic="AlienVault OTX - Indicator Reputation",
            analytic_icon="simple-icons:alienware",
            type="opinion" if pulse_count else "context",
            value=verdict,
            summary=_summary(data),
            details=_details(type_name, value, data),
            confidence=1.0 if pulse_count else 0.5,
            quantity=pulse_count,
            link=frontend_link,
        )
    )

    return result


plugin = CluePlugin(
    app_name=os.environ.get("APP_NAME", "alienvault-otx"),
    classification=CLASSIFICATION,
    enable_apm=False,
    enable_cache=True,
    enrich=enrich,
    supported_types=SUPPORTED_TYPES,
    logger=logger,
)

app = plugin.app


def main():
    """Main executor function."""
    plugin.app.run(host="0.0.0.0", port=int(os.environ.get("PLUGIN_PORT", os.environ.get("PORT", 8000))), debug=False)  # noqa: S104


if __name__ == "__main__":
    main()
