"""GreyNoise Clue Plugin

Status: In Development

Clue plugin to query GreyNoise Community API context for IPv4 selectors.
"""

import os
import textwrap
from typing import Any, Union

import requests
from clue.common.exceptions import ClueException, InvalidDataException, NotFoundException, TimeoutException, UnprocessableException
from clue.common.logging import get_logger
from clue.models.network import Annotation, QueryEntry
from clue.plugin import CluePlugin
from clue.plugin.utils import Params
from pydantic_core import Url

logger = get_logger(__file__)

GREYNOISE_API_KEY = os.environ.get("GREYNOISE_API_KEY", os.environ.get("GN_API_KEY", ""))
CLASSIFICATION = os.environ.get("CLASSIFICATION", "TLP:CLEAR")
API_URL = os.environ.get("GREYNOISE_API_URL", "https://api.greynoise.io/v3").rstrip("/")
FRONTEND_URL = os.environ.get("GREYNOISE_FRONTEND_URL", "https://viz.greynoise.io/ip").rstrip("/")
SUPPORTED_TYPES = {"ipv4"}

verify: Union[str, bool] = str(os.environ.get("GREYNOISE_VERIFY", "true"))
verify_bool = verify.lower()
if verify_bool in ("true", "1"):
    verify = True
elif verify_bool in ("false", "0"):
    verify = False
VERIFY = verify


def lookup_ip(value: str, params: Params) -> dict[str, Any]:
    """Lookup an IPv4 address in GreyNoise Community API."""
    if not GREYNOISE_API_KEY:
        raise UnprocessableException("No API key is provided. Set GREYNOISE_API_KEY or GN_API_KEY.")

    headers = {
        "Accept": "application/json",
        "key": GREYNOISE_API_KEY,
    }

    try:
        response = requests.get(f"{API_URL}/community/{value}", headers=headers, verify=VERIFY, timeout=params.max_timeout)
    except requests.exceptions.Timeout as e:
        raise TimeoutException("GreyNoise failed to respond in time.", cause=e) from e

    if response.status_code == 404:
        raise NotFoundException("No result found")
    if response.status_code in {401, 403}:
        raise UnprocessableException("GreyNoise API key was rejected.")
    if response.status_code == 429:
        raise ClueException("GreyNoise rate limit was exceeded.")
    if response.status_code == 400:
        raise InvalidDataException("GreyNoise rejected the supplied IP address.")
    if response.status_code != 200:
        raise ClueException(f"Error querying GreyNoise [{response.status_code}]")

    data = response.json()
    if not data:
        raise NotFoundException("No result found")
    return data


def _verdict(data: dict[str, Any]) -> str:
    classification = str(data.get("classification") or "").lower()
    if classification in {"malicious", "benign", "unknown"}:
        return classification
    if data.get("noise") is True:
        return "suspicious"
    if data.get("riot") is True:
        return "benign"
    return "unknown"


def _summary(data: dict[str, Any]) -> str:
    parts = []
    if data.get("classification"):
        parts.append(f"Classification: {data['classification']}")
    parts.append(f"Noise: {bool(data.get('noise'))}")
    parts.append(f"RIOT: {bool(data.get('riot'))}")
    if data.get("name"):
        parts.append(f"Name: {data['name']}")
    if data.get("last_seen"):
        parts.append(f"Last seen: {data['last_seen']}")
    if data.get("message"):
        parts.append(f"Message: {data['message']}")
    return "; ".join(parts)


def _details(data: dict[str, Any]) -> str:
    return textwrap.dedent(f"""\
        # GreyNoise Community Result

        IP: {data.get('ip') or 'Unknown'}

        Classification: {data.get('classification') or 'Unknown'}

        Noise: {data.get('noise', 'Unknown')}

        RIOT: {data.get('riot', 'Unknown')}

        Name: {data.get('name') or 'Unknown'}

        Last seen: {data.get('last_seen') or 'Unknown'}

        Message: {data.get('message') or 'Unknown'}
        """)


def enrich(type_name: str, value: str, params: Params, *_args) -> QueryEntry:
    """Run GreyNoise enrichment on an IPv4 selector."""
    if type_name not in SUPPORTED_TYPES:
        raise InvalidDataException(
            message=f"Type name `{type_name}` is invalid. Valid types are: {', '.join(sorted(SUPPORTED_TYPES))}"
        )

    data = lookup_ip(value, params)
    frontend_link = Url(data.get("link") or f"{FRONTEND_URL}/{value}")
    verdict = _verdict(data)
    is_signal = data.get("noise") is True or data.get("riot") is True or bool(data.get("classification"))

    result = QueryEntry(
        classification=CLASSIFICATION,
        link=frontend_link,
        count=1 if is_signal else 0,
        annotations=[],
        raw_data=data if params.raw else None,
    )

    if not params.annotate:
        return result

    annotation_type = "opinion" if verdict in {"malicious", "suspicious"} else "context"
    confidence = 1.0 if verdict in {"malicious", "benign"} else 0.7
    result.annotations.append(
        Annotation(
            analytic="GreyNoise - IP Context",
            analytic_icon="simple-icons:greynoise",
            type=annotation_type,
            value=verdict,
            summary=_summary(data),
            details=_details(data),
            confidence=confidence,
            quantity=1 if is_signal else 0,
            link=frontend_link,
        )
    )

    return result


plugin = CluePlugin(
    app_name=os.environ.get("APP_NAME", "greynoise"),
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
