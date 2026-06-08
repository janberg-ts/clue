"""RDAP Whois Clue Plugin

Status: In Development

Provides RDAP registration context for IP addresses.
"""

import os
import ipaddress
import textwrap
from typing import Any, Union
from urllib.parse import quote

import requests
from clue.common.exceptions import ClueException, InvalidDataException, NotFoundException, TimeoutException
from clue.common.logging import get_logger
from clue.models.network import Annotation, QueryEntry
from clue.plugin import CluePlugin
from clue.plugin.utils import Params
from pydantic_core import Url

logger = get_logger(__file__)

CLASSIFICATION = os.environ.get("CLASSIFICATION", "TLP:CLEAR")
API_URL = os.environ.get("RDAP_API_URL", os.environ.get("API_URL", "https://rdap.org/ip"))
FRONTEND_URL = os.environ.get(
    "RDAP_FRONTEND_URL", os.environ.get("FRONTEND_URL", "https://search.arin.net/rdap/?query=")
)
USER_AGENT = os.environ.get("RDAP_USER_AGENT", "Clue RDAP Whois Plugin")
SUPPORTED_TYPES = {"ipv4", "ipv6"}

verify: Union[str, bool] = str(os.environ.get("RDAP_VERIFY", "true"))
verify_bool = verify.lower()
if verify_bool in ("true", "1"):
    verify = True
elif verify_bool in ("false", "0"):
    verify = False
VERIFY = verify


def _lookup_url(value: str) -> str:
    return f"{API_URL.rstrip('/')}/{quote(value, safe=':')}"


def _frontend_link(value: str) -> Url:
    return Url(f"{FRONTEND_URL}{quote(value, safe='')}")


def _validate_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as e:
        raise InvalidDataException(f"Unable to interpret {value} as an IP address") from e


def _vcard_value(vcard: list[Any], field_name: str) -> str | None:
    if len(vcard) < 2 or not isinstance(vcard[1], list):
        return None

    for item in vcard[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == field_name and item[3]:
            return str(item[3])

    return None


def _entity_name(entity: dict[str, Any]) -> str | None:
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list):
        return _vcard_value(vcard, "fn") or _vcard_value(vcard, "org")
    return None


def _entities_by_role(data: dict[str, Any]) -> dict[str, list[str]]:
    entities: dict[str, list[str]] = {}
    for entity in data.get("entities") or []:
        if not isinstance(entity, dict):
            continue

        name = _entity_name(entity) or entity.get("handle")
        if not name:
            continue

        for role in entity.get("roles") or []:
            entities.setdefault(str(role), []).append(str(name))

    return entities


def _lookup_ip(value: str, params: Params) -> dict[str, Any]:
    try:
        response = requests.get(
            _lookup_url(value),
            headers={"Accept": "application/rdap+json, application/json", "User-Agent": USER_AGENT},
            timeout=params.max_timeout,
            verify=VERIFY,
        )
    except requests.exceptions.Timeout as e:
        raise TimeoutException("RDAP server failed to respond in time.", cause=e) from e

    if response.status_code == 404:
        raise NotFoundException("No RDAP record found")
    if response.status_code == 400:
        raise InvalidDataException("RDAP server rejected the supplied IP address.")
    if response.status_code == 429:
        raise TimeoutException("RDAP server rate limit was reached.")
    if response.status_code != 200:
        raise ClueException(f"Bad status from RDAP server: {response.status_code}")

    try:
        return response.json()
    except requests.exceptions.JSONDecodeError as e:
        raise ClueException("RDAP server returned an invalid JSON response.", cause=e) from e


def _cidrs(data: dict[str, Any]) -> list[str]:
    values = []
    for cidr in data.get("cidr0_cidrs") or []:
        if not isinstance(cidr, dict) or not cidr.get("length"):
            continue
        if cidr.get("v4prefix"):
            values.append(f"{cidr['v4prefix']}/{cidr['length']}")
        elif cidr.get("v6prefix"):
            values.append(f"{cidr['v6prefix']}/{cidr['length']}")

    return values


def _summary(data: dict[str, Any]) -> str:
    parts = []
    for label, key in (
        ("Network", "name"),
        ("Handle", "handle"),
        ("Country", "country"),
        ("Start", "startAddress"),
        ("End", "endAddress"),
    ):
        if value := data.get(key):
            parts.append(f"{label}: {value}")

    if cidrs := _cidrs(data):
        parts.append(f"CIDR: {', '.join(cidrs[:3])}")

    entities = _entities_by_role(data)
    for role in ("registrant", "technical", "abuse"):
        if names := entities.get(role):
            parts.append(f"{role.title()}: {', '.join(names[:3])}")

    return "; ".join(parts) if parts else "RDAP registration record found"


def enrich(type_name: str, value: str, params: Params, *_args) -> QueryEntry:
    """Run RDAP enrichment on an IP selector."""
    if type_name not in SUPPORTED_TYPES:
        raise InvalidDataException(
            message=f"Type name `{type_name}` is invalid. Valid types are: {', '.join(sorted(SUPPORTED_TYPES))}"
        )

    logger.info(f"Enriching [{type_name}] {value} limit {params.limit} (annotate={params.annotate})")

    value = _validate_ip(value)
    data = _lookup_ip(value, params)
    link = _frontend_link(value)
    result = QueryEntry(classification=CLASSIFICATION, count=1, link=link, raw_data=data if params.raw else None)

    if params.annotate:
        result.annotations.append(
            Annotation(
                analytic="RDAP Whois - IP Registration",
                analytic_icon="material-symbols:manage-search",
                icon=f"flag:{data.get('country', '').lower()}-4x3" if data.get("country") else None,
                type="context",
                value=str(data.get("handle") or data.get("name") or value),
                summary=_summary(data),
                details=textwrap.dedent(f"""\
                    # RDAP Whois

                    Network: {data.get('name') or 'Unknown'}

                    Handle: {data.get('handle') or 'Unknown'}

                    Country: {data.get('country') or 'Unknown'}

                    Address range: {data.get('startAddress') or 'Unknown'} - {data.get('endAddress') or 'Unknown'}

                    CIDR: {', '.join(_cidrs(data)) or 'Unknown'}
                    """),
                confidence=1.0,
                link=link,
            )
        )

    return result


plugin = CluePlugin(
    app_name=os.environ.get("APP_NAME", "rdap-whois"),
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