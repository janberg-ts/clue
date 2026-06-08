"""Shodan Clue Plugin

Status: In Development

Clue plugin to query Shodan host information for IP selectors.
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

SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", os.environ.get("SHODAN_KEY", ""))
CLASSIFICATION = os.environ.get("CLASSIFICATION", "TLP:CLEAR")
API_URL = os.environ.get("SHODAN_API_URL", "https://api.shodan.io").rstrip("/")
FRONTEND_URL = os.environ.get("SHODAN_FRONTEND_URL", "https://www.shodan.io/host").rstrip("/")
SUPPORTED_TYPES = {"ipv4", "ipv6"}

verify: Union[str, bool] = str(os.environ.get("SHODAN_VERIFY", "true"))
verify_bool = verify.lower()
if verify_bool in ("true", "1"):
    verify = True
elif verify_bool in ("false", "0"):
    verify = False
VERIFY = verify


def lookup_ip(value: str, params: Params) -> dict[str, Any]:
    """Lookup an IP address in Shodan."""
    if not SHODAN_API_KEY:
        raise UnprocessableException("No API key is provided. Set SHODAN_API_KEY or SHODAN_KEY.")

    try:
        response = requests.get(
            f"{API_URL}/shodan/host/{value}",
            params={"key": SHODAN_API_KEY},
            verify=VERIFY,
            timeout=params.max_timeout,
        )
    except requests.exceptions.Timeout as e:
        raise TimeoutException("Shodan failed to respond in time.", cause=e) from e

    if response.status_code == 404:
        raise NotFoundException("No result found")
    if response.status_code in {401, 403}:
        raise UnprocessableException("Shodan API key was rejected.")
    if response.status_code == 429:
        raise ClueException("Shodan rate limit was exceeded.")
    if response.status_code == 400:
        raise InvalidDataException("Shodan rejected the supplied IP address.")
    if response.status_code != 200:
        raise ClueException(f"Error querying Shodan [{response.status_code}]")

    data = response.json()
    if not data:
        raise NotFoundException("No result found")
    return data


def _vulns(data: dict[str, Any]) -> list[str]:
    vulns = data.get("vulns") or {}
    if isinstance(vulns, dict):
        return sorted(vulns.keys())
    if isinstance(vulns, list):
        return sorted(str(vuln) for vuln in vulns)
    return []


def _ports(data: dict[str, Any]) -> list[int]:
    ports = data.get("ports") or []
    return sorted(port for port in ports if isinstance(port, int))


def _summary(data: dict[str, Any], ports: list[int], vulns: list[str]) -> str:
    parts = []
    if ports:
        parts.append(f"Open ports: {', '.join(str(port) for port in ports[:12])}")
    if vulns:
        parts.append(f"Vulnerabilities: {len(vulns)}")
    if data.get("org"):
        parts.append(f"Org: {data['org']}")
    if data.get("isp"):
        parts.append(f"ISP: {data['isp']}")
    if data.get("asn"):
        parts.append(f"ASN: {data['asn']}")
    if data.get("country_name"):
        parts.append(f"Country: {data['country_name']}")
    return "; ".join(parts) or "Host observed by Shodan"


def _details(data: dict[str, Any], ports: list[int], vulns: list[str]) -> str:
    hostnames = data.get("hostnames") or []
    tags = data.get("tags") or []
    return textwrap.dedent(f"""\
        # Shodan Host Result

        IP: {data.get('ip_str') or data.get('ip') or 'Unknown'}

        Open ports: {', '.join(str(port) for port in ports) or 'None'}

        Vulnerabilities: {', '.join(vulns[:20]) or 'None'}

        Hostnames: {', '.join(hostnames[:20]) or 'None'}

        Tags: {', '.join(tags[:20]) or 'None'}

        Organization: {data.get('org') or 'Unknown'}

        ISP: {data.get('isp') or 'Unknown'}

        ASN: {data.get('asn') or 'Unknown'}

        Location: {data.get('city') or 'Unknown'}, {data.get('country_name') or 'Unknown'}
        """)


def enrich(type_name: str, value: str, params: Params, *_args) -> QueryEntry:
    """Run Shodan enrichment on an IP selector."""
    if type_name not in SUPPORTED_TYPES:
        raise InvalidDataException(
            message=f"Type name `{type_name}` is invalid. Valid types are: {', '.join(sorted(SUPPORTED_TYPES))}"
        )

    data = lookup_ip(value, params)
    ports = _ports(data)
    vulns = _vulns(data)
    frontend_link = Url(f"{FRONTEND_URL}/{value}")

    result = QueryEntry(
        classification=CLASSIFICATION,
        link=frontend_link,
        count=len(ports) or 1,
        annotations=[],
        raw_data=data if params.raw else None,
    )

    if not params.annotate:
        return result

    result.annotations.append(
        Annotation(
            analytic="Shodan - Host Information",
            analytic_icon="simple-icons:shodan",
            type="opinion" if vulns else "context",
            value="vulnerable" if vulns else "observed",
            summary=_summary(data, ports, vulns),
            details=_details(data, ports, vulns),
            confidence=0.9 if vulns else 0.7,
            quantity=len(vulns) or len(ports) or 1,
            link=frontend_link,
        )
    )

    return result


plugin = CluePlugin(
    app_name=os.environ.get("APP_NAME", "shodan"),
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
