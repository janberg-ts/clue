"""Team Cymru ASN Clue Plugin

Status: In Development

Provides BGP origin ASN context for IP addresses using Team Cymru's public DNS service.
"""

import ipaddress
import os
import textwrap
from typing import Any

import dns.exception
import dns.resolver
from clue.common.exceptions import InvalidDataException, NotFoundException, TimeoutException
from clue.common.logging import get_logger
from clue.models.network import Annotation, QueryEntry
from clue.plugin import CluePlugin
from clue.plugin.utils import Params
from pydantic_core import Url

CLASSIFICATION = os.environ.get("CLASSIFICATION", "TLP:CLEAR")
FRONTEND_URL = os.environ.get("TEAM_CYMRU_FRONTEND_URL", "https://www.team-cymru.com/ip-asn-mapping")
SUPPORTED_TYPES = {"ipv4", "ipv6"}
TIMEOUT = float(os.environ.get("TEAM_CYMRU_TIMEOUT", "3.0"))
INCLUDE_AS_NAME = os.environ.get("TEAM_CYMRU_INCLUDE_AS_NAME", "true").lower() not in {"false", "0"}

logger = get_logger(__file__)

resolver = dns.resolver.Resolver()
resolver.timeout = TIMEOUT
resolver.lifetime = TIMEOUT

if resolvers := [item.strip() for item in os.environ.get("TEAM_CYMRU_RESOLVERS", "").split(",") if item.strip()]:
    resolver.nameservers = resolvers

plugin = CluePlugin(
    app_name=os.environ.get("APP_NAME", "team-cymru"),
    classification=CLASSIFICATION,
    enable_apm=False,
    enable_cache=True,
    supported_types=SUPPORTED_TYPES,
    logger=logger,
)


def _validate_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        return ipaddress.ip_address(value)
    except ValueError as e:
        raise InvalidDataException(f"Unable to interpret {value} as an IP address") from e


def _query_name(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    if isinstance(address, ipaddress.IPv4Address):
        reversed_octets = ".".join(reversed(str(address).split(".")))
        return f"{reversed_octets}.origin.asn.cymru.com"

    reversed_nibbles = ".".join(reversed(address.exploded.replace(":", "")))
    return f"{reversed_nibbles}.origin6.asn.cymru.com"


def _txt_lookup(name: str) -> list[str]:
    try:
        answers = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.Timeout as e:
        raise TimeoutException(f"Team Cymru DNS lookup timed out for {name}", cause=e) from e
    except dns.exception.DNSException as e:
        logger.warning("Team Cymru DNS lookup failed for %s: %s", name, e)
        return []

    values = []
    for answer in answers:
        values.append("".join(part.decode("utf-8", errors="replace") for part in answer.strings))
    return values


def _parse_origin_record(record: str) -> dict[str, str]:
    parts = [part.strip() for part in record.split("|")]
    if len(parts) < 5:
        return {"record": record}

    return {
        "asn": parts[0],
        "prefix": parts[1],
        "country_code": parts[2],
        "registry": parts[3],
        "allocated": parts[4],
        "record": record,
    }


def _asn_name(asn: str) -> str | None:
    first_asn = asn.split()[0]
    if not first_asn.isdigit():
        return None

    records = _txt_lookup(f"AS{first_asn}.asn.cymru.com")
    if not records:
        return None

    parts = [part.strip() for part in records[0].split("|")]
    if len(parts) < 5:
        return None

    return parts[4]


def _lookup(value: str) -> dict[str, Any]:
    address = _validate_ip(value)
    query_name = _query_name(address)
    records = _txt_lookup(query_name)
    if not records:
        raise NotFoundException("No Team Cymru ASN record found")

    data: dict[str, Any] = _parse_origin_record(records[0])
    data["query"] = query_name
    data["ip"] = str(address)

    if INCLUDE_AS_NAME and data.get("asn"):
        if as_name := _asn_name(data["asn"]):
            data["as_name"] = as_name

    return data


def _summary(data: dict[str, Any]) -> str:
    parts = []
    if asn := data.get("asn"):
        parts.append(f"ASN: {asn}")
    if as_name := data.get("as_name"):
        parts.append(f"AS name: {as_name}")
    if prefix := data.get("prefix"):
        parts.append(f"Prefix: {prefix}")
    if registry := data.get("registry"):
        parts.append(f"Registry: {registry}")
    if country_code := data.get("country_code"):
        parts.append(f"Country: {country_code}")
    if allocated := data.get("allocated"):
        parts.append(f"Allocated: {allocated}")

    return "; ".join(parts) if parts else "Team Cymru ASN record found"


@plugin.use
def enrich(type_name: str, value: str, params: Params, *_args) -> QueryEntry:
    """Run Team Cymru ASN enrichment on an IP selector."""
    if type_name not in SUPPORTED_TYPES:
        raise InvalidDataException(
            message=f"Type name `{type_name}` is invalid. Valid types are: {', '.join(sorted(SUPPORTED_TYPES))}"
        )

    logger.info(f"Enriching [{type_name}] {value} limit {params.limit} (annotate={params.annotate})")

    data = _lookup(value)
    link = Url(FRONTEND_URL)
    value_label = f"AS{data['asn']}" if data.get("asn") else data["ip"]
    result = QueryEntry(classification=CLASSIFICATION, count=1, link=link, raw_data=data if params.raw else None)

    if params.annotate:
        result.annotations.append(
            Annotation(
                analytic="Team Cymru - IP to ASN",
                analytic_icon="material-symbols:hub-outline",
                type="context",
                value=value_label,
                summary=_summary(data),
                details=textwrap.dedent(f"""\
                    # Team Cymru IP to ASN

                    IP: {data.get('ip')}

                    ASN: {data.get('asn') or 'Unknown'}

                    AS name: {data.get('as_name') or 'Unknown'}

                    Prefix: {data.get('prefix') or 'Unknown'}

                    Registry: {data.get('registry') or 'Unknown'}

                    Country: {data.get('country_code') or 'Unknown'}

                    Allocated: {data.get('allocated') or 'Unknown'}
                    """),
                confidence=1.0,
                link=link,
                icon=f"flag:{data['country_code'].lower()}-4x3" if data.get("country_code") else None,
            )
        )

    return result


app = plugin.app


def main():
    """Main executor function."""
    plugin.app.run(host="0.0.0.0", port=int(os.environ.get("PLUGIN_PORT", os.environ.get("PORT", 8000))), debug=False)  # noqa: S104


if __name__ == "__main__":
    main()
