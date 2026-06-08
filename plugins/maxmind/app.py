"""MaxMind GeoLite2 Clue Plugin

Status: In Development

Provides IP geolocation and ASN context from local MaxMind GeoLite2 databases.
"""

import ipaddress
import os
import textwrap
from pathlib import Path
from typing import Any

import geoip2.database
import geoip2.errors
from clue.common.exceptions import InvalidDataException, NotFoundException, UnprocessableException
from clue.common.logging import get_logger
from clue.models.network import Annotation, QueryEntry
from clue.plugin import CluePlugin
from clue.plugin.utils import Params
from pydantic_core import Url

CLASSIFICATION = os.environ.get("CLASSIFICATION", "TLP:CLEAR")
FRONTEND_URL = os.environ.get("MAXMIND_FRONTEND_URL", "https://www.maxmind.com/en/geoip-demo")
SUPPORTED_TYPES = {"ipv4", "ipv6"}

DEFAULT_ASN_DB = "/data/maxmind/GeoLite2-ASN.mmdb,/usr/share/GeoIP/GeoLite2-ASN.mmdb,/var/lib/GeoIP/GeoLite2-ASN.mmdb"
DEFAULT_COUNTRY_DB = (
    "/data/maxmind/GeoLite2-Country.mmdb,/usr/share/GeoIP/GeoLite2-Country.mmdb,/var/lib/GeoIP/GeoLite2-Country.mmdb"
)
DEFAULT_CITY_DB = "/data/maxmind/GeoLite2-City.mmdb,/usr/share/GeoIP/GeoLite2-City.mmdb,/var/lib/GeoIP/GeoLite2-City.mmdb"

logger = get_logger(__file__)

plugin = CluePlugin(
    app_name=os.environ.get("APP_NAME", "maxmind"),
    classification=CLASSIFICATION,
    enable_apm=False,
    enable_cache=True,
    supported_types=SUPPORTED_TYPES,
    logger=logger,
)

readers: dict[str, geoip2.database.Reader | None] = {
    "asn": None,
    "country": None,
    "city": None,
}


def _candidate_paths(name: str, default: str) -> list[Path]:
    return [Path(item.strip()) for item in os.environ.get(name, default).split(",") if item.strip()]


def _first_existing_path(name: str, default: str) -> Path | None:
    for path in _candidate_paths(name, default):
        if path.is_file():
            return path
    return None


def _get_reader(kind: str) -> geoip2.database.Reader | None:
    if kind in readers and readers[kind] is not None:
        return readers[kind]

    path = {
        "asn": _first_existing_path("MAXMIND_ASN_DB", DEFAULT_ASN_DB),
        "country": _first_existing_path("MAXMIND_COUNTRY_DB", DEFAULT_COUNTRY_DB),
        "city": _first_existing_path("MAXMIND_CITY_DB", DEFAULT_CITY_DB),
    }[kind]

    if path is None:
        return None

    readers[kind] = geoip2.database.Reader(str(path))
    return readers[kind]


def _validate_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        return ipaddress.ip_address(value)
    except ValueError as e:
        raise InvalidDataException(f"Unable to interpret {value} as an IP address") from e


def _lookup_asn(value: str) -> dict[str, Any] | None:
    reader = _get_reader("asn")
    if reader is None:
        return None

    try:
        response = reader.asn(value)
    except geoip2.errors.AddressNotFoundError:
        return None

    return {
        "asn": response.autonomous_system_number,
        "organization": response.autonomous_system_organization,
        "network": str(response.network) if response.network else None,
    }


def _lookup_country(value: str) -> dict[str, Any] | None:
    reader = _get_reader("country")
    if reader is None:
        return None

    try:
        response = reader.country(value)
    except geoip2.errors.AddressNotFoundError:
        return None

    return {
        "country_iso_code": response.country.iso_code,
        "country_name": response.country.name,
        "continent_code": response.continent.code,
        "continent_name": response.continent.name,
    }


def _lookup_city(value: str) -> dict[str, Any] | None:
    reader = _get_reader("city")
    if reader is None:
        return None

    try:
        response = reader.city(value)
    except geoip2.errors.AddressNotFoundError:
        return None

    return {
        "city_name": response.city.name,
        "country_iso_code": response.country.iso_code,
        "country_name": response.country.name,
        "continent_code": response.continent.code,
        "continent_name": response.continent.name,
        "latitude": response.location.latitude,
        "longitude": response.location.longitude,
        "accuracy_radius": response.location.accuracy_radius,
        "time_zone": response.location.time_zone,
    }


def _lookup(value: str) -> dict[str, Any]:
    address = _validate_ip(value)
    data: dict[str, Any] = {"ip": str(address)}

    available = False
    for kind in ("asn", "country", "city"):
        if _get_reader(kind) is not None:
            available = True
            break

    if not available:
        raise UnprocessableException("No MaxMind GeoLite2 database files were found. Mount .mmdb files or set MAXMIND_*_DB paths.")

    if asn := _lookup_asn(str(address)):
        data["asn"] = asn
    if country := _lookup_country(str(address)):
        data["country"] = country
    if city := _lookup_city(str(address)):
        data["city"] = city

    if len(data) == 1:
        raise NotFoundException("No MaxMind GeoLite2 record found")

    return data


def _summary(data: dict[str, Any]) -> str:
    parts = []
    if asn := data.get("asn"):
        if asn.get("asn"):
            parts.append(f"ASN: AS{asn['asn']}")
        if asn.get("organization"):
            parts.append(f"Organization: {asn['organization']}")
    location = data.get("city") or data.get("country")
    if location:
        if location.get("city_name"):
            parts.append(f"City: {location['city_name']}")
        if location.get("country_name"):
            parts.append(f"Country: {location['country_name']}")

    return "; ".join(parts) if parts else "MaxMind GeoLite2 record found"


def _details(data: dict[str, Any]) -> str:
    asn = data.get("asn", {})
    location = data.get("city") or data.get("country") or {}

    return textwrap.dedent(f"""\
        # MaxMind GeoLite2

        IP: {data.get('ip')}

        ASN: {f"AS{asn.get('asn')}" if asn.get('asn') else 'Unknown'}

        Organization: {asn.get('organization') or 'Unknown'}

        Network: {asn.get('network') or 'Unknown'}

        Country: {location.get('country_name') or 'Unknown'}

        Country code: {location.get('country_iso_code') or 'Unknown'}

        City: {location.get('city_name') or 'Unknown'}

        Time zone: {location.get('time_zone') or 'Unknown'}
        """)


@plugin.use
def enrich(type_name: str, value: str, params: Params, *_args) -> QueryEntry:
    """Run MaxMind GeoLite2 enrichment on an IP selector."""
    if type_name not in SUPPORTED_TYPES:
        raise InvalidDataException(
            message=f"Type name `{type_name}` is invalid. Valid types are: {', '.join(sorted(SUPPORTED_TYPES))}"
        )

    logger.info(f"Enriching [{type_name}] {value} limit {params.limit} (annotate={params.annotate})")

    data = _lookup(value)
    link = Url(FRONTEND_URL)
    result = QueryEntry(classification=CLASSIFICATION, count=1, link=link, raw_data=data if params.raw else None)

    if params.annotate:
        location = data.get("city") or data.get("country") or {}
        result.annotations.append(
            Annotation(
                analytic="MaxMind GeoLite2 - IP Context",
                analytic_icon="gis:globe-users",
                type="context",
                value=data.get("ip", value),
                summary=_summary(data),
                details=_details(data),
                confidence=1.0,
                link=link,
                icon=f"flag:{location['country_iso_code'].lower()}-4x3" if location.get("country_iso_code") else None,
            )
        )

    return result


app = plugin.app


def main():
    """Main executor function."""
    plugin.app.run(host="0.0.0.0", port=int(os.environ.get("PLUGIN_PORT", os.environ.get("PORT", 8000))), debug=False)  # noqa: S104


if __name__ == "__main__":
    main()
