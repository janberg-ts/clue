"""DNS Lookup Plugin

Status: In Development

Provides DNS context for hostnames, domains, and IP addresses.
"""

import ipaddress
import os
import textwrap
from typing import Any

import dns.exception
import dns.reversename
import dns.resolver
from clue.common.exceptions import InvalidDataException, TimeoutException
from clue.common.logging import get_logger
from clue.models.network import Annotation, QueryEntry
from clue.plugin import CluePlugin
from clue.plugin.utils import Params

CLASSIFICATION = os.environ.get("CLASSIFICATION", "TLP:CLEAR")

logger = get_logger(__file__)

SUPPORTED_TYPES = {"domain", "hostname", "ipv4", "ipv6"}
DEFAULT_RECORD_TYPES = "A,AAAA,MX,NS,CNAME"
ANALYTIC = "DNS Lookup"


def _csv_env(name: str, default: str = "") -> list[str]:
    return [item.strip() for item in os.environ.get(name, default).split(",") if item.strip()]


RECORD_TYPES = [record_type.upper() for record_type in _csv_env("DNS_LOOKUP_RECORD_TYPES", DEFAULT_RECORD_TYPES)]
MAX_RESULTS = int(os.environ.get("DNS_LOOKUP_MAX_RESULTS", "50"))
TIMEOUT = float(os.environ.get("DNS_LOOKUP_TIMEOUT", "3.0"))

resolver = dns.resolver.Resolver()
resolver.timeout = TIMEOUT
resolver.lifetime = TIMEOUT

if resolvers := _csv_env("DNS_LOOKUP_RESOLVERS"):
    resolver.nameservers = resolvers

plugin = CluePlugin(
    app_name=os.environ.get("APP_NAME", "dns-lookup"),
    classification=CLASSIFICATION,
    enable_apm=False,
    enable_cache=True,
    supported_types=SUPPORTED_TYPES,
    logger=logger,
)


def _record_value(record: Any) -> str:
    if hasattr(record, "exchange"):
        exchange = record.exchange.to_text().rstrip(".") or "."
        return f"{record.preference} {exchange}"

    return record.to_text().strip('"').rstrip(".")


def _resolve_record(value: str, record_type: str, max_results: int) -> list[dict[str, str]]:
    try:
        answers = resolver.resolve(value, record_type)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.Timeout as e:
        raise TimeoutException(f"DNS lookup timed out for {value} {record_type}", cause=e) from e
    except dns.exception.DNSException as e:
        logger.warning("DNS lookup failed for %s %s: %s", value, record_type, e)
        return []

    records = []
    for answer in answers:
        records.append({"type": record_type, "value": _record_value(answer)})
        if len(records) >= max_results:
            break

    return records


def _resolve_name(value: str, max_results: int) -> list[dict[str, str]]:
    records = []
    for record_type in RECORD_TYPES:
        if len(records) >= max_results:
            break
        records.extend(_resolve_record(value, record_type, max_results - len(records)))

    return records


def _resolve_ptr(value: str, max_results: int) -> list[dict[str, str]]:
    try:
        reverse_name = dns.reversename.from_address(str(ipaddress.ip_address(value)))
    except ValueError as e:
        raise InvalidDataException(f"Unable to interpret {value} as an IP address") from e

    records = _resolve_record(str(reverse_name), "PTR", max_results)
    for record in records:
        record["query"] = str(reverse_name)

    return records


def _annotation(record: dict[str, str]) -> Annotation:
    summary = f"{record['type']} record: {record['value']}"

    return Annotation(
        analytic=ANALYTIC,
        analytic_icon="iconoir:dns",
        icon="iconoir:dns",
        type="context",
        value=record["value"],
        summary=summary,
        details=textwrap.dedent(f"""\
            # DNS Lookup

            Record type: {record['type']}

            Value: {record['value']}
            """),
        confidence=1.0,
    )


@plugin.use
def enrich(type_name: str, value: str, params: Params, *_args) -> QueryEntry:
    "Enrich a given indicator with DNS records"
    if type_name not in SUPPORTED_TYPES:
        raise InvalidDataException(
            message=f"Type name `{type_name}` is invalid. Valid types are: {', '.join(SUPPORTED_TYPES)}"
        )

    max_results = min(params.limit, MAX_RESULTS)
    logger.info(f"Enriching [{type_name}] {value} limit {max_results} (annotate={params.annotate})")

    if type_name in {"ipv4", "ipv6"}:
        records = _resolve_ptr(value, max_results)
    else:
        records = _resolve_name(value, max_results)

    annotations = [_annotation(record) for record in records] if params.annotate else []

    return QueryEntry(
        classification=CLASSIFICATION,
        count=len(records),
        annotations=annotations,
        raw_data=records if params.raw else None,
    )