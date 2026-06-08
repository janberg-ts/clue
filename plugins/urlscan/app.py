"""URLScan Clue Plugin

Status: In Development

Clue plugin to search existing URLScan results for URL and domain selectors.
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

URLSCAN_API_KEY = os.environ.get("URLSCAN_API_KEY", "")
CLASSIFICATION = os.environ.get("CLASSIFICATION", "TLP:CLEAR")
API_URL = os.environ.get("URLSCAN_API_URL", "https://urlscan.io/api/v1").rstrip("/")
FRONTEND_URL = os.environ.get("URLSCAN_FRONTEND_URL", "https://urlscan.io").rstrip("/")
DATE_RANGE = os.environ.get("URLSCAN_DATE_RANGE", "date:>now-30d")
MAX_RESULTS = int(os.environ.get("URLSCAN_MAX_RESULTS", "10"))
SUPPORTED_TYPES = {"url", "domain", "hostname"}

verify: Union[str, bool] = str(os.environ.get("URLSCAN_VERIFY", "true"))
verify_bool = verify.lower()
if verify_bool in ("true", "1"):
    verify = True
elif verify_bool in ("false", "0"):
    verify = False
VERIFY = verify

plugin = CluePlugin(
    app_name=os.environ.get("APP_NAME", "urlscan"),
    classification=CLASSIFICATION,
    enable_apm=False,
    enable_cache=True,
    supported_types=SUPPORTED_TYPES,
    logger=logger,
)


def _escape_query_value(value: str) -> str:
    reserved = set(r'+-=&&||><!(){}[]^"~*?:\/')
    return "".join(f"\\{character}" if character in reserved else character for character in value)


def _search_query(type_name: str, value: str) -> str:
    escaped = _escape_query_value(value.lower())
    if type_name == "url":
        query = f'(task.url:"{escaped}" OR page.url:"{escaped}" OR canonical.task.url:"{escaped}")'
    else:
        query = f"domain:{escaped}"

    return f"{query} {DATE_RANGE}" if DATE_RANGE else query


def search_urlscan(type_name: str, value: str, params: Params) -> dict[str, Any]:
    """Search URLScan for an existing scan result."""
    if not URLSCAN_API_KEY:
        raise UnprocessableException("No API key is provided. Set URLSCAN_API_KEY.")

    headers = {
        "Accept": "application/json",
        "API-Key": URLSCAN_API_KEY,
    }
    query_params = {
        "q": _search_query(type_name, value),
        "size": min(params.limit, MAX_RESULTS),
    }

    try:
        response = requests.get(f"{API_URL}/search/", headers=headers, params=query_params, verify=VERIFY, timeout=params.max_timeout)
    except requests.exceptions.Timeout as e:
        raise TimeoutException("URLScan failed to respond in time.", cause=e) from e

    if response.status_code == 404:
        raise NotFoundException("No result found")
    if response.status_code in {401, 403}:
        raise UnprocessableException("URLScan API key was rejected.")
    if response.status_code == 429:
        raise ClueException("URLScan rate limit was exceeded.")
    if response.status_code != 200:
        raise ClueException(f"Error querying URLScan [{response.status_code}]")

    data = response.json()
    if not data.get("results"):
        raise NotFoundException("No result found")

    return data


def _result_url(result: dict[str, Any]) -> str:
    if result.get("result"):
        return str(result["result"])
    if result.get("_id"):
        return f"{FRONTEND_URL}/result/{result['_id']}/"
    task = result.get("task") or {}
    return task.get("reportURL") or FRONTEND_URL


def _summary(result: dict[str, Any], total: int) -> str:
    page = result.get("page") or {}
    task = result.get("task") or {}
    verdicts = result.get("verdicts") or {}
    score = verdicts.get("score")
    malicious = verdicts.get("malicious")

    parts = [f"Results: {total}"]
    if task.get("url"):
        parts.append(f"Task URL: {task['url']}")
    if page.get("domain"):
        parts.append(f"Page domain: {page['domain']}")
    if page.get("ip"):
        parts.append(f"Page IP: {page['ip']}")
    if score is not None:
        parts.append(f"Score: {score}")
    if malicious is not None:
        parts.append(f"Malicious: {malicious}")

    return "; ".join(parts)


def _details(result: dict[str, Any], total: int) -> str:
    page = result.get("page") or {}
    task = result.get("task") or {}
    stats = result.get("stats") or {}
    verdicts = result.get("verdicts") or {}

    return textwrap.dedent(f"""\
        # URLScan Search Result

        Total results: {total}

        Task URL: {task.get('url') or 'Unknown'}

        Page URL: {page.get('url') or 'Unknown'}

        Page domain: {page.get('domain') or 'Unknown'}

        Page IP: {page.get('ip') or 'Unknown'}

        Page title: {page.get('title') or 'Unknown'}

        Requests: {stats.get('requests', 'Unknown')}

        Unique IPs: {stats.get('uniqIPs', 'Unknown')}

        Score: {verdicts.get('score', 'Unknown')}

        Malicious: {verdicts.get('malicious', 'Unknown')}
        """)


@plugin.use
def enrich(type_name: str, value: str, params: Params, *_args) -> QueryEntry:
    """Run URLScan search enrichment on a URL, domain, or hostname selector."""
    if type_name not in SUPPORTED_TYPES:
        raise InvalidDataException(
            message=f"Type name `{type_name}` is invalid. Valid types are: {', '.join(sorted(SUPPORTED_TYPES))}"
        )

    logger.info(f"Enriching [{type_name}] {value} limit {params.limit} (annotate={params.annotate})")

    data = search_urlscan(type_name, value, params)
    results = data.get("results") or []
    total = data.get("total") or len(results)
    first_result = results[0]
    result_link = Url(_result_url(first_result))
    verdicts = first_result.get("verdicts") or {}
    malicious = verdicts.get("malicious") is True

    result = QueryEntry(
        classification=CLASSIFICATION,
        link=result_link,
        count=min(total, len(results)),
        annotations=[],
        raw_data=data if params.raw else None,
    )

    if not params.annotate:
        return result

    result.annotations.append(
        Annotation(
            analytic="URLScan - Search Result",
            analytic_icon="simple-icons:urlscan",
            type="opinion" if malicious else "context",
            value="malicious" if malicious else "observed",
            summary=_summary(first_result, total),
            details=_details(first_result, total),
            confidence=1.0 if malicious else 0.7,
            quantity=total,
            link=result_link,
        )
    )

    return result


app = plugin.app


def main():
    """Main executor function."""
    plugin.app.run(host="0.0.0.0", port=int(os.environ.get("PLUGIN_PORT", os.environ.get("PORT", 8000))), debug=False)  # noqa: S104


if __name__ == "__main__":
    main()
