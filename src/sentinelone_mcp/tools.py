# Copyright 2026 MSPbots.ai
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""The SentinelOne tools: thin, documented wrappers over purple-mcp's tool functions.

Tool names and parameters follow purple-mcp exactly. Each wrapper adds a
concise description, parameter documentation, the standard error envelope and
the per-request credential check; the API work is done by purple-mcp.
"""

import asyncio
import inspect
import logging
import re
import time
from collections.abc import Callable
from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from ._json import compact as to_json
from ._json import error_envelope
from .purple import MissingCredentials, current_settings

# Imported after .purple so the settings bridge is in place first.
from purple_mcp.tools import (  # noqa: E402  isort: skip
    alerts,
    cve,
    inventory,
    misconfigurations,
    purple_ai as purple_ai_module,
    purple_utils,
    sdl,
    threat_intelligence,
    vulnerabilities,
)

logger = logging.getLogger("sentinelone_mcp.tools")

READ_ONLY = ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=True)
# Purple AI answers differ between calls and keep a conversation session.
READ_ONLY_RUN = ToolAnnotations(readOnlyHint=True, idempotentHint=False, openWorldHint=True)
LOCAL = ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=False)

NOT_CONFIGURED = error_envelope(
    "not_configured",
    "SentinelOne credentials are missing for this request (X-Purplemcp-Base-Url, X-Purplemcp-Token).",
    False,
)

# ---- shared parameter documentation -------------------------------------------

First = Annotated[int, Field(description="Records to return, 1-100 (default 10).", ge=1, le=100)]
After = Annotated[str | None, Field(description="pageInfo.endCursor from the previous page.")]
HistoryFirst = Annotated[int, Field(description="History events to return, 1-100 (default 10).", ge=1, le=100)]
FILTER_SHAPE = (
    'JSON string: an array of {"fieldId", "filterType", ...} objects (max 50), ANDed. filterType: '
    'string_equals {"value"}, string_in {"values"}, boolean_equals {"value"}, boolean_in {"values"}, '
    'datetime_range {"start","end"} in epoch ms from iso_to_unix_timestamp, fulltext {"values"}; '
    'add "isNegated": true to invert. fieldIds are flat camelCase (assetName, not asset.name).'
)
AlertFilters = Annotated[
    str | list[dict[str, Any]] | None,
    Field(
        description=FILTER_SHAPE + " Alert fieldIds: id, severity (CRITICAL..INFO), status (NEW, IN_PROGRESS, "
        "RESOLVED, FALSE_POSITIVE), alertName (fulltext), detectedAt, createdAt (default date field), "
        "analystVerdict, assigneeUserId (long_equals/long_in), assigneeFullName, alertNoteExists, "
        "storylineId, description."
    ),
]
AlertFields = Annotated[
    str | list[str] | None,
    Field(
        description='JSON array of fields to return, e.g. ["id","severity","status","name","detectedAt"]; '
        "omit for all. Others: externalId, description, firstSeenAt, lastSeenAt, analystVerdict, "
        "classification, confidenceLevel, noteExists, result, storylineId, ticketId, dataSources (only "
        "when listed), detectionSource, asset, assignee."
    ),
]
AlertView = Annotated[
    Literal["ALL", "ASSIGNED_TO_ME", "UNASSIGNED", "MY_TEAM"], Field(description="Assignment filter (default ALL).")
]
MisconfigView = Annotated[
    Literal[
        "ALL",
        "CLOUD",
        "KUBERNETES",
        "IDENTITY",
        "INFRASTRUCTURE_AS_CODE",
        "ADMISSION_CONTROLLER",
        "OFFENSIVE_SECURITY",
        "SECRET_SCANNING",
    ],
    Field(description="Environment filter (default ALL)."),
]
MisconfigFilters = Annotated[
    str | list[dict[str, Any]] | None,
    Field(
        description=FILTER_SHAPE + " Only string, boolean and datetime filters. Misconfiguration fieldIds: id, "
        "name, severity, status (NEW, IN_PROGRESS, ON_HOLD, RESOLVED, RISK_ACKED, SUPPRESSED, TO_BE_PATCHED), "
        "detectedAt, lastSeenAt, environment, product, vendor, analystVerdict, assigneeFullName, mitigable, "
        "asset* (assetName, assetType, assetCriticality, assetCloudAccount, assetCloudRegion, "
        "assetKubernetesCluster, ...), policyId, policyGroup, complianceStandards, hasClassifiedData, "
        "secretType, secretValidity (boolean_in only), requestResourceName, iacFramework."
    ),
]
MisconfigFields = Annotated[
    str | list[str] | None,
    Field(
        description='JSON array of fields to return, e.g. ["id","name","severity","status","asset"]; omit for '
        "all. Others: detectedAt, lastSeenAt, environment, product, vendor, analystVerdict, mitigable, "
        "misconfigurationType, scope, assignee, evidence, cnapp, remediation, mitreAttacks, complianceStandards."
    ),
]
VulnFilters = Annotated[
    str | list[dict[str, Any]] | None,
    Field(
        description=FILTER_SHAPE + " Only string, boolean and datetime filters. Vulnerability fieldIds: id, name, "
        "severity, status, detectedAt, lastSeenAt, product, vendor, analystVerdict, assigneeFullName, cveId, "
        "cveEpssScore (string_in ranges 0.0-0.35, 0.35-0.5, 0.5-0.75, 0.75-1.0), cveExploitMaturity, "
        "cveExploitedInTheWild, cveKevAvailable, softwareName, softwareVersion, softwareFixVersionAvailable, "
        "softwareType, softwareVendor, asset* (assetName, assetType, assetCriticality, ...)."
    ),
]
VulnFields = Annotated[
    str | list[str] | None,
    Field(
        description='JSON array of fields to return, e.g. ["id","name","severity","cve","software","asset"]; '
        "omit for all. Others: status, detectedAt, lastSeenAt, product, vendor, analystVerdict, scope, assignee."
    ),
]
FetchFields = Annotated[
    Literal["MINIMAL", "STANDARD", "ALL"] | list[str],
    Field(description='MINIMAL (7 fields), STANDARD (13) or ALL (~200), or a list of camelCase field names.'),
]
InventoryLimit = Annotated[int, Field(description="Items to return, 1-1000 (default 50).", ge=1, le=1000)]
InventorySkip = Annotated[int, Field(description="Items to skip for paging (default 0).", ge=0)]
Hash = Annotated[str, Field(description="File hash: MD5, SHA-1 or SHA-256.", min_length=32)]

# Whole-call budget: the gateway times a tool call out at 120s, while purple-mcp
# allows Purple AI 120s per request and polls PowerQuery results for up to 5 minutes.
CALL_BUDGET_SECONDS = 100.0

_STATUS = re.compile(r"\b(401|403|404|429|5\d\d)\b")


def _chain(error: BaseException) -> list[BaseException]:
    """The error and its causes, outermost first (the library wraps HTTP errors)."""
    chain: list[BaseException] = []
    current: BaseException | None = error
    while current is not None and current not in chain and len(chain) < 10:
        chain.append(current)
        current = current.__cause__ or current.__context__
    return chain


def _envelope_for(error: Exception) -> str:
    messages = [str(e).strip() or type(e).__name__ for e in _chain(error)]
    message = messages[0] if len(messages) == 1 else f"{messages[0]}: {messages[-1]}"
    status = next((m for m in (_STATUS.search(text) for text in reversed(messages)) if m), None)
    code, retryable = "upstream_error", True
    if status:
        value = status.group(1)
        code, retryable = {
            "401": ("unauthorized", False),
            "403": ("unauthorized", False),
            "404": ("not_found", False),
            "429": ("rate_limited", True),
        }.get(value, ("upstream_error", True))
    elif re.search(r"unauthori[sz]ed|forbidden|invalid token|authentication", message, re.IGNORECASE):
        code, retryable = "unauthorized", False
    return error_envelope(code, message[:800], retryable)


def _as_json_text(value: Any) -> Any:
    """purple-mcp takes filters / fields as JSON text; accept parsed JSON too."""
    return to_json(value) if isinstance(value, (list, dict)) else value


async def _run(name: str, function: Callable[..., Any], needs_console: bool = True, **kwargs: Any) -> str:
    """Call one purple-mcp tool and always return a string (result or error envelope)."""
    for key in ("filters", "fields"):
        if key in kwargs:
            kwargs[key] = _as_json_text(kwargs[key])
    if needs_console and current_settings() is None:
        return NOT_CONFIGURED
    started = time.monotonic()
    try:
        result = function(**kwargs)
        if inspect.isawaitable(result):
            result = await asyncio.wait_for(result, timeout=CALL_BUDGET_SECONDS)
    except MissingCredentials:
        return NOT_CONFIGURED
    except TimeoutError:
        logger.info("tool=%s outcome=timeout ms=%d", name, _ms(started))
        return error_envelope(
            "upstream_error",
            f"SentinelOne did not answer within {CALL_BUDGET_SECONDS:.0f} seconds; narrow the time range or query and try again.",
            True,
        )
    except ValueError as e:
        logger.info("tool=%s outcome=invalid_argument ms=%d", name, _ms(started))
        return error_envelope("invalid_argument", str(e)[:800], False)
    except Exception as e:  # noqa: BLE001 - tools must never raise
        logger.info("tool=%s outcome=error error=%s ms=%d", name, type(e).__name__, _ms(started))
        return _envelope_for(e)
    logger.info("tool=%s outcome=ok ms=%d", name, _ms(started))
    if isinstance(result, str):
        return result
    return to_json(result) if result is not None else to_json({"result": None})


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def register(mcp: FastMCP) -> None:  # noqa: C901 - one block per tool keeps the surface readable
    # ---- Purple AI and the data lake ---------------------------------------------

    @mcp.tool(annotations=READ_ONLY_RUN)
    async def purple_ai(
        query: Annotated[str, Field(description="A plain-language question, e.g. 'Find unsigned processes that accessed lsass.exe'.")],
    ) -> str:
        """Ask SentinelOne Purple AI a hunting question; it answers or returns a PowerQuery to run.

        Describe what to find (processes, paths, domains, users, behaviours); do not ask it to
        'generate a PowerQuery'. It cannot see alerts or change anything. Run returned queries
        with powerquery.
        """
        return await _run("purple_ai", purple_ai_module.purple_ai, query=query)

    @mcp.tool(annotations=READ_ONLY)
    async def powerquery(
        query: Annotated[str, Field(description="The PowerQuery, best taken from purple_ai; run a user's query exactly as given.")],
        start_datetime: Annotated[str, Field(description="Window start, ISO 8601 with offset, e.g. 2026-06-01T00:00:00Z.")],
        end_datetime: Annotated[str, Field(description="Window end, ISO 8601 with offset, later than the start.")],
    ) -> str:
        """Run a PowerQuery over the Singularity Data Lake for a time window (default to the last 24 h).

        Empty results are normal; do not retry the same query. Queries time out after 5 minutes:
        shorten the window if needed.
        """
        return await _run(
            "powerquery", sdl.powerquery, query=query, start_datetime=start_datetime, end_datetime=end_datetime
        )

    @mcp.tool(annotations=LOCAL)
    async def get_timestamp_range(
        reference_time: Annotated[str | None, Field(description="ISO 8601 anchor (default now).")] = None,
        years: int = 0,
        months: int = 0,
        weeks: int = 0,
        days: int = 0,
        hours: int = 0,
        minutes: int = 0,
        seconds: int = 0,
        direction: Annotated[Literal["past", "future"], Field(description="Range before or after the anchor.")] = "past",
    ) -> str:
        """Compute a start / end ISO 8601 window (e.g. hours=24) for powerquery."""
        return await _run(
            "get_timestamp_range",
            sdl.get_timestamp_range,
            needs_console=False,
            reference_time=reference_time,
            years=years,
            months=months,
            weeks=weeks,
            days=days,
            hours=hours,
            minutes=minutes,
            seconds=seconds,
            direction=direction,
        )

    @mcp.tool(annotations=LOCAL)
    async def iso_to_unix_timestamp(
        iso_datetime: Annotated[str, Field(description="ISO 8601 datetime in the user's time zone, e.g. 2026-06-01T08:00:00-04:00.")],
    ) -> str:
        """Convert an ISO 8601 datetime to epoch milliseconds (UTC) for datetime filters in search tools."""
        return await _run(
            "iso_to_unix_timestamp", purple_utils.iso_to_unix_timestamp, needs_console=False, iso_datetime=iso_datetime
        )

    # ---- alerts ---------------------------------------------------------------------

    @mcp.tool(annotations=READ_ONLY)
    async def get_alert(alert_id: Annotated[str, Field(description="Alert id.")]) -> str:
        """Get one alert: severity, status, verdict, detection source, asset, assignee and timing."""
        return await _run("get_alert", alerts.get_alert, alert_id=alert_id)

    @mcp.tool(annotations=READ_ONLY)
    async def list_alerts(
        first: First = 10, after: After = None, view_type: AlertView = "ALL", fields: AlertFields = None
    ) -> str:
        """List alerts, newest first, optionally by assignment; use search_alerts for other filters.

        Returns edges, pageInfo (endCursor for the next page) and totalCount.
        """
        return await _run("list_alerts", alerts.list_alerts, first=first, after=after, view_type=view_type, fields=fields)

    @mcp.tool(annotations=READ_ONLY)
    async def search_alerts(
        filters: AlertFilters = None,
        first: First = 10,
        after: After = None,
        view_type: AlertView = "ALL",
        fields: AlertFields = None,
    ) -> str:
        """Search alerts by severity, status, verdict, assignee, name or time window.

        For 'how many' questions set first=1 and read totalCount.
        """
        return await _run(
            "search_alerts", alerts.search_alerts, filters=filters, first=first, after=after, view_type=view_type, fields=fields
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_alert_notes(alert_id: Annotated[str, Field(description="Alert id.")]) -> str:
        """Get the analyst notes on an alert."""
        return await _run("get_alert_notes", alerts.get_alert_notes, alert_id=alert_id)

    @mcp.tool(annotations=READ_ONLY)
    async def get_alert_history(
        alert_id: Annotated[str, Field(description="Alert id.")], first: HistoryFirst = 10, after: After = None
    ) -> str:
        """Get an alert's audit trail: status changes, assignments and other events, in order."""
        return await _run("get_alert_history", alerts.get_alert_history, alert_id=alert_id, first=first, after=after)

    @mcp.tool(annotations=READ_ONLY)
    async def get_alert_investigation_report(alert_id: Annotated[str, Field(description="Alert id.")]) -> str:
        """Get Purple AI's auto-investigation report for an alert: findings, evidence, verdict, next steps."""
        return await _run("get_alert_investigation_report", alerts.get_alert_investigation_report, alert_id=alert_id)

    # ---- misconfigurations ----------------------------------------------------------

    @mcp.tool(annotations=READ_ONLY)
    async def get_misconfiguration(misconfiguration_id: Annotated[str, Field(description="Misconfiguration id.")]) -> str:
        """Get one misconfiguration: asset, severity, compliance, remediation steps and MITRE mapping."""
        return await _run("get_misconfiguration", misconfigurations.get_misconfiguration, misconfiguration_id=misconfiguration_id)

    @mcp.tool(annotations=READ_ONLY)
    async def list_misconfigurations(
        first: First = 10, after: After = None, view_type: MisconfigView = "ALL", fields: MisconfigFields = None
    ) -> str:
        """List posture misconfigurations (cloud, Kubernetes, identity, IaC, secrets), newest first."""
        return await _run(
            "list_misconfigurations", misconfigurations.list_misconfigurations, first=first, after=after, view_type=view_type, fields=fields
        )

    @mcp.tool(annotations=READ_ONLY)
    async def search_misconfigurations(
        filters: MisconfigFilters = None,
        first: First = 10,
        after: After = None,
        view_type: MisconfigView = "ALL",
        fields: MisconfigFields = None,
    ) -> str:
        """Search misconfigurations by severity, status, asset, cloud account, policy, compliance or time."""
        return await _run(
            "search_misconfigurations",
            misconfigurations.search_misconfigurations,
            filters=filters,
            first=first,
            after=after,
            view_type=view_type,
            fields=fields,
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_misconfiguration_notes(misconfiguration_id: Annotated[str, Field(description="Misconfiguration id.")]) -> str:
        """Get the analyst notes on a misconfiguration."""
        return await _run(
            "get_misconfiguration_notes", misconfigurations.get_misconfiguration_notes, misconfiguration_id=misconfiguration_id
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_misconfiguration_history(
        misconfiguration_id: Annotated[str, Field(description="Misconfiguration id.")],
        first: HistoryFirst = 10,
        after: After = None,
    ) -> str:
        """Get a misconfiguration's audit trail of status changes and other events."""
        return await _run(
            "get_misconfiguration_history",
            misconfigurations.get_misconfiguration_history,
            misconfiguration_id=misconfiguration_id,
            first=first,
            after=after,
        )

    # ---- vulnerabilities ------------------------------------------------------------

    @mcp.tool(annotations=READ_ONLY)
    async def get_vulnerability(vulnerability_id: Annotated[str, Field(description="Vulnerability id.")]) -> str:
        """Get one vulnerability: CVE, risk and EPSS scores, exploit maturity, software, asset, fix."""
        return await _run("get_vulnerability", vulnerabilities.get_vulnerability, vulnerability_id=vulnerability_id)

    @mcp.tool(annotations=READ_ONLY)
    async def list_vulnerabilities(first: First = 10, after: After = None, fields: VulnFields = None) -> str:
        """List vulnerabilities found on assets, newest first."""
        return await _run("list_vulnerabilities", vulnerabilities.list_vulnerabilities, first=first, after=after, fields=fields)

    @mcp.tool(annotations=READ_ONLY)
    async def search_vulnerabilities(
        filters: VulnFilters = None, first: First = 10, after: After = None, fields: VulnFields = None
    ) -> str:
        """Search vulnerabilities by severity, CVE, exploitation, KEV, software, fix availability or asset."""
        return await _run(
            "search_vulnerabilities", vulnerabilities.search_vulnerabilities, filters=filters, first=first, after=after, fields=fields
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_vulnerability_notes(vulnerability_id: Annotated[str, Field(description="Vulnerability id.")]) -> str:
        """Get the analyst notes on a vulnerability."""
        return await _run("get_vulnerability_notes", vulnerabilities.get_vulnerability_notes, vulnerability_id=vulnerability_id)

    @mcp.tool(annotations=READ_ONLY)
    async def get_vulnerability_history(
        vulnerability_id: Annotated[str, Field(description="Vulnerability id.")],
        first: HistoryFirst = 10,
        after: After = None,
    ) -> str:
        """Get a vulnerability's audit trail of status changes and other events."""
        return await _run(
            "get_vulnerability_history",
            vulnerabilities.get_vulnerability_history,
            vulnerability_id=vulnerability_id,
            first=first,
            after=after,
        )

    # ---- asset inventory ------------------------------------------------------------

    @mcp.tool(annotations=READ_ONLY)
    async def get_inventory_item(
        item_id: Annotated[str, Field(description="Inventory item (asset) id.")],
        fetch_fields: FetchFields = "ALL",
    ) -> str:
        """Get one asset from the unified inventory (endpoint, cloud resource, identity or network device)."""
        return await _run("get_inventory_item", inventory.get_inventory_item, item_id=item_id, fetch_fields=fetch_fields)

    @mcp.tool(annotations=READ_ONLY)
    async def list_inventory_items(
        limit: InventoryLimit = 50,
        skip: InventorySkip = 0,
        surface: Annotated[
            Literal["ENDPOINT", "CLOUD", "IDENTITY", "NETWORK_DISCOVERY"] | None,
            Field(description="Only this surface: agents and servers, cloud resources, identities, or discovered devices."),
        ] = None,
        fetch_fields: FetchFields = "MINIMAL",
    ) -> str:
        """List assets in the unified inventory, optionally for one surface."""
        return await _run(
            "list_inventory_items", inventory.list_inventory_items, limit=limit, skip=skip, surface=surface, fetch_fields=fetch_fields
        )

    @mcp.tool(annotations=READ_ONLY)
    async def search_inventory_items(
        filters: Annotated[
            str | dict[str, Any] | None,
            Field(
                description='JSON object of camelCase field -> values, ANDed, e.g. {"resourceType": ["Windows Server"], '
                '"assetStatus": ["Active"]}. Suffixes: __contains (partial, case-insensitive), __nin (exclude), '
                '__in (ids), __between {"from","to"} with dates or epoch ms (lastActiveDt). Common fields: name, '
                "resourceType, assetStatus, category, infectionStatus, osName, cloudProvider, lastActiveDt."
            ),
        ] = None,
        limit: InventoryLimit = 50,
        skip: InventorySkip = 0,
        fetch_fields: FetchFields = "MINIMAL",
    ) -> str:
        """Search the unified inventory by type, status, OS, name, cloud provider or last activity."""
        return await _run(
            "search_inventory_items", inventory.search_inventory_items, filters=filters, limit=limit, skip=skip, fetch_fields=fetch_fields
        )

    # ---- threat intelligence (VirusTotal) -------------------------------------------

    @mcp.tool(annotations=READ_ONLY)
    async def threat_intel_by_hash(hash_value: Hash) -> str:
        """Get VirusTotal intelligence for a file hash: detections, file details, names, signatures, tags."""
        return await _run("threat_intel_by_hash", threat_intelligence.threat_intel_by_hash, hash_value=hash_value)

    @mcp.tool(annotations=READ_ONLY)
    async def threat_intel_by_url(url: Annotated[str, Field(description="Full URL to look up.")]) -> str:
        """Get VirusTotal reputation for a URL: vendor verdicts, categories, redirects, last analysis."""
        return await _run("threat_intel_by_url", threat_intelligence.threat_intel_by_url, url=url)

    @mcp.tool(annotations=READ_ONLY)
    async def threat_intel_by_domain(domain: Annotated[str, Field(description="Domain name, e.g. example.com.")]) -> str:
        """Get VirusTotal reputation for a domain: verdicts, categories, DNS records, WHOIS, certificates."""
        return await _run("threat_intel_by_domain", threat_intelligence.threat_intel_by_domain, domain=domain)

    @mcp.tool(annotations=READ_ONLY)
    async def threat_intel_by_ip(ip_address: Annotated[str, Field(description="IPv4 or IPv6 address.")]) -> str:
        """Get VirusTotal reputation for an IP address: verdicts, owner / ASN, country, related activity."""
        return await _run("threat_intel_by_ip", threat_intelligence.threat_intel_by_ip, ip_address=ip_address)

    @mcp.tool(annotations=READ_ONLY)
    async def threat_intel_get_file_relationships(
        hash_value: Hash,
        relationship_type: Annotated[
            Literal[
                "contacted_domains",
                "contacted_ips",
                "contacted_urls",
                "similar_files",
                "execution_parents",
                "bundled_files",
                "compressed_parents",
                "overlay_parents",
            ],
            Field(description="Which relationship to list."),
        ],
    ) -> str:
        """List a file's VirusTotal relationships: network IOCs it contacted or related / parent files."""
        return await _run(
            "threat_intel_get_file_relationships",
            threat_intelligence.threat_intel_get_file_relationships,
            hash_value=hash_value,
            relationship_type=relationship_type,
        )

    @mcp.tool(annotations=READ_ONLY)
    async def threat_intel_search(
        query: Annotated[
            str, Field(description="VirusTotal Intelligence query, e.g. 'type:peexe positives:5+ tag:ransomware fs:7d-'.")
        ],
    ) -> str:
        """Search VirusTotal Intelligence for files matching a query (needs an Intelligence-enabled key)."""
        return await _run("threat_intel_search", threat_intelligence.threat_intel_search, query=query)

    @mcp.tool(annotations=READ_ONLY)
    async def threat_intel_get_file_behavior(
        hash_value: Hash,
        sandbox: Annotated[str | None, Field(description="One sandbox, e.g. 'VirusTotal Jujubox'; omit for all.")] = None,
    ) -> str:
        """Get VirusTotal sandbox behaviour for a file: processes, network, files, registry, MITRE TTPs."""
        return await _run(
            "threat_intel_get_file_behavior",
            threat_intelligence.threat_intel_get_file_behavior,
            hash_value=hash_value,
            sandbox=sandbox,
        )

    # ---- CVE database (public) ------------------------------------------------------

    @mcp.tool(annotations=READ_ONLY)
    async def cve_search_by_id(cve_id: Annotated[str, Field(description="CVE id, e.g. CVE-2024-3094.")]) -> str:
        """Get a CVE from a public CVE database: description, CVSS, affected products, references, CWE."""
        return await _run("cve_search_by_id", cve.cve_search_by_id, needs_console=False, cve_id=cve_id)

    @mcp.tool(annotations=READ_ONLY)
    async def cve_search_by_vendor(
        vendor: Annotated[str, Field(description="Vendor name, e.g. apache.")],
        product: Annotated[str | None, Field(description="Product name, e.g. httpd; omit to list the vendor's products.")] = None,
    ) -> str:
        """List CVEs for a vendor (and product), or the vendor's products when no product is given."""
        return await _run("cve_search_by_vendor", cve.cve_search_by_vendor, needs_console=False, vendor=vendor, product=product)

    @mcp.tool(annotations=READ_ONLY)
    async def cve_database_status() -> str:
        """Show the public CVE database's last update time and size."""
        return await _run("cve_database_status", cve.cve_database_status, needs_console=False)
