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
"""FastMCP factory and the per-request credential middleware."""

import contextvars
import re
import uuid
from urllib.parse import urlsplit

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .config import Settings
from .purple import build_settings, use_settings

# Header names registered with the gateway, then the alternative names some
# callers send; the first one present wins.
BASE_URL_HEADERS = ("X-Purplemcp-Base-Url", "X-S1-Console-URL")
TOKEN_HEADERS = ("X-Purplemcp-Token", "X-S1-API-Token")
HEADER_VIRUSTOTAL = "X-Virustotal-Api-Key"
REQUIRED_HEADERS = [BASE_URL_HEADERS[0], TOKEN_HEADERS[0]]

_PLACEHOLDER = re.compile(r"^\$\{.*\}$")
_BEARER = re.compile(r"^(bearer|apitoken)\s+", re.IGNORECASE)

request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("sentinelone_request_id", default="-")

INSTRUCTIONS = (
    "SentinelOne Singularity protects endpoints, cloud and identity. These "
    "tools read one SentinelOne console; none of them change anything.\n"
    "Usage:\n"
    "- Hunting: ask purple_ai in plain language (it writes PowerQueries), then "
    "run the returned query with powerquery over a window from "
    "get_timestamp_range (default last 24 h).\n"
    "- Alerts: list_alerts / search_alerts -> get_alert, get_alert_notes, "
    "get_alert_history, get_alert_investigation_report.\n"
    "- Exposure: list/search_vulnerabilities and list/search_misconfigurations, "
    "each with get_*, *_notes and *_history.\n"
    "- Assets: list/search_inventory_items -> get_inventory_item.\n"
    "- search_* take filters as a JSON string; datetime filters need epoch "
    "milliseconds from iso_to_unix_timestamp. Lists page with first + after "
    "(pageInfo.endCursor); ask for fields='[\"id\"]' while paging.\n"
    "- threat_intel_* query VirusTotal (needs the optional VirusTotal key); "
    "cve_* query a public CVE database."
)


def _clean(value: str | None) -> str | None:
    text = (value or "").strip()
    if not text or _PLACEHOLDER.match(text):
        return None
    return text


def normalize_console_url(value: str) -> str | None:
    """https origin of the console (path, query and trailing slash dropped); None if unusable."""
    text = value.strip()
    if "://" not in text:
        text = f"https://{text}"
    parts = urlsplit(text)
    if parts.scheme != "https" or not parts.hostname:
        return None
    return f"https://{parts.netloc}"


class GatewayCredentialsMiddleware:
    """Builds the request's purple-mcp settings from the SentinelOne headers on /mcp.

    Needs the console URL and token; otherwise 401.
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope.get("path", "").startswith("/mcp"):
            await self.app(scope, receive, send)
            return

        request = Request(scope)

        def first(names: tuple[str, ...]) -> str | None:
            return next((v for v in (_clean(request.headers.get(n)) for n in names) if v), None)

        base_url_raw = first(BASE_URL_HEADERS)
        token = first(TOKEN_HEADERS)
        if token:
            token = _clean(_BEARER.sub("", token))
        if not base_url_raw or not token:
            missing = [h for h, v in zip(REQUIRED_HEADERS, (base_url_raw, token), strict=True) if not v]
            await JSONResponse(
                {
                    "error": "Missing credentials",
                    "message": f"Missing header(s): {', '.join(missing)}",
                    "required_headers": REQUIRED_HEADERS,
                    "optional_headers": [HEADER_VIRUSTOTAL],
                },
                status_code=401,
            )(scope, receive, send)
            return

        base_url = normalize_console_url(base_url_raw)
        try:
            if base_url is None:
                raise ValueError(f"{REQUIRED_HEADERS[0]} must be the console's https URL, e.g. https://your-console.sentinelone.net")
            settings = build_settings(base_url, token, _clean(request.headers.get(HEADER_VIRUSTOTAL)))
        except ValueError as e:
            await JSONResponse({"error": "Invalid header", "message": str(e)}, status_code=400)(scope, receive, send)
            return

        request_id = (request.headers.get("x-request-id") or "").strip()[:64] or uuid.uuid4().hex[:12]
        rid_token = request_id_var.set(request_id)
        try:
            with use_settings(settings):
                await self.app(scope, receive, send)
        finally:
            request_id_var.reset(rid_token)


def create_mcp_server(settings: Settings | None = None) -> FastMCP:
    """Build the FastMCP server and register every tool."""
    mcp = FastMCP(
        name="sentinelone-mcp",
        instructions=INSTRUCTIONS,
        # The service sits behind the gateway, so Host is never localhost;
        # DNS-rebinding protection would reject those requests with 421.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        stateless_http=True,
    )

    from .tools import register

    register(mcp)
    return mcp
