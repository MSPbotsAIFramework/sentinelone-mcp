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
"""Tool calls through purple-mcp with the HTTP layer mocked, and error mapping."""

import asyncio
import json

import httpx
import pytest
from purple_mcp.tools import alerts

from sentinelone_mcp.purple import build_settings, use_settings
from sentinelone_mcp.server import create_mcp_server
from sentinelone_mcp.tools import _envelope_for

TENANT_A = build_settings("https://a.sentinelone.net", "tok-A")
TENANT_B = build_settings("https://b.sentinelone.net", "tok-B")


async def _call(tool: str, args: dict, settings=TENANT_A):
    with use_settings(settings):
        content, _ = await create_mcp_server().call_tool(tool, args)
    return content[0].text


@pytest.fixture
def http(monkeypatch):
    """Capture every request purple-mcp sends and answer with a canned GraphQL alert."""
    seen: list[httpx.Request] = []

    async def send(self, request, *args, **kwargs):
        seen.append(request)
        body = {"data": {"alert": {"id": "alert-1", "name": "Suspicious PowerShell", "severity": "HIGH", "status": "NEW"}}}
        return httpx.Response(200, json=body, request=request)

    monkeypatch.setattr(httpx.AsyncClient, "send", send)
    return seen


async def test_get_alert_goes_to_the_requests_console_with_its_token(http):
    text = await _call("get_alert", {"alert_id": "alert-1"})
    request = http[0]
    assert request.url.host == "a.sentinelone.net"
    assert request.url.path == "/web/api/v2.1/unifiedalerts/graphql"
    assert request.headers["Authorization"] == "Bearer tok-A"
    assert "Suspicious PowerShell" in text


async def test_concurrent_tenants_reach_their_own_consoles(http):
    await asyncio.gather(
        _call("get_alert", {"alert_id": "alert-1"}, TENANT_A),
        _call("get_alert", {"alert_id": "alert-1"}, TENANT_B),
    )
    pairs = sorted((r.url.host, r.headers["Authorization"]) for r in http)
    assert pairs == [("a.sentinelone.net", "Bearer tok-A"), ("b.sentinelone.net", "Bearer tok-B")]


async def test_arguments_are_passed_through(monkeypatch):
    captured = {}

    async def fake(**kwargs):
        captured.update(kwargs)
        return '{"edges": []}'

    monkeypatch.setattr(alerts, "search_alerts", fake)
    filters = '[{"fieldId": "severity", "filterType": "string_equals", "value": "CRITICAL"}]'
    text = await _call("search_alerts", {"filters": filters, "first": 1, "view_type": "UNASSIGNED"})
    assert text == '{"edges": []}'
    assert json.loads(captured["filters"]) == json.loads(filters)
    assert {k: v for k, v in captured.items() if k != "filters"} == {"first": 1, "after": None, "view_type": "UNASSIGNED", "fields": None}


async def test_parsed_filters_and_fields_are_sent_as_json_text(monkeypatch):
    captured = {}

    async def fake(**kwargs):
        captured.update(kwargs)
        return "{}"

    monkeypatch.setattr(alerts, "list_alerts", fake)
    await _call("list_alerts", {"fields": ["id", "severity"]})
    assert captured["fields"] == '["id","severity"]'


async def test_value_errors_become_invalid_argument(monkeypatch):
    async def fake(**kwargs):
        raise ValueError("filters must be a JSON array")

    monkeypatch.setattr(alerts, "search_alerts", fake)
    result = json.loads(await _call("search_alerts", {"filters": "nope"}))
    assert result["error"] == {"code": "invalid_argument", "message": "filters must be a JSON array", "retryable": False}


async def test_out_of_range_page_size_is_rejected_before_the_library():
    with use_settings(TENANT_A):
        with pytest.raises(Exception):
            await create_mcp_server().call_tool("list_alerts", {"first": 500})


@pytest.mark.parametrize(
    "message,code,retryable",
    [
        ("HTTP 401: Unauthorized", "unauthorized", False),
        ("GraphQL request failed with status 403", "unauthorized", False),
        ("Alert not found (404)", "not_found", False),
        ("Too many requests: 429", "rate_limited", True),
        ("Server error 502 from console", "upstream_error", True),
        ("Invalid token supplied", "unauthorized", False),
        ("Connection reset", "upstream_error", True),
    ],
)
def test_error_mapping(message, code, retryable):
    envelope = json.loads(_envelope_for(RuntimeError(message)))["error"]
    assert (envelope["code"], envelope["retryable"]) == (code, retryable)


def test_wrapped_http_errors_are_classified_by_their_cause():
    try:
        try:
            raise RuntimeError('HTTP error from alerts API (HTTP 401). Details: {"title":"UNAUTHORIZED"}')
        except RuntimeError as inner:
            raise RuntimeError("Failed to list alerts") from inner
    except RuntimeError as outer:
        envelope = json.loads(_envelope_for(outer))["error"]
    assert envelope["code"] == "unauthorized" and envelope["retryable"] is False
    assert envelope["message"].startswith("Failed to list alerts: HTTP error from alerts API (HTTP 401)")


async def test_local_tools_need_no_console():
    content, _ = await create_mcp_server().call_tool("iso_to_unix_timestamp", {"iso_datetime": "2026-06-01T00:00:00Z"})
    assert "1780272000000" in content[0].text
    content, _ = await create_mcp_server().call_tool("get_timestamp_range", {"hours": 24})
    assert "offset_time" in content[0].text


async def test_threat_intel_without_virustotal_key_explains(monkeypatch):
    text = await _call("threat_intel_by_hash", {"hash_value": "44d88612fea8a8f36de82e1278abb02f"})
    result = json.loads(text) if text.startswith("{") else {"raw": text}
    assert "virustotal" in json.dumps(result).lower() or "vt" in json.dumps(result).lower()
