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
from purple_mcp.tools import alerts, cve, inventory, purple_ai

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
    assert json.loads(text) == {"edges": []}  # purple-mcp's JSON text, now compact and size-capped
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


async def test_slow_calls_stop_within_the_budget(monkeypatch):
    from sentinelone_mcp import tools

    async def slow(**kwargs):
        await asyncio.sleep(5)

    monkeypatch.setattr(tools, "CALL_BUDGET_SECONDS", 0.05)
    monkeypatch.setattr(alerts, "search_alerts", slow)
    result = json.loads(await _call("search_alerts", {}))
    assert result["error"]["code"] == "upstream_error"
    assert result["error"]["retryable"] is True
    assert "narrow" in result["error"]["message"]


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



# ---- results go through the size limit; cut lists continue exactly ----------------------------------------
# Checklist: cursor lists cut along the way and walked by next_after return every record once, and the nested
# pageInfo agrees with next_after; an uncut page keeps endCursor as next_after; the last page has none;
# inventory walked by next_skip returns every item once; whole lists walked by next_offset return every record
# once; long text is shortened with a note, short text and small results are unchanged; no retry_page_size
# when the continuation is exact.

def _wide(i):
    return {"id": f"a{i:04d}", "name": f"Alert {i}", **{f"field{k}": f"value {k}" for k in range(40)}}


def _connection(rows, first, after):
    start = 0 if after is None else int(after[1:]) + 1
    chunk = rows[start : start + first]
    edges = [{"node": r, "cursor": f"c{start + i}"} for i, r in enumerate(chunk)]
    more = start + len(chunk) < len(rows)
    info = {"hasNextPage": more, "hasPreviousPage": start > 0, "endCursor": edges[-1]["cursor"] if edges else None}
    return json.dumps({"edges": edges, "pageInfo": info, "totalCount": len(rows)}, indent=2)


async def test_cut_cursor_pages_walked_by_next_after_return_every_record_once(monkeypatch):
    rows = [_wide(i) for i in range(250)]

    async def fake(first, after=None, **_):
        return _connection(rows, first, after)

    monkeypatch.setattr(alerts, "list_alerts", fake)
    ids, after, cut, calls = [], None, 0, 0
    while True:
        out = json.loads(await _call("list_alerts", {"first": 100} | ({"after": after} if after else {})))
        calls += 1
        assert "retry_page_size" not in out
        if out.get("truncated"):
            cut += 1
            assert out["pageInfo"]["endCursor"] == out["next_after"] and out["pageInfo"]["hasNextPage"] is True
        ids += [e["node"]["id"] for e in out["edges"]]
        after = out.get("next_after")
        if not after:
            break
        assert calls < 50
    assert cut > 0 and ids == [r["id"] for r in rows]


async def test_uncut_cursor_page_gives_end_cursor_and_the_last_page_none(monkeypatch):
    rows = [{"id": f"a{i}"} for i in range(15)]

    async def fake(first, after=None, **_):
        return _connection(rows, first, after)

    monkeypatch.setattr(alerts, "list_alerts", fake)
    first = json.loads(await _call("list_alerts", {"first": 10}))
    assert first["next_after"] == "c9" and first["pageInfo"]["endCursor"] == "c9" and "truncated" not in first
    last = json.loads(await _call("list_alerts", {"first": 10, "after": "c9"}))
    assert [e["node"]["id"] for e in last["edges"]] == [f"a{i}" for i in range(10, 15)] and "next_after" not in last


async def test_inventory_walked_by_next_skip_returns_every_item_once(monkeypatch):
    rows = [_wide(i) for i in range(420)]

    async def fake(limit, skip, **_):
        chunk = rows[skip : skip + limit]
        return json.dumps({"data": chunk, "pagination": {"totalCount": len(rows), "limit": limit, "skip": skip}}, indent=2)

    monkeypatch.setattr(inventory, "list_inventory_items", fake)
    ids, skip, cut, calls = [], 0, 0, 0
    while True:
        out = json.loads(await _call("list_inventory_items", {"limit": 200, "skip": skip}))
        calls += 1
        assert "retry_page_size" not in out
        cut += bool(out.get("truncated"))
        ids += [r["id"] for r in out["data"]]
        if out.get("next_skip") is None:
            break
        skip = out["next_skip"]
        assert calls < 100
    assert cut > 0 and ids == [r["id"] for r in rows]


async def test_whole_lists_walked_by_next_offset_return_every_record_once(monkeypatch):
    rows = [{"cve": f"CVE-2026-{i:05d}", "summary": "s" * 200, **{f"f{k}": k for k in range(20)}} for i in range(300)]

    async def fake(vendor, product=None):
        return json.dumps(rows, indent=2)

    monkeypatch.setattr(cve, "cve_search_by_vendor", fake)
    ids, offset, cut, calls = [], None, 0, 0
    while True:
        out = json.loads(await _call("cve_search_by_vendor", {"vendor": "apache"} | ({"offset": offset} if offset else {})))
        calls += 1
        assert "retry_page_size" not in out
        cut += bool(out.get("truncated"))
        ids += [r["cve"] for r in out["items"]]
        offset = out.get("next_offset")
        if offset is None:
            break
        assert calls < 100
    assert cut > 0 and ids == [r["cve"] for r in rows]
    page = json.loads(await _call("cve_search_by_vendor", {"vendor": "apache", "offset": 10, "limit": 3}))
    assert [r["cve"] for r in page["items"]] == ["CVE-2026-00010", "CVE-2026-00011", "CVE-2026-00012"]
    assert (page["next_offset"], page["total"]) == (13, 300)
    past = json.loads(await _call("cve_search_by_vendor", {"vendor": "apache", "offset": 999}))
    assert (past["items"], past["has_more"]) == ([], False)


async def test_long_text_is_shortened_and_short_text_unchanged(monkeypatch):
    long_answer = "Purple AI says: " + "x" * 50_000

    async def fake(query):
        return long_answer if query == "long" else "Short answer."

    monkeypatch.setattr(purple_ai, "purple_ai", fake)
    out = json.loads(await _call("purple_ai", {"query": "long"}))
    assert out["truncated"] is True and out["text"].startswith("Purple AI says: ") and len(json.dumps(out)) <= 20_000
    assert await _call("purple_ai", {"query": "short"}) == "Short answer."


async def test_small_results_keep_their_content(monkeypatch):
    async def fake(alert_id):
        return json.dumps({"id": alert_id, "name": "x", "severity": "HIGH"}, indent=2)

    monkeypatch.setattr(alerts, "get_alert", fake)
    assert json.loads(await _call("get_alert", {"alert_id": "a1"})) == {"id": "a1", "name": "x", "severity": "HIGH"}
