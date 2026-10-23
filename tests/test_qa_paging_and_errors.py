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
"""PRD-21366 (snake_case page_info paging) and PRD-21367 (error codes and retryable)."""

import json

import pytest
from purple_mcp.tools import (
    alerts,
    cve,
    misconfigurations,
    threat_intelligence,
    vulnerabilities,
)

from sentinelone_mcp.purple import build_settings, use_settings
from sentinelone_mcp.server import create_mcp_server
from sentinelone_mcp.tools import _envelope_for

TENANT = build_settings("https://a.sentinelone.net", "tok-A")
TENANT_VT = build_settings("https://a.sentinelone.net", "tok-A", virustotal_api_key="vt-key")


async def _call(tool, args, settings=TENANT):
    with use_settings(settings):
        content, _ = await create_mcp_server().call_tool(tool, args)
    return json.loads(content[0].text)


def connection(records, snake: bool, padding: int = 0):
    """A purple-mcp style list: cursor pages over ``records``; snake_case like model_dump_json()."""

    def page(first=10, after=None, **_):
        start = 0 if after is None else int(after.split("-")[1]) + 1
        chunk = records[start : start + first]
        pad = {f"f{k}": "x" * 90 for k in range(padding // 90)}  # many short fields: shortening can't make it fit
        edges = [{"node": {"id": r, **pad}, "cursor": f"c-{records.index(r)}"} for r in chunk]
        more = start + len(chunk) < len(records)
        end = edges[-1]["cursor"] if edges else None
        if snake:
            body = {"edges": edges, "page_info": {"has_next_page": more, "end_cursor": end}, "total_count": len(records)}
        else:
            body = {"edges": edges, "pageInfo": {"hasNextPage": more, "endCursor": end}, "totalCount": len(records)}
        return json.dumps(body, indent=2)

    return page


async def walk(tool, first, extra=None):
    ids, after, calls = [], None, 0
    while True:
        out = await _call(tool, {"first": first, **(extra or {})} | ({} if after is None else {"after": after}))
        calls += 1
        ids += [e["node"]["id"] for e in out["edges"]]
        after = out.get("next_after")
        if after is None:
            info = out.get("page_info") or out.get("pageInfo")
            assert not (info.get("has_next_page") or info.get("hasNextPage"))
            return ids, calls
        assert calls < 200


@pytest.mark.parametrize(
    ("module", "tool"),
    [
        (vulnerabilities, "list_vulnerabilities"),
        (vulnerabilities, "search_vulnerabilities"),
        (misconfigurations, "list_misconfigurations"),
        (misconfigurations, "search_misconfigurations"),
    ],
)
async def test_snake_case_page_info_is_followed_to_the_last_record(monkeypatch, module, tool):
    records = [f"v{i:03d}" for i in range(248)]
    monkeypatch.setattr(module, tool, connection(records, snake=True))
    ids, calls = await walk(tool, 10)
    assert ids == records and calls == 25


async def test_camel_case_page_info_still_works(monkeypatch):
    records = [f"a{i:03d}" for i in range(35)]
    monkeypatch.setattr(alerts, "list_alerts", connection(records, snake=False))
    ids, _ = await walk("list_alerts", 10)
    assert ids == records


@pytest.mark.parametrize("snake", [True, False])
async def test_cut_pages_continue_after_the_last_record_returned(monkeypatch, snake):
    records = [f"v{i:03d}" for i in range(60)]
    monkeypatch.setattr(vulnerabilities, "list_vulnerabilities", connection(records, snake=snake, padding=3000))
    out = await _call("list_vulnerabilities", {"first": 20})
    assert out["truncated"] is True and "retry_page_size" not in out
    returned = [e["node"]["id"] for e in out["edges"]]
    info = out["page_info"] if snake else out["pageInfo"]
    assert out["next_after"] == f"c-{len(returned) - 1}"
    assert (info.get("end_cursor") or info.get("endCursor")) == out["next_after"]
    assert info.get("has_next_page", info.get("hasNextPage")) is True
    ids, _ = await walk("list_vulnerabilities", 20)
    assert ids == records


async def test_last_page_has_no_next_after(monkeypatch):
    monkeypatch.setattr(vulnerabilities, "list_vulnerabilities", connection(["v1", "v2"], snake=True))
    out = await _call("list_vulnerabilities", {"first": 10})
    assert "next_after" not in out and [e["node"]["id"] for e in out["edges"]] == ["v1", "v2"]


async def test_empty_list(monkeypatch):
    monkeypatch.setattr(vulnerabilities, "list_vulnerabilities", connection([], snake=True))
    out = await _call("list_vulnerabilities", {"first": 10})
    assert out["edges"] == [] and "next_after" not in out


# ---- PRD-21367 --------------------------------------------------------------------------------------------------

THREAT_INTEL = [
    ("threat_intel_by_hash", {"hash_value": "a" * 64}),
    ("threat_intel_by_url", {"url": "https://example.com"}),
    ("threat_intel_by_domain", {"domain": "example.com"}),
    ("threat_intel_by_ip", {"ip_address": "8.8.8.8"}),
    ("threat_intel_get_file_relationships", {"hash_value": "a" * 64, "relationship_type": "contacted_ips"}),
    ("threat_intel_search", {"query": "type:file"}),
    ("threat_intel_get_file_behavior", {"hash_value": "a" * 64}),
]


@pytest.mark.parametrize(("tool", "args"), THREAT_INTEL)
async def test_threat_intel_without_the_virustotal_header_is_not_configured(monkeypatch, tool, args):
    def must_not_run(**_):
        raise AssertionError("purple-mcp must not be called without a VirusTotal key")

    monkeypatch.setattr(threat_intelligence, tool, must_not_run)
    tools = {t.name: t for t in await create_mcp_server().list_tools()}
    args = {k: v for k, v in args.items() if k in tools[tool].inputSchema["properties"]}
    out = await _call(tool, args)
    assert out["error"] == {
        "code": "not_configured",
        "message": "Send a VirusTotal API key in the X-Virustotal-Api-Key header to use threat_intel_* tools.",
        "retryable": False,
    }


async def test_threat_intel_with_the_virustotal_header_is_called(monkeypatch):
    monkeypatch.setattr(threat_intelligence, "threat_intel_by_ip", lambda **_: '{"ip": "8.8.8.8"}')
    assert await _call("threat_intel_by_ip", {"ip_address": "8.8.8.8"}, TENANT_VT) == {"ip": "8.8.8.8"}


@pytest.mark.parametrize(
    ("message", "code", "retryable"),
    [
        ('Value "nope" could not be parsed into a UUID', "invalid_argument", False),
        ("Required value was null.", "not_found", False),
        ("Field bogus does not exist or not supported for FILTER API call", "invalid_argument", False),
        ("Invalid ISO 8601 datetime string: yesterday", "invalid_argument", False),
        ("Inventory resource not found", "not_found", False),
        ("AI investigation is not enabled for this account", "not_configured", False),
        ("PURPLEMCP_VT_API_KEY environment variable must be set. Get your API key from x", "not_configured", False),
        ("Something unexpected happened", "upstream_error", False),
        ("Server error 502 from console", "upstream_error", True),
        ("Too many requests: 429", "rate_limited", True),
        ("Connection reset", "upstream_error", True),
        ("Read timed out", "upstream_error", True),
    ],
)
def test_errors_are_classified_by_their_text(message, code, retryable):
    error = json.loads(_envelope_for(RuntimeError(message)))["error"]
    assert (error["code"], error["retryable"]) == (code, retryable)


def test_iso_errors_carry_a_format_example():
    error = json.loads(_envelope_for(RuntimeError("Invalid ISO 8601 datetime string: yesterday")))["error"]
    assert error["message"].endswith("Use ISO 8601, e.g. 2026-10-22T00:00:00Z.")


def test_virustotal_message_names_the_header():
    error = json.loads(_envelope_for(RuntimeError("PURPLEMCP_VT_API_KEY environment variable must be set.")))["error"]
    assert "X-Virustotal-Api-Key" in error["message"] and "PURPLEMCP" not in error["message"]


def test_a_timeout_exception_without_text_is_retryable():
    assert json.loads(_envelope_for(TimeoutError()))["error"]["retryable"] is True


async def test_errors_raised_by_tools_reach_the_caller_classified(monkeypatch):
    def fails(**_):
        raise RuntimeError("Required value was null.")

    monkeypatch.setattr(alerts, "get_alert", fails)
    out = await _call("get_alert", {"alert_id": "00000000-0000-0000-0000-000000000000"})
    assert out["error"]["code"] == "not_found" and out["error"]["retryable"] is False


@pytest.mark.parametrize("empty", ["{}", "", None])
async def test_unknown_cve_is_not_found(monkeypatch, empty):
    monkeypatch.setattr(cve, "cve_search_by_id", lambda **_: empty)
    out = await _call("cve_search_by_id", {"cve_id": "CVE-0000-0000"})
    assert out["error"] == {"code": "not_found", "message": "No CVE CVE-0000-0000 in the CVE database.", "retryable": False}


async def test_known_cve_is_returned(monkeypatch):
    monkeypatch.setattr(cve, "cve_search_by_id", lambda **_: '{"id": "CVE-2024-3094"}')
    assert await _call("cve_search_by_id", {"cve_id": "CVE-2024-3094"}) == {"id": "CVE-2024-3094"}
