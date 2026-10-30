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
"""tools/list snapshot and description budget. No network access."""

import asyncio
import json

import pytest

from sentinelone_mcp.server import INSTRUCTIONS, create_mcp_server

# Tool names and required parameters follow purple-mcp and are a public
# contract: existing agents depend on them. Changing this snapshot is a
# breaking change.
EXPECTED_TOOLS: dict[str, set[str]] = {
    "purple_ai": {"query"},
    "powerquery": {"query", "start_datetime", "end_datetime"},
    "get_timestamp_range": set(),
    "iso_to_unix_timestamp": {"iso_datetime"},
    "get_alert": {"alert_id"},
    "list_alerts": set(),
    "search_alerts": set(),
    "get_alert_notes": {"alert_id"},
    "get_alert_history": {"alert_id"},
    "get_alert_investigation_report": {"alert_id"},
    "get_misconfiguration": {"misconfiguration_id"},
    "list_misconfigurations": set(),
    "search_misconfigurations": set(),
    "get_misconfiguration_notes": {"misconfiguration_id"},
    "get_misconfiguration_history": {"misconfiguration_id"},
    "get_vulnerability": {"vulnerability_id"},
    "list_vulnerabilities": set(),
    "search_vulnerabilities": set(),
    "get_vulnerability_notes": {"vulnerability_id"},
    "get_vulnerability_history": {"vulnerability_id"},
    "get_inventory_item": {"item_id"},
    "list_inventory_items": set(),
    "search_inventory_items": set(),
    "threat_intel_by_hash": {"hash_value"},
    "threat_intel_by_url": {"url"},
    "threat_intel_by_domain": {"domain"},
    "threat_intel_by_ip": {"ip_address"},
    "threat_intel_get_file_relationships": {"hash_value", "relationship_type"},
    "threat_intel_search": {"query"},
    "threat_intel_get_file_behavior": {"hash_value"},
    "cve_search_by_id": {"cve_id"},
    "cve_search_by_vendor": {"vendor"},
    "cve_database_status": set(),
    "search_agents": set(),
    "isolate_endpoint": {"agent_id"},
    "reconnect_endpoint": {"agent_id"},
}

# The only tools that change SentinelOne state (PRD-21243); every other tool is read-only.
ACTION_TOOLS = {"isolate_endpoint", "reconnect_endpoint"}


@pytest.fixture(scope="module")
def tools():
    return {t.name: t for t in asyncio.run(create_mcp_server().list_tools())}


def test_tool_names_are_stable(tools):
    assert set(tools) == set(EXPECTED_TOOLS)


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_required_params(tools, name):
    assert set(tools[name].inputSchema.get("required", [])) == EXPECTED_TOOLS[name]


def test_parameters_match_the_library():
    import purple_mcp.tools.alerts as alerts
    import inspect

    ours = {t.name: t for t in asyncio.run(create_mcp_server().list_tools())}
    assert list(ours["search_alerts"].inputSchema["properties"]) == list(inspect.signature(alerts.search_alerts).parameters)


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_description_budget(tools, name):
    description = (tools[name].description or "").strip()
    assert description, f"{name} has no description"
    assert len(description) <= 500
    assert len(description.splitlines()[0]) <= 100


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS.keys() - ACTION_TOOLS))
def test_every_other_tool_is_read_only(tools, name):
    assert tools[name].annotations.readOnlyHint is True


@pytest.mark.parametrize("name", sorted(ACTION_TOOLS))
def test_agent_action_tools_are_marked_destructive_and_idempotent(tools, name):
    annotations = tools[name].annotations
    assert annotations.readOnlyHint is False
    assert annotations.destructiveHint is True
    assert annotations.idempotentHint is True


def test_search_filters_are_documented(tools):
    filters = tools["search_vulnerabilities"].inputSchema["properties"]["filters"]
    text = json.dumps(filters)
    assert "string_equals" in text and "cveExploitedInTheWild" in text


def test_instructions_budget():
    assert len(INSTRUCTIONS) <= 1500


def test_tool_without_credentials_returns_not_configured():
    content, _ = asyncio.run(create_mcp_server().call_tool("list_alerts", {}))
    assert json.loads(content[0].text)["error"]["code"] == "not_configured"


@pytest.mark.parametrize("name", ["list_inventory_items", "search_inventory_items"])
def test_inventory_limit_capped_at_200(tools, name):
    schema = tools[name].inputSchema["properties"]["limit"]
    assert schema["maximum"] == 200 and schema["default"] == 50


# ---- agent-action tools: envelope mapping (PRD-21243, AC4/AC5/AC6/AC9/TC-S1-005/006/007/010/012) ----
# AC2/AC3 (the real isolate/reconnect round trip) and AC4's real viewer-only-token 403 need a live
# SentinelOne console and are not automatable here; see docs/tickets/PRD-21243.ac.json.


@pytest.mark.parametrize("name,args", [("search_agents", {}), ("isolate_endpoint", {"agent_id": "a1"}), ("reconnect_endpoint", {"agent_id": "a1"})])
def test_agent_action_tools_need_credentials_too(name, args):
    """TC-S1-007 / AC6: identical to every other tool when console headers are missing."""
    content, _ = asyncio.run(create_mcp_server().call_tool(name, args))
    assert json.loads(content[0].text)["error"]["code"] == "not_configured"


async def _call_with_settings(tool: str, args: dict):
    from sentinelone_mcp.purple import build_settings, use_settings

    with use_settings(build_settings("https://x.sentinelone.net", "tok")):
        content, _ = await create_mcp_server().call_tool(tool, args)
    return json.loads(content[0].text)


def test_isolate_endpoint_maps_403_to_unauthorized(monkeypatch):
    """TC-S1-005 / AC4, with the HTTP call itself mocked (see test_agents_api.py for the raw client)."""
    from sentinelone_mcp import agents_api

    async def forbidden(agent_id):
        raise RuntimeError("SentinelOne agents API disconnect failed (HTTP 403): Insufficient permissions")

    monkeypatch.setattr(agents_api, "disconnect", forbidden)
    result = asyncio.run(_call_with_settings("isolate_endpoint", {"agent_id": "a1"}))
    assert result["error"]["code"] == "unauthorized"
    assert result["error"]["retryable"] is False


def test_isolate_endpoint_maps_unknown_agent_to_not_found(monkeypatch):
    """TC-S1-006 / AC5."""
    from sentinelone_mcp import agents_api

    async def not_found(agent_id):
        raise RuntimeError(f"SentinelOne agents API disconnect matched no agent (HTTP 404): id {agent_id!r} not found")

    monkeypatch.setattr(agents_api, "disconnect", not_found)
    result = asyncio.run(_call_with_settings("isolate_endpoint", {"agent_id": "no-such-agent"}))
    assert result["error"]["code"] == "not_found"


def test_isolate_endpoint_is_a_no_op_on_an_already_isolated_agent(monkeypatch):
    """TC-S1-011 / AC2: calling it twice never raises, both calls report success."""
    from sentinelone_mcp import agents_api

    async def already_disconnecting(agent_id):
        return {"agent_id": agent_id, "network_status": "disconnecting", "affected": 1}

    monkeypatch.setattr(agents_api, "disconnect", already_disconnecting)
    first = asyncio.run(_call_with_settings("isolate_endpoint", {"agent_id": "a1"}))
    second = asyncio.run(_call_with_settings("isolate_endpoint", {"agent_id": "a1"}))
    assert "error" not in first and "error" not in second
    assert first == second == {"agent_id": "a1", "network_status": "disconnecting", "affected": 1}


def test_search_agents_rejects_bad_network_status_without_calling_the_api(monkeypatch):
    """TC-S1-012 / AC1: FastMCP's Literal validation rejects it before agents_api is reached."""
    from sentinelone_mcp import agents_api

    called = False

    async def spy(**kwargs):
        nonlocal called
        called = True
        return {"agents": []}

    monkeypatch.setattr(agents_api, "list_agents", spy)
    result = asyncio.run(_call_with_settings("search_agents", {"network_status": "not-a-real-status"}))
    assert result["error"]["code"] == "invalid_argument"
    assert called is False
