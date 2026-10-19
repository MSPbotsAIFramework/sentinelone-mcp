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
}


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


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_every_tool_is_read_only(tools, name):
    assert tools[name].annotations.readOnlyHint is True


def test_search_filters_are_documented(tools):
    filters = tools["search_vulnerabilities"].inputSchema["properties"]["filters"]
    text = json.dumps(filters)
    assert "string_equals" in text and "cveExploitedInTheWild" in text


def test_instructions_budget():
    assert len(INSTRUCTIONS) <= 1500


def test_tool_without_credentials_returns_not_configured():
    content, _ = asyncio.run(create_mcp_server().call_tool("list_alerts", {}))
    assert json.loads(content[0].text)["error"]["code"] == "not_configured"
