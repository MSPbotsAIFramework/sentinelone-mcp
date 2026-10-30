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
"""agents_api against the classic Management Console API, with httpx mocked (PRD-21243).

No network access and no real SentinelOne console; purple-mcp's GraphQL calls are covered
separately by test_api_client.py. These tests exercise the classic REST client directly
(list_agents / disconnect / connect), not the MCP tool wrappers in tools.py.
"""

import asyncio

import httpx
import pytest

from sentinelone_mcp import agents_api
from sentinelone_mcp.purple import build_settings, use_settings

TENANT_A = build_settings("https://a.sentinelone.net", "tok-A")
TENANT_B = build_settings("https://b.sentinelone.net", "tok-B")


def _json_response(status: int, body: dict):
    async def send(self, request, *args, **kwargs):
        return httpx.Response(status, json=body, request=request)

    return send


async def test_list_agents_maps_matches_to_the_documented_shape(monkeypatch):
    body = {
        "data": [
            {"uuid": "agent-1", "computerName": "web-7", "networkStatus": "connected", "siteName": "HQ", "osType": "windows"}
        ],
        "pagination": {"nextCursor": "cursor-2"},
    }
    monkeypatch.setattr(httpx.AsyncClient, "send", _json_response(200, body))
    with use_settings(TENANT_A):
        result = await agents_api.list_agents(computer_name="web")
    assert result == {
        "agents": [{"id": "agent-1", "computerName": "web-7", "networkStatus": "connected", "siteName": "HQ", "osType": "windows"}],
        "next_cursor": "cursor-2",
    }


async def test_list_agents_with_no_matches_is_an_empty_list_not_an_error(monkeypatch):
    monkeypatch.setattr(httpx.AsyncClient, "send", _json_response(200, {"data": []}))
    with use_settings(TENANT_A):
        result = await agents_api.list_agents(computer_name="no-such-host")
    assert result == {"agents": []}


async def test_list_agents_sends_filters_and_the_tenant_token(monkeypatch):
    seen: list[httpx.Request] = []

    async def send(self, request, *args, **kwargs):
        seen.append(request)
        return httpx.Response(200, json={"data": []}, request=request)

    monkeypatch.setattr(httpx.AsyncClient, "send", send)
    with use_settings(TENANT_A):
        await agents_api.list_agents(computer_name="web-7", network_status="connected", limit=25, cursor="c1")
    request = seen[0]
    assert request.url.host == "a.sentinelone.net"
    assert request.url.path == "/web/api/v2.1/agents"
    assert request.headers["Authorization"] == "ApiToken tok-A"
    assert request.url.params["computerName__contains"] == "web-7"
    assert request.url.params["networkStatus"] == "connected"
    assert request.url.params["limit"] == "25"
    assert request.url.params["cursor"] == "c1"


async def test_disconnect_reports_the_transitional_status(monkeypatch):
    monkeypatch.setattr(httpx.AsyncClient, "send", _json_response(200, {"data": {"affected": 1}}))
    with use_settings(TENANT_A):
        result = await agents_api.disconnect("agent-1")
    assert result == {"agent_id": "agent-1", "network_status": "disconnecting", "affected": 1}


async def test_connect_reports_the_transitional_status(monkeypatch):
    monkeypatch.setattr(httpx.AsyncClient, "send", _json_response(200, {"data": {"affected": 1}}))
    with use_settings(TENANT_A):
        result = await agents_api.connect("agent-1")
    assert result == {"agent_id": "agent-1", "network_status": "connecting", "affected": 1}


async def test_disconnect_posts_the_id_filter_with_the_tenant_token(monkeypatch):
    import json as _json

    seen: list[httpx.Request] = []

    async def send(self, request, *args, **kwargs):
        seen.append(request)
        return httpx.Response(200, json={"data": {"affected": 1}}, request=request)

    monkeypatch.setattr(httpx.AsyncClient, "send", send)
    with use_settings(TENANT_A):
        await agents_api.disconnect("agent-1")
    request = seen[0]
    assert request.url.path == "/web/api/v2.1/agents/actions/disconnect"
    assert request.headers["Authorization"] == "ApiToken tok-A"
    assert _json.loads(request.content) == {"filter": {"ids": ["agent-1"]}}


async def test_unknown_agent_id_raises_with_404_in_the_message(monkeypatch):
    monkeypatch.setattr(httpx.AsyncClient, "send", _json_response(200, {"data": {"affected": 0}}))
    with use_settings(TENANT_A), pytest.raises(RuntimeError, match="404"):
        await agents_api.disconnect("no-such-agent")


async def test_permission_denied_raises_with_403_in_the_message(monkeypatch):
    body = {"has_error": True, "error_response": {"errors": [{"code": 4030010, "title": "Insufficient permissions"}]}}
    monkeypatch.setattr(httpx.AsyncClient, "send", _json_response(403, body))
    with use_settings(TENANT_A), pytest.raises(RuntimeError, match="403"):
        await agents_api.disconnect("agent-1")


async def test_server_error_raises_with_status_in_the_message(monkeypatch):
    monkeypatch.setattr(httpx.AsyncClient, "send", _json_response(502, {"error": "upstream down"}))
    with use_settings(TENANT_A), pytest.raises(RuntimeError, match="502"):
        await agents_api.connect("agent-1")


async def test_timeout_propagates_for_the_caller_to_classify(monkeypatch):
    async def timeout(self, request, *args, **kwargs):
        raise httpx.ReadTimeout("timed out", request=request)

    monkeypatch.setattr(httpx.AsyncClient, "send", timeout)
    with use_settings(TENANT_A), pytest.raises(httpx.ReadTimeout):
        await agents_api.list_agents()


async def test_concurrent_tenants_never_see_each_others_token(monkeypatch):
    """AC7 / TC-S1-008: two tenants isolating an endpoint at the same time stay isolated."""
    seen: list[httpx.Request] = []

    async def send(self, request, *args, **kwargs):
        await asyncio.sleep(0.01)  # encourage interleaving
        seen.append(request)
        return httpx.Response(200, json={"data": {"affected": 1}}, request=request)

    monkeypatch.setattr(httpx.AsyncClient, "send", send)

    async def call(settings):
        with use_settings(settings):
            return await agents_api.disconnect("agent-1")

    await asyncio.gather(call(TENANT_A), call(TENANT_B))
    pairs = sorted((r.url.host, r.headers["Authorization"]) for r in seen)
    assert pairs == [("a.sentinelone.net", "ApiToken tok-A"), ("b.sentinelone.net", "ApiToken tok-B")]
