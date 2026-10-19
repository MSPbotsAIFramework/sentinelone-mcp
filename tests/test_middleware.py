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
"""Credential middleware: 401/400 on bad headers, per-request purple-mcp settings."""

import asyncio

import pytest
from purple_mcp.config import get_settings
from starlette.testclient import TestClient

from sentinelone_mcp.__main__ import build_http_app
from sentinelone_mcp.purple import MissingCredentials, current_settings
from sentinelone_mcp.server import GatewayCredentialsMiddleware, create_mcp_server, normalize_console_url

MCP_HEADERS = {"Accept": "application/json, text/event-stream"}
LIST_TOOLS = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
CREDS = {"X-Purplemcp-Base-Url": "https://your-console.sentinelone.net", "X-Purplemcp-Token": "your-console-token"}


def _client() -> TestClient:
    return TestClient(build_http_app(create_mcp_server()))


def test_health_is_local():
    with _client() as client:
        resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


@pytest.mark.parametrize("drop", list(CREDS))
def test_each_required_header_is_required(drop):
    headers = {k: v for k, v in CREDS.items() if k != drop}
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=MCP_HEADERS | headers)
    assert resp.status_code == 401
    assert drop in resp.json()["message"]


def test_alternative_header_names_are_accepted():
    headers = {"X-S1-Console-URL": CREDS["X-Purplemcp-Base-Url"], "X-S1-API-Token": "tok"}
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=MCP_HEADERS | headers)
    assert resp.status_code == 200
    assert "purple_ai" in resp.text


def test_plain_http_console_is_rejected():
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=MCP_HEADERS | CREDS | {"X-Purplemcp-Base-Url": "http://x.sentinelone.net"})
    assert resp.status_code == 400


@pytest.mark.parametrize(
    "value,expected",
    [
        ("https://your-console.sentinelone.net", "https://your-console.sentinelone.net"),
        ("your-console.sentinelone.net/", "https://your-console.sentinelone.net"),
        ("https://your-console.sentinelone.net/web/api/v2.1", "https://your-console.sentinelone.net"),
        ("http://your-console.sentinelone.net", None),
    ],
)
def test_normalize_console_url(value, expected):
    assert normalize_console_url(value) == expected


def _run_middleware(headers: list[tuple[bytes, bytes]]) -> dict:
    seen: dict = {}

    async def app(scope, receive, send):
        seen["settings"] = current_settings()
        seen["library"] = get_settings()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message):
        return None

    asyncio.run(GatewayCredentialsMiddleware(app)({"type": "http", "path": "/mcp", "headers": headers}, receive, send))
    return seen


def test_library_settings_come_from_the_request_and_are_reset():
    seen = _run_middleware(
        [
            (b"x-purplemcp-base-url", b"https://example.sentinelone.net/"),
            (b"x-purplemcp-token", b"ApiToken tok-123"),
            (b"x-virustotal-api-key", b"vt-1"),
        ]
    )
    library = seen["library"]
    assert library is seen["settings"]
    assert library.graphql_service_token == "tok-123"
    assert library.sentinelone_console_base_url == "https://example.sentinelone.net"
    assert library.vt_api_key == "vt-1"
    assert current_settings() is None
    with pytest.raises(MissingCredentials):
        get_settings()


def test_concurrent_requests_do_not_share_credentials():
    observed: list[tuple[str, str]] = []

    async def app(scope, receive, send):
        before = get_settings().graphql_service_token
        await asyncio.sleep(0.01)
        observed.append((before, get_settings().graphql_service_token))
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message):
        return None

    middleware = GatewayCredentialsMiddleware(app)

    def scope(token: bytes) -> dict:
        return {
            "type": "http",
            "path": "/mcp",
            "headers": [(b"x-purplemcp-base-url", b"https://example.sentinelone.net"), (b"x-purplemcp-token", token)],
        }

    async def both():
        await asyncio.gather(middleware(scope(b"tenant-a"), receive, send), middleware(scope(b"tenant-b"), receive, send))

    asyncio.run(both())
    assert sorted(observed) == [("tenant-a", "tenant-a"), ("tenant-b", "tenant-b")]
