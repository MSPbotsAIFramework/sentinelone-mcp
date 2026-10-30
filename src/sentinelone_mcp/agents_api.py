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
"""SentinelOne's classic Management Console REST API: agent search and network actions.

Every other module in this connector calls purple-mcp's Data Lake / GraphQL APIs.
Isolating or reconnecting an endpoint is not something purple-mcp (or the Data Lake)
exposes -- SentinelOne's own open-source library has no agent-action tool module (see
docs/tickets/PRD-21243.md "Current state"). This module talks to the classic REST API
directly, reusing the same per-request settings (console base URL + raw token) that
purple.current_settings() already carries for every other tool; it stores nothing of
its own.

Functions here raise a plain Exception whose message contains the HTTP status code
(e.g. "(HTTP 403)") on failure; tools.py's existing _envelope_for maps that text to
the standard error envelope by status code, so no new error-mapping branch is needed
there (see Tech design > Change list).
"""

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from .purple import current_settings

# Same family of timeouts already used by purple-mcp for its own console calls.
_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=5.0, pool=5.0)

_AGENTS_PATH = "/web/api/v2.1/agents"
_ACTIONS_PATH = "/web/api/v2.1/agents/actions/{action}"

# SOP §5 (mandatory): bounded retry + exponential backoff for 429/5xx, honoring
# Retry-After; other 4xx must not be retried. purple-mcp's own tenacity-based
# retry policies (graphql_client_base.py, sdl_query_client.py) retry on
# httpx.HTTPError / any raise_for_status() failure -- that would also retry
# non-transient 4xx like 403/404, which SOP §5 forbids, so they are not reused
# here. This is a small hand-rolled loop instead (status-code driven, not
# exception driven), per the review's second option.
_RETRYABLE_STATUSES = {429, 500, 502, 503, 504}
_MAX_ATTEMPTS = 3  # 1 initial try + up to 2 retries
_BACKOFF_BASE_SECONDS = 0.5
_BACKOFF_MAX_SECONDS = 8.0  # keeps worst case well under _run_classic's 100s call budget


def _retry_delay_seconds(attempt: int, response: httpx.Response) -> float:
    """Delay before retry number `attempt` (1-indexed), honoring a numeric Retry-After."""
    retry_after = response.headers.get("Retry-After")
    if retry_after is not None:
        try:
            return min(float(retry_after), _BACKOFF_MAX_SECONDS)
        except ValueError:
            pass  # not a plain number (e.g. an HTTP-date); fall back to backoff
    return min(_BACKOFF_BASE_SECONDS * (2 ** (attempt - 1)), _BACKOFF_MAX_SECONDS)


async def _send_with_retry(send: Callable[[], Awaitable[httpx.Response]]) -> httpx.Response:
    """Send, retrying a bounded number of times on 429/5xx only, honoring Retry-After.

    Any other status (including every other 4xx) is returned as-is on the first
    attempt -- the caller's existing >=400 check and `_fail` mapping are unchanged.
    """
    response = await send()
    attempt = 1
    while response.status_code in _RETRYABLE_STATUSES and attempt < _MAX_ATTEMPTS:
        await asyncio.sleep(_retry_delay_seconds(attempt, response))
        response = await send()
        attempt += 1
    return response


def _client() -> httpx.AsyncClient:
    """One short-lived client per call, authenticated for the current request's tenant."""
    settings = current_settings()
    token = getattr(settings, "graphql_service_token", None) or getattr(settings, "sdl_api_token", None)
    base_url = getattr(settings, "sentinelone_console_base_url", None) if settings else None
    if not base_url or not token:
        # _run_classic already short-circuits on current_settings() is None; this only
        # guards the case where settings exist but are somehow incomplete.
        raise ValueError("SentinelOne credentials are missing for this request.")
    return httpx.AsyncClient(
        base_url=base_url,
        headers={"Authorization": f"ApiToken {token}", "Accept": "application/json"},
        timeout=_TIMEOUT,
    )


def _fail(action: str, response: httpx.Response) -> None:
    detail = response.text.strip()[:400]
    raise RuntimeError(f"SentinelOne agents API {action} failed (HTTP {response.status_code}): {detail}")


async def list_agents(
    computer_name: str | None = None,
    uuid: str | None = None,
    network_status: str | None = None,
    limit: int = 10,
    cursor: str | None = None,
) -> dict[str, Any]:
    """GET /web/api/v2.1/agents -- one page of agent summaries; an empty match is success."""
    params: dict[str, str | int] = {"limit": limit}
    if computer_name:
        params["computerName__contains"] = computer_name
    if uuid:
        params["uuid"] = uuid
    if network_status:
        params["networkStatus"] = network_status
    if cursor:
        params["cursor"] = cursor
    async with _client() as client:
        response = await _send_with_retry(lambda: client.get(_AGENTS_PATH, params=params))
        if response.status_code >= 400:
            _fail("list", response)
        body = response.json()
    agents = [
        {
            "id": item.get("uuid") or item.get("id"),
            "computerName": item.get("computerName"),
            "networkStatus": item.get("networkStatus"),
            "siteName": item.get("siteName"),
            "osType": item.get("osType"),
        }
        for item in body.get("data", [])
    ]
    result: dict[str, Any] = {"agents": agents}
    next_cursor = (body.get("pagination") or {}).get("nextCursor")
    if next_cursor:
        result["next_cursor"] = next_cursor
    return result


async def _agent_action(action: str, agent_id: str) -> dict[str, Any]:
    """POST /web/api/v2.1/agents/actions/{disconnect,connect} for one agent id.

    SentinelOne's classic action endpoints match by filter and report how many agents
    were affected rather than erroring on an unknown id; affected == 0 means no agent
    matched this id (not_found), affected >= 1 means the action was accepted -- including
    when the agent was already in the target state, which is the no-op case AC2 asks for.
    """
    async with _client() as client:
        response = await _send_with_retry(
            lambda: client.post(
                _ACTIONS_PATH.format(action=action),
                json={"filter": {"ids": [agent_id]}},
            )
        )
        if response.status_code >= 400:
            _fail(action, response)
        body = response.json()
    affected = (body.get("data") or {}).get("affected", 0)
    if not affected:
        raise RuntimeError(f"SentinelOne agents API {action} matched no agent (HTTP 404): id {agent_id!r} not found")
    network_status = "disconnecting" if action == "disconnect" else "connecting"
    return {"agent_id": agent_id, "network_status": network_status, "affected": affected}


async def disconnect(agent_id: str) -> dict[str, Any]:
    """Isolate one agent from the network; transitions it toward 'disconnected'."""
    return await _agent_action("disconnect", agent_id)


async def connect(agent_id: str) -> dict[str, Any]:
    """Reconnect one agent to the network; transitions it toward 'connected'."""
    return await _agent_action("connect", agent_id)
