# PRD-21243 · Code review

## Round 1 · 2026-10-30 · reviewed 338304a (base abe07ac)

Verdict: changes requested

### Scope

`git diff abe07ac...338304a -- src/ tests/ README.md` (the design/doc-only commit `fa8f8b9` is
covered by the design leg, not re-reviewed here). Gate re-run on the reviewed commit:
`uv run pytest -q` → `216 passed, 3 warnings in 19.50s` (no `declared_commands` beyond `pytest`
in this repo). CJK scan (`grep -rnP '[\x{4e00}-\x{9fff}]' --exclude-dir=.git --exclude-dir=.venv .`)
→ no output. README "MSPbots Connector" section (`README.md:24-93`) diffed byte-for-byte against
`vendor-mcp-development/reference/readme-connector-section.md` → identical. `purple_mcp.config.Settings`
(installed at `purple-mcp@e306034`) read directly to confirm `graphql_service_token` /
`sdl_api_token` / `sentinelone_console_base_url` are real field names on the settings object
`agents_api._client()` reads via `getattr` — they are (`.venv/lib/python3.12/site-packages/purple_mcp/config.py`),
so that part of the new credential-reading code is not a silent-failure risk.

### Findings

1. [must-fix] `src/sentinelone_mcp/agents_api.py:59-61` (`_fail`, called from `list_agents` at
   `:83-84` and `_agent_action` at `:116-117`) — the new classic-API client raises immediately on
   the first `429` or `5xx` response, with no retry, no exponential backoff, and no handling of a
   `Retry-After` header. This is the connector's **first** direct HTTP client (every other tool
   goes through `purple-mcp`, which does implement retry/backoff itself — confirmed by reading
   the vendored library: `purple_mcp/libs/graphql_client_base.py`, `purple_mcp/libs/sdl/sdl_query_client.py`
   and others reference retry/backoff, and `tenacity` is in `uv.lock` as a `purple-mcp` dependency).
   So this gap is new, not inherited. SOP §5 ("Network robustness") is explicitly marked
   mandatory: limited retry with exponential backoff is required for `429` and `5xx` responses,
   `Retry-After` must be honored, and other `4xx` responses must not be retried. The §14
   Checklist item covering the same requirement (bounded retry + backoff for `429`/`5xx`,
   honor `Retry-After`, total call time under 120s including retries) is one of the explicit
   must-fix categories for this track (`mcp-track.md` §4.3: "SOP §14 Checklist"). Concretely, a transient SentinelOne 5xx or a 429 while calling `isolate_endpoint`
   during an active incident — the exact scenario this tool exists for — fails outright today
   instead of retrying a bounded number of times; the error is correctly labelled `retryable: true`
   by the existing `_envelope_for` status-code mapping (unchanged, reused as designed), but nothing
   in this new module actually retries before surfacing that to the caller.
   What would fix it: wrap the two outbound calls (`list_agents`'s `client.get` and
   `_agent_action`'s `client.post`) in a small bounded retry (e.g. 2–3 attempts, exponential
   backoff, honoring a numeric `Retry-After` header when present) for `429` and `5xx` responses
   only — `tenacity` is already resolved in `uv.lock` (as a transitive dependency of `purple-mcp`)
   so no new lock entries are required if it is promoted to a direct dependency in `pyproject.toml`,
   or a hand-rolled `asyncio.sleep`-based loop works equally well without adding a dependency.
   Either way, `tests/test_agents_api.py` needs a case asserting a `429`/`503` followed by a `200`
   succeeds (and one asserting a non-transient `404`/`403` does *not* retry).

### Suggestions

None beyond the must-fix above — the rest of the diff (credential plumbing reuse, error-envelope
reuse, tool registration, README/Tools-table/Delivery-notes updates, test coverage for everything
that doesn't need a live console) matches the technical design and the repo's existing conventions.
