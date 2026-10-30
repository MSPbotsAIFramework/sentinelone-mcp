# PRD-21243 · Code review

Status: frozen @ 50061de

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

### Fixes (round 1) · 9a0342d

1. [must-fix #1 — fixed] `src/sentinelone_mcp/agents_api.py` — added `_send_with_retry`, a bounded
   retry loop (up to 3 attempts, exponential backoff starting at 0.5s and capped at 8s) wrapping
   the two outbound calls (`list_agents`'s `client.get`, `_agent_action`'s `client.post`). It
   retries only on `429` and `5xx` (`_RETRYABLE_STATUSES = {429, 500, 502, 503, 504}`), honors a
   numeric `Retry-After` header when present (falling back to backoff if it isn't a plain number),
   and returns any other status — including every other `4xx` — unchanged on the first attempt, so
   `_fail`'s existing `>=400` → envelope mapping is untouched. `_run_classic`'s existing 100s
   `asyncio.wait_for` budget (`tools.py:161`, unchanged) already keeps the worst case (3 attempts +
   backoff) under the SOP §5 120s ceiling, so no new timeout plumbing was needed.
   **Not reused**: purple-mcp's two tenacity-based retry policies
   (`graphql_client_base.py:100-104`, `sdl/sdl_query_client.py:86-91`) both retry on
   `httpx.HTTPError` / any `raise_for_status()` failure, which would also retry non-transient 4xx
   (403/404) — SOP §5 explicitly says those must not be retried — and neither reads `Retry-After`.
   Promoting `tenacity` to a direct dependency to force a status-code-only, `Retry-After`-aware
   policy through it would have added more surface than the ~35-line hand-rolled loop the reviewer
   offered as the equally-acceptable second option, so that option was taken; `tenacity` stays an
   indirect dependency (unchanged in `uv.lock`, still resolved at `9.2.1` via `purple-mcp`).
   Tests added in `tests/test_agents_api.py`: `test_429_then_200_retries_and_succeeds` (and the
   `503`-via-`list_agents` variant) assert a transient failure is retried and the eventual success
   is returned to the caller unchanged; `test_retries_are_bounded_then_fails_with_the_last_status`
   asserts a persistent `503` makes exactly `_MAX_ATTEMPTS` (3) calls and still raises `RuntimeError`
   with `503` in the message; `test_non_transient_4xx_does_not_retry` asserts a `403` makes exactly
   one call. The pre-existing `test_server_error_raises_with_status_in_the_message` (a persistent
   `502`) still passes unchanged in substance — `agents_api.asyncio.sleep` is monkeypatched there
   (and in the new retry tests) so the added backoff doesn't slow the suite down.

#### Re-run (commit `9a0342d`, synced with `main @ abe07ac` — unmoved since round 1, no merge needed)

| Command | Result |
|---|---|
| `uv run pytest -q` | `220 passed, 3 warnings in 31.49s` (216 + 4 new; no new failures, no skips) |
| `grep -rnP '[\x{4e00}-\x{9fff}]' --exclude-dir=.git --exclude-dir=.venv .` | no output |
| README "MSPbots Connector" section vs. `vendor-mcp-development/reference/readme-connector-section.md` | unchanged this round, still identical (not touched by this fix) |
| `gitleaks detect` | not available on this machine (unchanged from round 1); no credentials added or changed in this fix |
| Manual smoke: `uv run python -m sentinelone_mcp` (placeholder headers, local) | `GET /health` → `{"status":"ok"}`; `tools/list` with no headers → HTTP 401; `tools/list` with placeholder headers → 36 tools incl. `search_agents`/`isolate_endpoint`/`reconnect_endpoint` (same count as round 1, confirms no signature regression); `tools/call search_agents` against the real `placeholder.sentinelone.net` console → reached SentinelOne's API gateway, `HTTP 401` returned immediately (non-retryable, as designed) and mapped to `{"error":{"code":"unauthorized",...}}` — same live-reachability evidence as round 1 |

No test case in `docs/tickets/PRD-21243.ac.json` was touched by this fix (it changes `agents_api.py`'s
internal transport behavior only, not any tool's inputs/outputs/error mapping); the TC-S1-00x matrix
and its 7 `blocked`-on-real-account entries from round 1 are unaffected and unchanged.

## Round 2 · 2026-10-30 · reviewed 50061de (base 338304a)

Verdict: approved

### Scope

`git diff 338304a...50061de -- src/ tests/` (`docs/tickets/PRD-21243-review.md` is the review
record itself — commits `4e4aba8`, `7852ee2`, `50061de` only touch it and are not re-reviewed as
code; `7852ee2` translates two quoted SOP fragments that round 1 left in Chinese back into
English, a docs-only correction, not a code change). Diff is exactly commit `9a0342d`:
`src/sentinelone_mcp/agents_api.py` (+50/-4) and `tests/test_agents_api.py` (+69). No other file
changed since round 1 — `README.md` is untouched this round (still byte-identical to
`vendor-mcp-development/reference/readme-connector-section.md`, confirmed in round 1 and not
touched by `9a0342d`).

Re-ran independently on `50061de`: `uv run pytest -q` → `220 passed, 3 warnings in 16.28s` (matches
the self-test re-run reported in the Fixes section below, no new failures, no skips). CJK scan
(`grep -rnP '[\x{4e00}-\x{9fff}]' --exclude-dir=.git --exclude-dir=.venv .`) → no output, repo-wide
(not just the diff). Full `abe07ac...50061de` diff stat reviewed to confirm no scope creep since
round 1: `README.md`, `docs/tickets/PRD-21243.ac.json`, `docs/tickets/PRD-21243.md`,
`src/sentinelone_mcp/{agents_api.py,server.py,tools.py}`, `tests/{test_agents_api.py,test_tools.py}`
— unchanged set of files from round 1 plus the round-1 fix, nothing unrelated touched.

### Verification of round 1 must-fix #1 (`agents_api.py:59-61`, bounded retry)

Read `9a0342d` in full, not just the stub's description:

- `_send_with_retry` wraps both outbound calls (`list_agents`'s `client.get` at the call site,
  `_agent_action`'s `client.post`) behind a `Callable[[], Awaitable[httpx.Response]]`, so the
  existing `response.status_code >= 400` → `_fail` mapping downstream is untouched — confirmed by
  reading the full file, not just the diff hunks.
- Retries only `{429, 500, 502, 503, 504}` (`_RETRYABLE_STATUSES`); any other status, including
  every other `4xx` (403/404/...), returns on the first attempt — exactly what SOP §5 requires
  (bounded retry for 429/5xx, no retry for other 4xx). `test_non_transient_4xx_does_not_retry`
  asserts exactly 1 call on a 403.
- Bounded at `_MAX_ATTEMPTS = 3` (1 initial + 2 retries), backoff `0.5s * 2^(attempt-1)` capped at
  `8s` — worst case (2 retries at the cap) is 16s, well inside the SOP §5 / §14 120s-per-call
  ceiling together with `_run_classic`'s unchanged 100s `asyncio.wait_for` budget
  (`tools.py:161`, confirmed unchanged in the `abe07ac...50061de` diff — this PR does not touch
  `tools.py`'s timeout).
- `Retry-After` is read and honored when it parses as a plain float, capped at the same 8s ceiling
  so a server-supplied large value cannot blow the call budget; a non-numeric value (e.g. an
  HTTP-date) falls back to the exponential schedule instead of crashing — reasonable, and covered
  by the `test_429_then_200_retries_and_succeeds` case (`Retry-After: "1"`).
- New tests are status-code driven (construct `httpx.Response` directly), not timing-dependent,
  and monkeypatch `agents_api.asyncio.sleep` so the suite doesn't actually wait out the backoff —
  ran them: `test_429_then_200_retries_and_succeeds`, `test_503_then_200_retries_and_succeeds_for_list`,
  `test_retries_are_bounded_then_fails_with_the_last_status`, `test_non_transient_4xx_does_not_retry`
  all pass as part of the 220.
- The "not reused: purple-mcp's tenacity policies" rationale in the Fixes section checks out
  against the actual retry predicates in `graphql_client_base.py` / `sdl_query_client.py`
  (exception-driven, retries on any `httpx.HTTPError`) — a hand-rolled status-code-driven loop is
  the correct choice here given SOP §5's "don't retry other 4xx" requirement, not a shortcut.

No new must-fix. The fix matches the technical design's error-envelope convention (nothing in
`_fail` or `_envelope_for` changed) and does not introduce a new dependency (`tenacity` stays
indirect, unchanged in `uv.lock`).

### Findings

None.

### Suggestions

None beyond round 1 (already resolved or not applicable).
