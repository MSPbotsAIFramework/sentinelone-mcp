# SentinelOne MCP Server

An [MCP](https://modelcontextprotocol.io) server for [SentinelOne](https://www.sentinelone.com)
Singularity. It lets an AI agent ask Purple AI hunting questions, run PowerQueries over the
Singularity Data Lake, and read alerts, vulnerabilities, misconfigurations and the asset
inventory of one SentinelOne console, plus VirusTotal and public CVE lookups. It is read-only.

The tools come from SentinelOne's own open-source tool library,
[purple-mcp](https://github.com/Sentinel-One/purple-mcp) (MIT), which is installed as a pinned
dependency. purple-mcp reads one console's credentials from environment variables when it
starts; this server adds what a multi-tenant gateway needs: credentials per request, the
standard error envelope, concise tool documentation, and the usual health and isolation
guarantees.

- Transport: MCP Streamable HTTP at `POST /mcp`, health probe at `GET /health`
- Stateless and multi-tenant: credentials arrive on every request as HTTP headers and are
  never stored; every tool is listed from the first `tools/list`
- Python 3.12, [uv](https://docs.astral.sh/uv/), FastMCP, purple-mcp
- License: Apache-2.0, Copyright 2026 MSPbots.ai (purple-mcp: MIT, see [NOTICE](NOTICE))

<div align="center">

## MSPbots Connector

**The MCP Gateway built for MSPs: visible, controlled, and your data stays where it belongs.**

[**Get started at connect.mspbots.ai →**](https://connect.mspbots.ai)

</div>

---

MSPbots Connector gives your AI clients one MCP URL to reach your entire MSP stack (RMM, PSA, documentation, security, finance), and gives you control over who can call which tool and a record of everything that was called.

**Hosted service: [connect.mspbots.ai](https://connect.mspbots.ai)** · Free to use.

### Why Connector

![MSPbots Connector](https://stgoss.mspbots.ai/files/mcp/mspbots-mcp.png)

| | |
|---|---|
| **Visible** | Every tool call is logged: who, which vendor, when. Usage dashboard, CSV export, SIEM streaming. |
| **Controlled** | Role-based, per-tool allowlist. Deny by default. |
| **Protected** | Credentials encrypted per record. AI clients never see your vendor passwords or tokens. |
| **MSP-native** | Built for the MSP stack only: RMM, PSA, documentation, security, finance. |

### Quick start

1. **Sign up** at [connect.mspbots.ai](https://connect.mspbots.ai).
2. **Connect your vendors.** Pick from 150+ connectors and authorize each one on the vendor's own page, or bring your own API keys. No extra vendor accounts needed.
3. **Set access.** Create roles and decide which tools each role may call. Nothing is allowed until you allow it.
4. **Add your MCP URL to your AI client.** Copy the URL from your Connector dashboard into Claude, ChatGPT, Cursor, VS Code, Gemini, Codex, or any MCP-capable client.
5. **Ask your AI to do real work**, and watch every call appear in the audit log.

### Features

**Unified gateway**
- One MCP URL for all your AI clients
- 150+ connectors across the MSP stack
- Custom MCP servers supported, free
- Authorization happens on each vendor's own page; the AI never sees passwords or tokens
- Bring your own credentials: use the vendor API keys you already have
- Multiple accounts per app; connect once, reuse across AI clients
- Tool search: finds the right action for the task
- One sign-in; vendor credentials are injected behind the scenes and OAuth tokens refresh automatically

**Visibility**
- Audit log for every tool call (who, which vendor, when)
- Usage dashboard: call volume, top vendors, error rate, per-user activity
- Export audit logs to CSV, or stream to Loki, Graylog, or LogScale (SIEM)
- Optional recording of tool arguments and result summaries (off by default, enabled per organization)

**Control**
- Per-role, per-tool allowlist, deny by default
- owner / admin / member roles
- SCIM provisioning with Entra ID, Okta, JumpCloud, and Google Workspace

**Security**
- Credentials encrypted one record at a time (AES-256-GCM, per-record key)
- AI clients authenticate with OAuth 2.1 + PKCE
- Vendor responses are scanned for prompt-injection patterns and returned as structured data. This is one layer of defense, not a guarantee against every attack.
- Static egress IP for customer firewall and API allowlisting

### Pricing

**Free.**

Links: [connect.mspbots.ai](https://connect.mspbots.ai) · [mspbots.ai](https://mspbots.ai)

---

## Authentication headers

| Header | Required | Type | Default | Allowed values | Description | Example |
|---|---|---|---|---|---|---|
| `X-Purplemcp-Base-Url` | Yes | string | none | https URL | SentinelOne console URL (`X-S1-Console-URL` is also accepted) | `https://your-console.sentinelone.net` |
| `X-Purplemcp-Token` | Yes | string | none | - | Console API token of a service user (`X-S1-API-Token` is also accepted; a leading `ApiToken `/`Bearer ` is ignored) | `your-console-token` |
| `X-Virustotal-Api-Key` | No | string | none | - | VirusTotal API key, needed only by the `threat_intel_*` tools | `your-virustotal-key` |

Where to get them:

- In the SentinelOne console create a **service user** (Policy & Settings -> User Management ->
  Service Users) at Account or Site scope with a viewer-level role, and generate its API token.
  The token must cover a single Account or Site; Global-scope tokens are not supported. Purple
  AI and the Data Lake need the matching licences on the account.
- The console URL is the address you sign in to, e.g. `https://your-console.sentinelone.net`;
  a path after the host name is ignored.
- A VirusTotal key comes from the VirusTotal profile page; `threat_intel_search` needs a
  key with Intelligence access.

How credentials are used: for each request the server builds purple-mcp's settings from these
headers and makes them current only for that request; purple-mcp then calls the console's
GraphQL and REST APIs with the token. A request to `/mcp` without the URL or token gets HTTP
401 naming the missing header; a URL that is not https gets HTTP 400.

## Tools

All tools return a JSON string and are read-only. Lists page with `first` (1-100) and `after`
(`next_after`, or `pageInfo.endCursor`, of the previous page); the inventory pages with `limit` / `skip`
(`next_skip`). `threat_intel_search` and `cve_search_by_vendor` come back whole and take `offset` /
`limit` (`next_offset`). Results are compact JSON kept under 20,000 characters: when a list is cut to fit,
`next_after` / `next_skip` / `next_offset` start right after the last record returned (and `pageInfo`
agrees), so following them never skips records; long text answers are shortened with a note.
`search_*` tools take `filters` as a JSON string or array (see each tool's parameter
description); datetime filters use epoch milliseconds from `iso_to_unix_timestamp`.

| Tool | Purpose | Parameters (required in **bold**) |
|---|---|---|
| `purple_ai` | Ask Purple AI a hunting question; it answers or returns a PowerQuery | **query** |
| `powerquery` | Run a PowerQuery over the Data Lake for a time window | **query**, **start_datetime**, **end_datetime** |
| `get_timestamp_range` | Compute a start / end window (e.g. last 24 h) | reference_time, years, months, weeks, days, hours, minutes, seconds, direction |
| `iso_to_unix_timestamp` | Convert an ISO 8601 time to epoch milliseconds | **iso_datetime** |
| `get_alert` | One alert | **alert_id** |
| `list_alerts` | Alerts, newest first, by assignment | first, after, view_type, fields |
| `search_alerts` | Alerts by severity, status, verdict, assignee, name, time | filters, first, after, view_type, fields |
| `get_alert_notes` | Analyst notes on an alert | **alert_id** |
| `get_alert_history` | An alert's audit trail | **alert_id**, first, after |
| `get_alert_investigation_report` | Purple AI's auto-investigation report for an alert | **alert_id** |
| `get_misconfiguration` | One misconfiguration | **misconfiguration_id** |
| `list_misconfigurations` | Posture misconfigurations by environment | first, after, view_type, fields |
| `search_misconfigurations` | Misconfigurations by severity, status, asset, policy, compliance | filters, first, after, view_type, fields |
| `get_misconfiguration_notes` | Notes on a misconfiguration | **misconfiguration_id** |
| `get_misconfiguration_history` | A misconfiguration's audit trail | **misconfiguration_id**, first, after |
| `get_vulnerability` | One vulnerability | **vulnerability_id** |
| `list_vulnerabilities` | Vulnerabilities, newest first | first, after, fields |
| `search_vulnerabilities` | Vulnerabilities by severity, CVE, exploitation, KEV, software, asset | filters, first, after, fields |
| `get_vulnerability_notes` | Notes on a vulnerability | **vulnerability_id** |
| `get_vulnerability_history` | A vulnerability's audit trail | **vulnerability_id**, first, after |
| `get_inventory_item` | One asset from the unified inventory | **item_id**, fetch_fields |
| `list_inventory_items` | Assets, optionally for one surface | limit, skip, surface, fetch_fields |
| `search_inventory_items` | Assets by type, status, OS, name, cloud, last activity | filters, limit, skip, fetch_fields |
| `threat_intel_by_hash` | VirusTotal report for a file hash | **hash_value** |
| `threat_intel_by_url` | VirusTotal reputation for a URL | **url** |
| `threat_intel_by_domain` | VirusTotal reputation for a domain | **domain** |
| `threat_intel_by_ip` | VirusTotal reputation for an IP | **ip_address** |
| `threat_intel_get_file_relationships` | A file's contacted IOCs or related files | **hash_value**, **relationship_type** |
| `threat_intel_search` | VirusTotal Intelligence search | **query**, offset, limit |
| `threat_intel_get_file_behavior` | VirusTotal sandbox behaviour for a file | **hash_value**, sandbox |
| `cve_search_by_id` | One CVE from a public CVE database | **cve_id** |
| `cve_search_by_vendor` | CVEs for a vendor / product | **vendor**, product, offset, limit |
| `cve_database_status` | Public CVE database freshness | - |

Errors come back as a JSON envelope instead of an exception:

```json
{"error": {"code": "unauthorized", "message": "...401...", "retryable": false}}
```

`code` is one of `not_configured`, `unauthorized`, `not_found`, `invalid_argument`,
`rate_limited`, `upstream_error`.

## Run locally

```bash
uv sync
uv run python -m sentinelone_mcp          # listens on 0.0.0.0:8080
```

or with Docker:

```bash
docker build --platform linux/amd64 -t sentinelone-mcp:dev .
docker run --rm -p 8080:8080 sentinelone-mcp:dev
```

Configuration (environment variables, all optional): `MCP_HTTP_HOST` (default `0.0.0.0`),
`MCP_HTTP_PORT` (default `8080`), `LOG_LEVEL` (default `INFO`). Credentials are never read
from the environment.

## Testing example

```bash
# list tools
curl -s http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-Purplemcp-Base-Url: https://your-console.sentinelone.net" \
  -H "X-Purplemcp-Token: your-console-token" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

# new critical alerts
curl -s http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-Purplemcp-Base-Url: https://your-console.sentinelone.net" \
  -H "X-Purplemcp-Token: your-console-token" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_alerts","arguments":{"filters":[{"fieldId":"severity","filterType":"string_equals","value":"CRITICAL"},{"fieldId":"status","filterType":"string_equals","value":"NEW"}],"first":10}}}'
```

Unit tests (no network access needed):

```bash
uv run pytest
```

## Delivery notes

- **Tool count (33).** Names and parameters are purple-mcp's, kept as an existing contract.
- **Built on the vendor's library.** API calls, GraphQL queries and parsing are purple-mcp's,
  pinned to a reviewed commit in `pyproject.toml`; updating it is a one-line change followed
  by the snapshot tests.
- **Per-request credentials.** purple-mcp looks its settings up through one function; this
  server points that function at the current request's settings, so concurrent tenants never
  share a token, and no process-wide credentials exist.
- **Documentation.** Tool descriptions are short; filter syntax, field names and enum values
  are in each parameter's description.
- **Threat intelligence** needs the optional VirusTotal key; without it those tools say so.

## License

Apache License 2.0 - see [LICENSE](LICENSE) and [NOTICE](NOTICE).
