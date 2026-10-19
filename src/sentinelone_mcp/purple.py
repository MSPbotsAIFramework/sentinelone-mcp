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
"""Per-request credentials for SentinelOne's purple-mcp tool library.

purple-mcp reads its console URL and token once from environment variables
(``purple_mcp.config.get_settings()``), which makes one process serve one
tenant. Every purple-mcp tool resolves its settings through
``get_settings() -> _load_base_settings()``; that second function is looked up
in the config module at call time, so replacing it with a reader of a
context variable gives each request its own settings without touching the
library's tool code. Nothing credential-related is stored at module level.
"""

import contextlib
import contextvars
import logging
from collections.abc import Iterator

# Importing purple_mcp.config tries to load settings from the environment and
# logs a CRITICAL traceback when they are absent, which they always are here.
_purple_logger = logging.getLogger("purple_mcp")
_previous_level = _purple_logger.level
_purple_logger.setLevel(logging.CRITICAL + 1)
try:
    import purple_mcp.config as purple_config
finally:
    # The library logs every settings construction at INFO; keep its warnings only.
    _purple_logger.setLevel(max(_previous_level, logging.WARNING))

_settings_var: contextvars.ContextVar["purple_config.Settings | None"] = contextvars.ContextVar(
    "purple_settings", default=None
)


class MissingCredentials(ValueError):
    """A purple-mcp tool ran outside a request that carried SentinelOne credentials."""


def _request_settings() -> "purple_config.Settings":
    settings = _settings_var.get()
    if settings is None:
        raise MissingCredentials("SentinelOne credentials are missing for this request.")
    return settings


# Route every purple-mcp settings lookup to the current request.
purple_config._load_base_settings = _request_settings  # type: ignore[assignment]


def build_settings(console_base_url: str, token: str, virustotal_api_key: str | None = None) -> "purple_config.Settings":
    """purple-mcp settings for one tenant; raises ValueError for an unusable URL."""
    values = {
        purple_config.CONSOLE_TOKEN_ENV: token,
        purple_config.CONSOLE_BASE_URL_ENV: console_base_url,
    }
    if virustotal_api_key:
        values[purple_config.VT_API_KEY_ENV] = virustotal_api_key
    try:
        return purple_config.Settings(**values)
    except Exception as e:  # pydantic ValidationError carries the reason
        raise ValueError(f"Invalid SentinelOne console settings: {_first_line(e)}") from None


@contextlib.contextmanager
def use_settings(settings: "purple_config.Settings") -> Iterator[None]:
    token = _settings_var.set(settings)
    try:
        yield
    finally:
        _settings_var.reset(token)


def current_settings() -> "purple_config.Settings | None":
    return _settings_var.get()


def _first_line(error: Exception) -> str:
    lines = [line.strip() for line in str(error).splitlines() if line.strip()]
    # pydantic: "1 validation error for Settings" / "<field>" / "  Value error, <reason> [...]"
    for line in lines:
        if "error," in line.lower():
            return line.split(",", 1)[1].split("[type=")[0].strip()
    return lines[-1][:200] if lines else type(error).__name__
