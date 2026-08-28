"""The Prisma AIRS scan API, as this appliance calls it.

Transport only: build the request, post it, hand back the parsed document. It knows the vendor's
wire format and nothing about what a verdict means — that translation is next door in scan.py, so
the day the API changes shape only this file moves.

Written against the HTTP endpoint rather than pan-aisecurity's SDK on purpose. The SDK is a
generated OpenAPI client wrapped around aiohttp, and it brings twenty-one transitive packages onto
an appliance to send one JSON body that urllib already sends. Its models were worth reading — the
schema below was checked against them field by field — but not worth depending on. Two facts from
that reading are load-bearing and are the ones people get wrong:

  * `tool_event.metadata` is NESTED. Flattened, the service answers 400 `invalid tool event`.
  * `tool_event.input` / `output` are JSON *strings*, not objects. Objects answer 500.

Sizes and retry statuses are the SDK's own constants, kept here so a limit is enforced where the
request is built rather than discovered as a truncation somewhere downstream.
"""

from __future__ import annotations

import json
import logging
import random
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("pretzel-ai.airs")

DEFAULT_ENDPOINT = "https://service.api.aisecurity.paloaltonetworks.com"
SCAN_SYNC_PATH = "/v1/scan/sync/request"

# The vendor's limits. Prompt and response cap far below `context`, which exists to carry whole
# retrieved documents.
MAX_PROMPT_BYTES = 2 * 1024 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_CONTEXT_BYTES = 100 * 1024 * 1024
MAX_PROFILE_NAME = 100

# Retried because they mean the request did not happen. A 4xx other than 429 means it happened and
# was wrong, and repeating a wrong request is a slower way to be wrong.
RETRY_STATUSES = frozenset((429, 500, 502, 503, 504))
MAX_ATTEMPTS = 3
BACKOFF_BASE_SEC = 0.5
BACKOFF_CAP_SEC = 8.0

USER_AGENT = "pz-pretzel-ai/1.0"


class AirsError(Exception):
    """The scan did not produce a verdict. Carries whether the cause was transport or the service
    itself, because those are chased in different places."""

    def __init__(self, message: str, *, status: int = 0, transport: bool = False) -> None:
        super().__init__(message)
        self.status = status
        self.transport = transport


@dataclass(frozen=True)
class ToolEvent:
    """One tool invocation, in the only shape the service accepts.

    `server` is required by the schema and is the field an AI gateway cannot supply: a chat
    completion request names a function, never the MCP server behind it. Only a runtime holding
    the tool registry knows, which is the structural reason this scan cannot be delegated to a
    gateway hook.
    """

    server: str
    tool: str
    ecosystem: str = "mcp"
    method: str = "tools/call"
    input: str | None = None       # JSON text
    output: str | None = None      # JSON text

    def as_content(self) -> dict[str, Any]:
        event: dict[str, Any] = {
            "metadata": {
                "ecosystem": self.ecosystem,
                "method": self.method,
                "server_name": self.server,
                "tool_invoked": self.tool,
            }
        }
        if self.input is not None:
            event["input"] = self.input
        if self.output is not None:
            event["output"] = self.output
        return {"tool_event": event}


@dataclass(frozen=True)
class ScanContent:
    """One element of `contents`.

    Several fields may be set together, and that is how a response gets judged against the prompt
    that produced it rather than in isolation.
    """

    prompt: str | None = None
    response: str | None = None
    context: str | None = None
    code_prompt: str | None = None
    code_response: str | None = None
    tool_event: ToolEvent | None = None

    def as_dict(self) -> dict[str, Any]:
        if self.tool_event is not None:
            out = self.tool_event.as_content()
        else:
            out = {}
        for name, value, cap in (("prompt", self.prompt, MAX_PROMPT_BYTES),
                                 ("response", self.response, MAX_RESPONSE_BYTES),
                                 ("context", self.context, MAX_CONTEXT_BYTES),
                                 ("code_prompt", self.code_prompt, MAX_PROMPT_BYTES),
                                 ("code_response", self.code_response, MAX_RESPONSE_BYTES)):
            if value is None:
                continue
            out[name] = _clip(value, cap, name)
        return out


def _clip(text: str, cap_bytes: int, field_name: str) -> str:
    """Trim to the service's limit, loudly.

    Silently sending 2 MiB of a 3 MiB document would produce a verdict about a fragment and report
    it as a verdict about the document. The cut is logged so that reading is never made by
    accident.
    """
    raw = text.encode("utf-8")
    if len(raw) <= cap_bytes:
        return text
    log.warning("airs: %s clipped from %d to %d bytes for the scan", field_name, len(raw), cap_bytes)
    return raw[:cap_bytes].decode("utf-8", "ignore")


@dataclass
class AirsConfig:
    """Everything needed to reach the service. `fail_closed` is policy rather than transport, and
    it lives here because it is set beside the endpoint in the same config file."""

    api_key: str = ""
    endpoint: str = DEFAULT_ENDPOINT
    profile_name: str = ""
    profile_id: str = ""
    timeout_sec: float = 30.0
    fail_closed: bool = True

    def validate(self) -> None:
        if not self.api_key:
            raise ValueError("airs: api_key is not configured")
        if not (self.profile_name or self.profile_id):
            raise ValueError("airs: one of profile_name or profile_id is required")
        if len(self.profile_name) > MAX_PROFILE_NAME:
            raise ValueError(f"airs: profile_name exceeds {MAX_PROFILE_NAME} characters")

    @property
    def profile(self) -> dict[str, str]:
        out = {}
        if self.profile_name:
            out["profile_name"] = self.profile_name
        if self.profile_id:
            out["profile_id"] = self.profile_id
        return out


class AirsClient:
    """Posts scans and returns the service's document. Raises AirsError when it cannot."""

    def __init__(self, config: AirsConfig) -> None:
        config.validate()
        self._config = config
        self._url = config.endpoint.rstrip("/") + SCAN_SYNC_PATH

    @property
    def config(self) -> AirsConfig:
        return self._config

    def scan(self, contents: list[ScanContent], *, tr_id: str = "", session_id: str = "",
             transaction_id: str = "", app_name: str = "pretzel-ai", app_user: str = "",
             ai_model: str = "", user_ip: str = "") -> tuple[dict[str, Any], int]:
        """→ (response document, latency in ms).

        `contents` is ordered and the service reads it that way: the LAST element is what gets
        judged, and everything before it is context for that judgement. A caller stacking history
        is choosing what gets scanned by choosing what goes last.
        """
        if not contents:
            raise AirsError("airs: nothing to scan")

        body: dict[str, Any] = {
            "ai_profile": self._config.profile,
            "contents": [c.as_dict() for c in contents],
            "metadata": {k: v for k, v in (("app_name", app_name), ("app_user", app_user),
                                           ("ai_model", ai_model), ("user_ip", user_ip)) if v},
        }
        # Sent only when set. An empty string is a value the service would file as an id, and a
        # scan filed under "" groups with every other scan that had none.
        for name, value in (("tr_id", tr_id), ("session_id", session_id),
                            ("transaction_id", transaction_id)):
            if value:
                body[name] = value

        return self._post(body)

    def _post(self, body: dict[str, Any]) -> tuple[dict[str, Any], int]:
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
            "x-pan-token": self._config.api_key,
        }

        started = time.monotonic()
        last_error = ""
        for attempt in range(1, MAX_ATTEMPTS + 1):
            status, doc, transport_error = self._once(payload, headers)

            if not transport_error and status == 200:
                return doc, int((time.monotonic() - started) * 1000)

            retryable = bool(transport_error) or status in RETRY_STATUSES
            last_error = transport_error or _service_error(status, doc)

            if not retryable or attempt == MAX_ATTEMPTS:
                raise AirsError(f"airs: {last_error}", status=status,
                                transport=bool(transport_error))

            delay = min(BACKOFF_CAP_SEC, BACKOFF_BASE_SEC * (2 ** (attempt - 1)))
            delay *= 1.0 + random.random() * 0.25   # jitter: workers share one rate bucket
            log.info("airs: retrying in %.2fs (attempt %d/%d, %s)",
                     delay, attempt, MAX_ATTEMPTS, last_error[:120])
            time.sleep(delay)

        raise AirsError(f"airs: {last_error}")      # unreachable; keeps the type honest

    def _once(self, payload: bytes, headers: dict[str, str]) -> tuple[int, dict[str, Any], str]:
        request = urllib.request.Request(self._url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self._config.timeout_sec) as response:
                return response.status, _parse(response.read()), ""
        except urllib.error.HTTPError as exc:
            return exc.code, _parse(exc.read()), ""
        except (urllib.error.URLError, OSError) as exc:
            return 0, {}, str(getattr(exc, "reason", exc))[:200]


def _parse(raw: bytes) -> dict[str, Any]:
    try:
        doc = json.loads(raw.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        return {"__raw__": raw.decode("utf-8", "replace")[:400]}
    return doc if isinstance(doc, dict) else {"__raw__": str(doc)[:400]}


def _service_error(status: int, doc: dict[str, Any]) -> str:
    """The service's own words when it has them. Its 400s name the field that was wrong, which is
    the whole value of reading them — `invalid tool event at index 0` is an answer."""
    error = doc.get("error")
    if isinstance(error, dict) and error.get("message"):
        return f"HTTP {status}: {str(error['message'])[:300]}"
    if isinstance(error, str) and error:
        return f"HTTP {status}: {error[:300]}"
    if "__raw__" in doc:
        return f"HTTP {status}: {doc['__raw__']}"
    return f"HTTP {status}"
