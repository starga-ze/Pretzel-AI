"""The LLM leg straight to the provider, with no gateway in the path.

This is how customers run the appliance today when they have not deployed a gateway, and it is the
shape the guardrail work has to account for: nothing inspects a turn on this path unless the
appliance inspects it. A completion here carries no `hook_results`, and the code that reads one
must not treat their absence as a clean scan — src/guardrail.py's NOT_INSPECTED exists for exactly
this deployment.

urllib rather than a vendor SDK: there is no one vendor here. The endpoint, the header a key goes
in, and the prefix it takes are per-provider config, and every provider worth pointing at publishes
an OpenAI-compatible chat-completions endpoint. One code path, described by data.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Sequence

from src.llm.transport import (
    Completion, LlmTransport, Message, ToolSpec, build_body, parse_choice,
)

log = logging.getLogger("pretzel-ai.llm")

USER_AGENT = "pz-pretzel-ai/1.0"


@dataclass(frozen=True)
class Endpoint:
    """One provider's chat-completions endpoint, and how it wants to be authenticated."""

    url: str
    api_key: str
    auth_header: str = "Authorization"
    auth_prefix: str = "Bearer "
    headers: dict[str, str] = field(default_factory=dict)

    def auth(self) -> dict[str, str]:
        return {self.auth_header: f"{self.auth_prefix}{self.api_key}", **self.headers}


class DirectTransport:
    """Implements src.llm.transport.LlmTransport against provider endpoints.

    Holds one endpoint per provider slug and picks by the model's slug, so a single appliance can
    serve `openai/…` and `claude/…` in the same catalog without a gateway between.
    """

    def __init__(self, endpoints: dict[str, Endpoint], *, timeout_sec: float = 45.0,
                 token_param_for=None, bare_model=None) -> None:
        self._endpoints = dict(endpoints)
        self._timeout = timeout_sec
        self._token_param_for = token_param_for or (lambda _model: "max_tokens")
        # The routing slug is the gateway's syntax; a provider's own API wants the model name
        # alone. The catalog knows how to strip it, so it is injected rather than re-derived.
        self._bare_model = bare_model or (lambda model: model.split("/", 1)[-1])

    @property
    def describes(self) -> str:
        if not self._endpoints:
            return "direct (no provider endpoint configured)"
        return "direct → " + ", ".join(sorted(self._endpoints))

    def endpoint_for(self, model: str) -> tuple[Endpoint | None, str]:
        """→ (endpoint, error). The slug decides; a bare model name has nowhere to go.

        Both spellings are accepted, for the reason Model.slug gives: "@openai/…" is a gateway
        config's, "openai/…" is the appliance's, and they name the same provider.
        """
        head = model[1:] if model.startswith("@") else model
        slug = head.split("/", 1)[0] if "/" in head else ""
        if not slug:
            return None, (f"model '{model}' carries no provider slug, so there is no direct "
                          f"endpoint to send it to")
        endpoint = self._endpoints.get(slug)
        if endpoint is None:
            return None, f"no direct endpoint is configured for provider '{slug}'"
        return endpoint, ""

    def complete(self, model: str, messages: Sequence[Message], *,
                 tools: Sequence[ToolSpec] = (), tool_choice: str = "auto",
                 max_tokens: int = 4096, trace_id: str = "") -> Completion:
        endpoint, error = self.endpoint_for(model)
        if endpoint is None:
            return Completion(ok=False, code="BAD_ROUTE", error=error, model=model)

        body = build_body(model, messages, tools=tools, tool_choice=tool_choice,
                          token_param=self._token_param_for(model), max_tokens=max_tokens)
        # The provider has never heard of the routing slug.
        body["model"] = self._bare_model(model)

        headers = {"Content-Type": "application/json",
                   "Accept": "application/json",
                   "User-Agent": USER_AGENT,
                   **endpoint.auth()}

        started = time.monotonic()
        status, doc, transport_error = self._post(endpoint.url, body, headers)
        latency_ms = int((time.monotonic() - started) * 1000)

        if transport_error:
            return Completion(ok=False, code="UNREACHABLE", error=transport_error,
                              model=model, latency_ms=latency_ms)

        return _to_completion(doc, status, latency_ms, model)

    def _post(self, url: str, body: dict[str, Any],
              headers: dict[str, str]) -> tuple[int, dict[str, Any], str]:
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
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


def _to_completion(doc: dict[str, Any], status: int, latency_ms: int, model: str) -> Completion:
    if "__raw__" in doc:
        return Completion(ok=False, code="BAD_RESPONSE", status=status, latency_ms=latency_ms,
                          model=model, raw=doc,
                          error=f"provider response was not JSON: {doc['__raw__']}")

    error = doc.get("error") if isinstance(doc.get("error"), dict) else {}
    if error or status >= 400:
        message = str(error.get("message", "")) or f"the provider returned HTTP {status}"
        return Completion(ok=False, code="UPSTREAM_ERROR", status=status, latency_ms=latency_ms,
                          model=model, raw=doc, error=message)

    text, calls, finish = parse_choice(doc)
    if not text and not calls:
        return Completion(ok=False, code="BAD_RESPONSE", status=status, latency_ms=latency_ms,
                          model=model, raw=doc, error="provider response carried no completion")

    usage = doc.get("usage") if isinstance(doc.get("usage"), dict) else {}
    return Completion(ok=True, text=text, tool_calls=calls, finish_reason=finish,
                      usage=usage, status=status, latency_ms=latency_ms,
                      model=str(doc.get("model") or model), raw=doc)
