"""The provider endpoint, and the HTTP round trip to it.

Straight to the vendor, with no gateway in the path. This is how the appliance runs today, and
it is the shape the guardrail work has to account for: nothing inspects a turn on this path
unless the appliance inspects it. A completion here carries no gateway hook results, and the
code that reads one must not treat their absence as a clean scan.

urllib rather than a vendor SDK: there is no one vendor here. The endpoint, the header a key
goes in, and the prefix it takes are per-provider config, and every provider worth pointing at
publishes an OpenAI-compatible chat-completions endpoint. One code path, described by data.

The call is synchronous and blocking, deliberately. Streaming is off in wire.build_body because
a response-side checkpoint has to see a whole answer before any of it is shown - so a turn
holds its gRPC worker for the length of the round trip, and the console is sent a finished
answer that the handler re-streams.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Sequence

from src.completion import Completion, Message
from src.completion.wire import build_body, parse_choice

log = logging.getLogger("pretzel-ai.transport.direct")


def _default_token_param(model: str) -> str:
    """What a model wants its output cap called, when nothing said otherwise.

    The old name, because it is the one every provider still accepts. The gpt-5 generation rejects
    it and wants `max_completion_tokens`, which is why this is a fallback and not a constant - the
    catalog carries the real answer per model.
    """
    return "max_tokens"


def _strip_routing_slug(model: str) -> str:
    """"openai/gpt-4o" -> "gpt-4o". The provider has never heard of the slug.

    A blunter rule than the catalog's, which knows which spellings name the same model. Used only
    when no catalog was handed in.
    """
    return model.split("/", 1)[-1]

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

        # Both are injected because the CATALOG knows them, not this file: which parameter a model
        # wants its token cap under, and which spellings name the same model. The fallbacks below
        # are for a transport built without one - a probe, or a test - and are named rather than
        # written inline so a stack trace says which one ran.
        if token_param_for is None:
            token_param_for = _default_token_param
        self._token_param_for = token_param_for

        if bare_model is None:
            bare_model = _strip_routing_slug
        self._bare_model = bare_model

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
                 max_tokens: int = 4096, trace_id: str = "") -> Completion:
        endpoint, error = self.endpoint_for(model)
        if endpoint is None:
            return Completion(ok=False, code="BAD_ROUTE", error=error, model=model)

        body = build_body(model, messages,
                          token_param=self._token_param_for(model), max_tokens=max_tokens)
        # The provider has never heard of the routing slug.
        body["model"] = self._bare_model(model)

        headers = {"Content-Type": "application/json",
                   "Accept": "application/json",
                   "User-Agent": USER_AGENT,
                   **endpoint.auth()}

        """ POST """
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
    """The provider's document. `__raw__` when it was not one this code can read.

    Gemini's OpenAI-compatible endpoint answers an ERROR as a one-element JSON ARRAY -
    [{"error": {"code": 503, "message": "This model is currently experiencing high demand",
    "status": "UNAVAILABLE"}}] - while a success is a plain object. Measured 2026-09-02 on a
    live 503. Unwrapped here rather than in _to_completion because it is a fact about the
    envelope, not about what the envelope said: left wrapped, a busy model is reported to the
    operator as "provider response was not JSON", which sends them looking for a parse bug
    instead of retrying.
    """
    try:
        doc = json.loads(raw.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        return {"__raw__": raw.decode("utf-8", "replace")[:400]}

    if isinstance(doc, list) and len(doc) == 1 and isinstance(doc[0], dict):
        return doc[0]

    if isinstance(doc, dict):
        return doc

    # Valid JSON, but not a shape this code can read. Kept as text so the error says what actually
    # came back rather than that something was missing from it.
    return {"__raw__": str(doc)[:400]}


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

    text, finish = parse_choice(doc)
    if not text:
        return Completion(ok=False, code="BAD_RESPONSE", status=status, latency_ms=latency_ms,
                          model=model, raw=doc, error="provider response carried no completion")

    usage = doc.get("usage") if isinstance(doc.get("usage"), dict) else {}
    return Completion(ok=True, text=text, finish_reason=finish,
                      usage=usage, status=status, latency_ms=latency_ms,
                      model=str(doc.get("model") or model), raw=doc)
