"""The LLM leg through the Portkey AI gateway.

Uses the vendor SDK rather than hand-rolled HTTP. Not because the call is hard — it is one JSON
POST — but because a customer deployment is easier to reason about when the appliance is running
the vendor's own client, with their retry and timeout defaults and their docs.

Two behaviours of that SDK are load-bearing here and were verified before depending on them:

  * a successful turn keeps `hook_results` on the response, so an inline guardrail verdict
    survives `model_dump()`;
  * a guardrail block arrives as an exception, and the hook results survive on
    `exc.response.json()` — NOT on `exc.body`, which carries only the error message.

That second one is the whole reason this file catches by shape rather than by class. Reading the
verdict off the exception is what keeps "was this turn inspected" separate from "did this turn
succeed"; losing it would turn a guardrail block into a generic upstream error.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Sequence

from portkey_ai import Portkey

from src.llm.transport import (
    Completion, LlmTransport, Message, ToolSpec, build_body, parse_choice,
)

log = logging.getLogger("pretzel-ai.llm")

# The gateway answers a guardrail denial with this, which is not in anyone's HTTP registry.
GUARDRAIL_STATUS = 446


class PortkeyTransport:
    """Implements src.llm.transport.LlmTransport against an AI gateway."""

    def __init__(self, base_url: str, api_key: str, *, timeout_sec: float = 45.0,
                 token_param_for=None, extra_headers: dict[str, str] | None = None) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout_sec
        self._extra = dict(extra_headers or {})
        # Injected so the transport does not need the catalog: it asks a callable which name this
        # model's output cap goes out under.
        self._token_param_for = token_param_for or (lambda _model: "max_tokens")
        self._client = Portkey(base_url=self._base_url, api_key=api_key)

    @property
    def describes(self) -> str:
        return f"gateway {self._base_url}"

    def complete(self, model: str, messages: Sequence[Message], *,
                 tools: Sequence[ToolSpec] = (), tool_choice: str = "auto",
                 max_tokens: int = 4096, trace_id: str = "") -> Completion:
        body = build_body(model, messages, tools=tools, tool_choice=tool_choice,
                          token_param=self._token_param_for(model), max_tokens=max_tokens)
        # The SDK takes model and messages as named arguments and everything else through
        # extra_body, so they come back out of the body we just built.
        model_arg = body.pop("model")
        messages_arg = body.pop("messages")

        headers = dict(self._extra)
        if trace_id:
            # Forwarded to Prisma AIRS as the scan's tr_id. It is the only id the gateway's hook
            # sets, which is why the appliance's own three-level scheme only lands fully on the
            # direct scan path.
            headers["x-portkey-trace-id"] = trace_id

        started = time.monotonic()
        try:
            response = self._client.chat.completions.create(
                model=model_arg, messages=messages_arg, extra_body=body,
                extra_headers=headers or None, timeout=self._timeout)
            doc = response.model_dump()
            status = 200
        except Exception as exc:                    # noqa: BLE001 - classified by shape below
            # Not caught by class: the SDK raises openai.APIStatusError, and `openai` is vendored
            # inside portkey_ai and not importable here. Naming it would mean reaching into a
            # private path a version bump can move. The shape is stable — an HTTP failure carries
            # a response we can read, a transport failure does not.
            doc, status, transport_error = _classify(exc)
            if transport_error:
                return Completion(ok=False, code="UNREACHABLE", error=transport_error,
                                  model=model,
                                  latency_ms=int((time.monotonic() - started) * 1000))

        latency_ms = int((time.monotonic() - started) * 1000)
        return _to_completion(doc, status, latency_ms, model)


def _classify(exc: Exception) -> tuple[dict[str, Any], int, str]:
    """→ (document, status, transport error). An empty transport error means it was HTTP."""
    response = getattr(exc, "response", None)
    status = int(getattr(exc, "status_code", 0) or 0)
    if response is None or not status:
        return {}, 0, str(exc)[:300]
    try:
        doc = response.json()
    except Exception:                               # noqa: BLE001 - a non-JSON error body
        return {"__raw__": (getattr(response, "text", "") or "")[:400]}, status, ""
    return (doc if isinstance(doc, dict) else {"__raw__": str(doc)[:400]}), status, ""


def _to_completion(doc: dict[str, Any], status: int, latency_ms: int, model: str) -> Completion:
    if "__raw__" in doc:
        return Completion(ok=False, code="BAD_RESPONSE", status=status, latency_ms=latency_ms,
                          model=model, raw=doc,
                          error=f"gateway response was not JSON: {doc['__raw__']}")

    error = doc.get("error") if isinstance(doc.get("error"), dict) else {}
    error_type = str(error.get("type", ""))
    error_msg = str(error.get("message", ""))

    if not error_msg and doc.get("status") == "failure":
        error_msg = str(doc.get("message", "")) or "the gateway rejected the request"
        error_type = error_type or "gateway_rejected"

    if status == GUARDRAIL_STATUS or error_type == "hooks_failed" or _soft_denied(doc):
        return Completion(ok=False, code="BLOCKED", status=status, latency_ms=latency_ms,
                          model=model, raw=doc,
                          error=error_msg or "the guardrail denied this turn")

    if error_type or error_msg:
        return Completion(ok=False, code="UPSTREAM_ERROR", status=status, latency_ms=latency_ms,
                          model=model, raw=doc,
                          error=error_msg or "the provider returned an error")

    text, calls, finish = parse_choice(doc)
    if not text and not calls:
        return Completion(ok=False, code="BAD_RESPONSE", status=status, latency_ms=latency_ms,
                          model=model, raw=doc,
                          error="gateway response carried no completion")

    usage = doc.get("usage") if isinstance(doc.get("usage"), dict) else {}
    return Completion(ok=True, text=text, tool_calls=calls, finish_reason=finish,
                      usage=usage, status=status, latency_ms=latency_ms,
                      model=str(doc.get("model") or model), raw=doc)


def _soft_denied(doc: dict[str, Any]) -> bool:
    """A denial wearing a 200. The gateway forwarded nothing and said so inside the hook; read as
    anything else, enforcement looks off when it is on."""
    hooks = doc.get("hook_results")
    if not isinstance(hooks, dict):
        return False
    for key in ("before_request_hooks", "after_request_hooks"):
        for hook in hooks.get(key) or []:
            if isinstance(hook, dict) and (hook.get("deny") or hook.get("softDeny200")):
                return True
    return False
