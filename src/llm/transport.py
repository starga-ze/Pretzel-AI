"""What a model call looks like, independent of who serves it.

Two implementations sit behind this: src/llm/portkey.py routes through the AI gateway, and
src/llm/direct.py goes straight to the provider. Customers run both — the gateway when they want
its routing and observability, the provider directly when they do not — and the appliance should
not care which is deployed.

Both speak the OpenAI chat-completions shape on the wire. That is a wire fact, not a vendor
preference: the gateway translates it to whatever the upstream expects, and providers other than
OpenAI publish compatible endpoints. Where a shape difference is real it is handled at the edge
that knows about it, not leaked into this vocabulary.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Protocol, Sequence


class Role(enum.Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


@dataclass(frozen=True)
class ToolSpec:
    """A tool offered to the model.

    `server` is not sent to the model — it has no field for it — but travels with the spec because
    the guardrail's tool schema requires naming the MCP server, and the only place that knows is
    whatever registered the tool.
    """

    name: str
    description: str
    parameters: dict[str, Any]
    server: str = ""

    def as_wire(self) -> dict[str, Any]:
        return {"type": "function",
                "function": {"name": self.name,
                             "description": self.description,
                             "parameters": self.parameters}}


@dataclass(frozen=True)
class ToolInvocation:
    """A tool the model asked for, as it came back."""

    call_id: str
    name: str
    arguments: str      # JSON text, exactly as emitted


@dataclass(frozen=True)
class Message:
    """One entry of the conversation.

    `tool_calls` is a sibling of `content` rather than nested inside it, because that is where the
    wire format puts it — and that placement is the reason a text-extracting guardrail never sees
    tool calls. Keeping the shape honest here is what lets the rest of the codebase reason about
    that gap instead of being surprised by it.
    """

    role: Role
    content: str | None = None
    tool_calls: tuple[ToolInvocation, ...] = ()
    tool_call_id: str = ""      # only on Role.TOOL

    def as_wire(self) -> dict[str, Any]:
        out: dict[str, Any] = {"role": self.role.value, "content": self.content}
        if self.tool_calls:
            out["tool_calls"] = [
                {"id": c.call_id, "type": "function",
                 "function": {"name": c.name, "arguments": c.arguments}}
                for c in self.tool_calls]
        if self.role is Role.TOOL:
            out["tool_call_id"] = self.tool_call_id
            # A tool result must be a string. Providers reject null here, and the failure surfaces
            # far from the cause.
            out["content"] = self.content or ""
        elif self.content is None and not self.tool_calls:
            # content=None is only legal alongside tool_calls.
            out["content"] = ""
        return out


@dataclass(frozen=True)
class Completion:
    """What came back, and enough of how it came back to explain a failure.

    `raw` is the provider's document, kept because the inline guardrail reads its `hook_results`
    and because a field the vendor adds tomorrow should reach the console without a change here.
    """

    ok: bool
    text: str = ""
    tool_calls: tuple[ToolInvocation, ...] = ()
    finish_reason: str = ""
    usage: dict[str, Any] = field(default_factory=dict)

    status: int = 0
    latency_ms: int = 0
    model: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    code: str = ""      # BLOCKED | UNREACHABLE | UPSTREAM_ERROR | BAD_RESPONSE | ""
    error: str = ""

    @property
    def wants_tools(self) -> bool:
        """True when the model asked to run something. The agent loop's continue condition."""
        return bool(self.tool_calls)


class LlmTransport(Protocol):
    """Serves one completion. Knows nothing about guardrails."""

    def complete(self, model: str, messages: Sequence[Message], *,
                 tools: Sequence[ToolSpec] = (), tool_choice: str = "auto",
                 max_tokens: int = 0, trace_id: str = "") -> Completion:
        ...

    @property
    def describes(self) -> str:
        """A short line for the startup log: where turns actually go."""
        ...


def build_body(model: str, messages: Sequence[Message], *,
               tools: Sequence[ToolSpec], tool_choice: str,
               token_param: str, max_tokens: int) -> dict[str, Any]:
    """The request body both transports send.

    `token_param` is a per-model fact rather than a constant: the gpt-5 generation rejects
    `max_tokens` outright and wants `max_completion_tokens`, while gpt-4o and Gemini take the old
    name. The catalog carries which, so a model that flips is a config edit.
    """
    body: dict[str, Any] = {
        "model": model,
        "messages": [m.as_wire() for m in messages],
        "stream": False,
        token_param: max_tokens,
    }
    if tools:
        body["tools"] = [t.as_wire() for t in tools]
        body["tool_choice"] = tool_choice
    return body


def parse_choice(doc: dict[str, Any]) -> tuple[str, tuple[ToolInvocation, ...], str]:
    """→ (text, tool calls, finish reason) from a completion document."""
    choices = doc.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return "", (), ""

    choice = choices[0]
    message = choice.get("message")
    if not isinstance(message, dict):
        return "", (), str(choice.get("finish_reason", ""))

    text = message.get("content")
    calls = []
    for raw in message.get("tool_calls") or []:
        if not isinstance(raw, dict):
            continue
        fn = raw.get("function") or {}
        calls.append(ToolInvocation(call_id=str(raw.get("id", "")),
                                    name=str(fn.get("name", "")),
                                    arguments=str(fn.get("arguments", "") or "{}")))
    return (text if isinstance(text, str) else ""), tuple(calls), str(choice.get("finish_reason", ""))
