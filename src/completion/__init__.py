"""What one model call looks like: the vocabulary, independent of who serves it.

    __init__.py   this file - Role, Message, Completion
    wire.py       the OpenAI chat-completions shape, encoded and decoded

Nothing in this package does I/O. It is what a model call IS; who makes one is transport/, and
the line between them is the socket - a reader chasing a timeout or a credential goes there.

Named for what the package produces, the way guardrail/ is named for the Verdict it produces
and engine/ for the TurnResult. What is in here is not "LLM utilities" - it is the two ends of
one exchange, and everything else in the appliance either builds one of these or reads one.

Every provider worth pointing at publishes an OpenAI-compatible chat-completions endpoint, so
that shape is the wire format here. It is a wire fact rather than a vendor preference: where a
real difference exists it is handled at the edge that knows about it, in vendor.py, and never
leaked into this vocabulary.

There is no tool vocabulary either. Nothing here offers a model a tool or reads one back: an
agent loop is a thing to be built on a framework that already has one, not hand-rolled beside a
chat turn, and the half of one that used to live here was scaffolding for a loop that never ran.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Role(enum.Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"


@dataclass(frozen=True)
class Message:
    """One entry of the conversation."""

    role: Role
    content: str | None = None

    def as_wire(self) -> dict[str, Any]:
        # Never null. A provider rejects a null content outright, and the failure surfaces far
        # from the cause.
        return {"role": self.role.value, "content": self.content or ""}


@dataclass(frozen=True)
class Completion:
    """What came back, and enough of how it came back to explain a failure.

    `raw` is the provider's document, kept because the inline guardrail reads its `hook_results`
    and because a field the vendor adds tomorrow should reach the console without a change here.
    """

    ok: bool
    text: str = ""
    finish_reason: str = ""
    usage: dict[str, Any] = field(default_factory=dict)

    status: int = 0
    latency_ms: int = 0
    model: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    code: str = ""      # BLOCKED | UNREACHABLE | UPSTREAM_ERROR | BAD_RESPONSE | ""
    error: str = ""
