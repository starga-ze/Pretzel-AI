"""The OpenAI chat-completions shape: this vocabulary encoded, and decoded back.

Two functions and no state. They are apart from vendor.py because they change for a different
reason: this file moves when a provider changes the JSON it speaks, vendor.py moves when an
endpoint, a credential or a timeout changes.
"""

from __future__ import annotations

from typing import Any, Sequence

from src.completion import Message


def build_body(model: str, messages: Sequence[Message], *,
               token_param: str, max_tokens: int) -> dict[str, Any]:
    """The request body both transports send.

    `token_param` is a per-model fact rather than a constant: the gpt-5 generation rejects
    `max_tokens` outright and wants `max_completion_tokens`, while gpt-4o and Gemini take the old
    name. The catalog carries which, so a model that flips is a config edit.
    """
    return {
        "model": model,
        "messages": [m.as_wire() for m in messages],
        "stream": False,
        token_param: max_tokens,
    }


def parse_choice(doc: dict[str, Any]) -> tuple[str, str]:
    """→ (text, finish reason) from a completion document."""
    choices = doc.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return "", ""

    choice = choices[0]
    finish = str(choice.get("finish_reason", ""))

    message = choice.get("message")
    if not isinstance(message, dict):
        return "", finish

    text = message.get("content")
    return (text if isinstance(text, str) else ""), finish
