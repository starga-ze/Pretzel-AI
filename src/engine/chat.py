"""One model call, and that is the turn.

There is no loop and nothing to loop over: the request offers the model no tools, so it has
nothing to ask for and no reason to be called twice.

    scan the prompt → call → scan the response → answer

All four steps are live. The two scans are no-ops while no guardrail is built - Engine._inspect
returns immediately when there is none - so the order is the code rather than a comment about it,
and an agent loop calls the same method twice more without owning a copy of the rules.
"""

from __future__ import annotations

import logging
from typing import Sequence

from src.completion import Message
from src.engine import Checkpoint, Engine, Turn, TurnResult

log = logging.getLogger("pretzel-ai.engine.chat")


class ChatEngine(Engine):
    """Runs a chat turn: one completion, start to finish."""

    def __init__(self, transport, guardrail, catalog, *, system_prompt: str = "",
                 max_tokens: int = 4096, fail_open: bool = False) -> None:
        """Spelled out rather than inherited, so what a chat engine takes is readable here."""
        super().__init__(transport, guardrail, catalog, system_prompt=system_prompt,
                         max_tokens=max_tokens, fail_open=fail_open)

    def run(self, message: str, *, model: str = "", system_prompt: str | None = None,
            history: Sequence[Message] = (), turn: Turn | None = None) -> TurnResult:
        message, turn, result = self._open(message, model, turn)
        if message is None:
            return result

        messages = self._opening_messages(message, system_prompt, history)

        stop = self._inspect(Checkpoint.PROMPT, turn, result, 0, prompt=message)
        if stop is not None:
            return stop

        completion = self.transport.complete(
            turn.model,             # resolved by _open; `model` is whatever the caller typed
            messages,
            max_tokens=self.max_tokens,
            trace_id=turn.session_id or turn.transaction_id,
        )
        latency = completion.latency_ms

        stop = self._accept(completion, result, latency)
        if stop is not None:
            return stop

        # The whole completion, not just its text: a gateway guardrail reads its verdict off the
        # document rather than asking for one, and cannot do that from the text alone.
        stop = self._inspect(Checkpoint.RESPONSE, turn, result, latency,
                             prompt=message, completion=completion)
        if stop is not None:
            return stop

        return self._answer(result, completion, latency)
