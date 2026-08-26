"""Chat and the model catalog.

Chat() runs one turn through the AIRS gateway and streams the reply back to mgmtd. The reply
text is re-streamed word by word so the console can render it as it arrives; the final chunk
carries the complete turn document (reply, the AIRS scan verdict, usage, ok/code) as JSON,
which mgmtd files verbatim.

Why re-stream a completed answer rather than stream tokens from the model: the gateway call is
non-streaming on purpose. The AIRS response-side guardrail has to see the whole answer to rule
on it, so streaming raw tokens straight through would either skip that scan or buffer for it
anyway. Scanning the finished answer and then re-streaming it is the honest compromise.
"""

import json
import logging

from src.grpc import pretzel_ai_pb2

log = logging.getLogger("pretzel-ai")


# How the completed reply is sliced into deltas for the console. Whitespace-preserving so the
# reassembled text is byte-identical to result_json["reply"].
def _chunks(text):
    token = ""
    for ch in text:
        token += ch
        if ch.isspace():
            yield token
            token = ""
    if token:
        yield token

def _dump_value(v):
    """Values are capped; fields are not. The cut is marked so a truncated value is never read
    as the whole of it.

    Sized in UTF-8 BYTES, not code points, because the other end of this comparison is C++ and
    std::string::size() counts bytes. "한번더" is 3 characters and 9 bytes; two dumps that
    disagreed on which number to print would look like a transport bug on every Korean turn.
    """
    if not v:
        return '"" (empty)'
    n = len(v.encode("utf-8"))
    body = v[:_DUMP_CAP] + '" \u2026truncated' if n > _DUMP_CAP else v + '"'
    return f'({n} bytes) "{body}'

def dump_chat_request(request):
    lines = ["", "  \u250c\u2500 ChatRequest \u2190 mgmtd " + "\u2500" * 42]
    for name in ("model", "message", "system_prompt", "session_id", "transaction_id"):
        lines.append(f"  \u2502 {name:<15} {_dump_value(getattr(request, name))}")
    lines.append(f"  \u2502 history         {len(request.history)} turn(s)")
    for i, t in enumerate(request.history):
        lines.append(f"  \u2502   [{i}] role    {_dump_value(t.role)}")
        lines.append(f"  \u2502       content {_dump_value(t.content)}")
    lines.append("  \u2514" + "\u2500" * 68)
    return "\n".join(lines)

class ChatHandlers:
    """Chat + ListModels.

    A mixin: PretzelAiServicer composes it with the generated base. Kept out of the
    servicer because these methods change when this domain's contract does, and
    nothing else in the service has a reason to move with them.
    """

    def Chat(self, request, context):
        log.info(
            "Chat turn from %s: model=%s system_prompt=%s message_chars=%d history=%d "
            "session=%s txn=%s",
            context.peer(),
            request.model or "(default)",
            "set" if request.system_prompt else "none",
            len(request.message),
            len(request.history),
            request.session_id or "(none)",
            request.transaction_id or "(none)",
        )

        # DEBUG on purpose, and it stays there: `message` and `history` are whatever a person
        # typed, and the INFO line above deliberately reports only their sizes. Reading this is a
        # decision to read employee text, so it takes a decision to switch on.
        log.debug("%s", dump_chat_request(request))

        history = [{"role": t.role, "content": t.content} for t in request.history]
        result = self._gateway.complete_turn(
            request.model, request.message, request.system_prompt or None,
            history, request.session_id, request.transaction_id)

        # Stream the reply text (only present on a successful turn) so the console fills in as it
        # arrives; a failed turn streams nothing and carries its reason on the final chunk.
        if result.get("ok") and isinstance(result.get("reply"), str):
            for piece in _chunks(result["reply"]):
                yield pretzel_ai_pb2.ChatChunk(delta=piece, done=False)

        yield pretzel_ai_pb2.ChatChunk(
            done=True,
            error="" if result.get("ok") else result.get("error", ""),
            result_json=json.dumps(result, ensure_ascii=False),
        )

    def ListModels(self, request, context):
        """The picker's catalog. Unary and cheap — it is read once per page load."""
        try:
            models = self._gateway.catalog()
        except Exception as exc:                    # noqa: BLE001 - reported to the console
            log.exception("ListModels failed")
            return pretzel_ai_pb2.ModelList(error=str(exc))

        log.debug("ListModels from %s: %d models", context.peer(), len(models))
        return pretzel_ai_pb2.ModelList(
            models=[pretzel_ai_pb2.Model(**m) for m in models],
            default_model=self._gateway.default_model)
