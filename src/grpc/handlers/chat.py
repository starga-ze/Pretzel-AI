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

from src.chat.console import to_document
from src.grpc import pretzel_ai_pb2
from src.guardrail import Turn
from src.llm.transport import Message, Role

log = logging.getLogger("pretzel-ai")

# Values in the request dump are capped; fields never are. A 32 KiB turn would otherwise bury
# the surrounding log, and the cut is marked so a truncated value is never read as the whole.
_DUMP_CAP = 2048


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

        # An unknown role is dropped rather than coerced to "user": a mislabelled assistant turn
        # replayed as the person's own words rewrites what the model believes it already said.
        history = [Message(role=Role(t.role), content=t.content)
                   for t in request.history
                   if t.role in ("user", "assistant") and t.content]

        # The three ids the appliance traces a scan by. tr_id is NOT set here — the engine mints
        # one per model call, and with tools there is more than one of those in a single request.
        turn = Turn(session_id=request.session_id,
                    transaction_id=request.transaction_id,
                    app_user=_peer_user(context))

        # Where this actually goes — gateway or straight to the provider, inspected by AIRS or by
        # the gateway's inline hook or by nothing — was decided once at startup, in
        # factory.build_engine. This handler cannot tell and must not try: a branch here would be
        # a second place the deployment matrix is decided, and the two would drift.
        result = self._engine.run(
            request.message,
            model=request.model,
            system_prompt=request.system_prompt or None,
            history=history,
            turn=turn)

        document = to_document(result)

        # Stream the reply text (only on a successful turn) so the console fills in as it arrives.
        # It is a FINISHED answer being re-streamed, not tokens proxied from the model: the
        # response-side checkpoint has to see the whole thing before any of it is shown, so there
        # is nothing to stream until there is everything.
        if result.ok and result.reply:
            for piece in _chunks(result.reply):
                yield pretzel_ai_pb2.ChatChunk(delta=piece, done=False)

        yield pretzel_ai_pb2.ChatChunk(
            done=True,
            error="" if result.ok else result.error,
            result_json=json.dumps(document, ensure_ascii=False),
        )

    def ListModels(self, request, context):
        """The picker's catalog. Unary and cheap — it is read once per page load."""
        try:
            catalog = self._engine.catalog
            models = catalog.as_list()
        except Exception as exc:                    # noqa: BLE001 - reported to the console
            log.exception("ListModels failed")
            return pretzel_ai_pb2.ModelList(error=str(exc))

        log.debug("ListModels from %s: %d models", context.peer(), len(models))
        return pretzel_ai_pb2.ModelList(
            models=[pretzel_ai_pb2.Model(**m) for m in models],
            default_model=catalog.default)


def _peer_user(context) -> str:
    """Who to file this scan under.

    mgmtd does not forward the signed-in operator today, so the peer address is the closest thing
    to an identity available here. Named as its own function because the day mgmtd does send a
    username, this is the one line that changes — and until then the scan logs should say plainly
    that the appliance, not a person, is what they identified.
    """
    return context.peer() or "pretzel-ai"
