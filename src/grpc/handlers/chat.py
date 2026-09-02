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

from src.completion import Message, Role
from src.deployment.config import CHAT
from src.engine import Turn
from src.engine.console import to_document
from src.grpc import pretzel_ai_pb2

log = logging.getLogger("pretzel-ai")

# Values in the request dump are capped; fields never are. A 32 KiB turn would otherwise bury
# the surrounding log, and the cut is marked so a truncated value is never read as the whole.
_DUMP_CAP = 2048

# `message` is whatever a person typed and has no ceiling — a pasted log arrives here as easily as
# a sentence. Twenty bytes is enough to tell one turn from another in a log and not enough to be
# worth reading, which is the point: the size says how big it was, the console shows what it said.
_MESSAGE_CAP = 20

# What a turn gets when there is no engine to run it. Reached on a fresh install, before the
# appliance has pushed a deployment, and after a push that was refused left nothing behind — see
# src/deployment.py. Worded for the console, which shows it to whoever typed.
_UNCONFIGURED = ("no AI vendor is configured on this appliance — enable one and store its API key "
                 "in Configuration > AI Provider")


# How the completed reply is sliced into deltas for the console. Whitespace-preserving so the
# reassembled text is byte-identical to result_json["reply"].
def _chunks(text):
    token = ""
    for ch in text:
        token += ch
        # The break goes WITH the word it follows, so joining every chunk back together gives the
        # original string byte for byte. The console relies on that: what it renders has to equal
        # result_json["reply"].
        if ch.isspace():
            yield token
            token = ""

    # Whatever is left after the last space. A reply not ending in whitespace would otherwise lose
    # its final word.
    if token:
        yield token

def _dump_value(v, cap=_DUMP_CAP):
    """Values are capped; fields are not. The cut is marked so a truncated value is never read
    as the whole of it.

    Sized in UTF-8 BYTES, not code points, because the other end of this comparison is C++ and
    std::string::size() counts bytes. "한번더" is 3 characters and 9 bytes; two dumps that
    disagreed on which number to print would look like a transport bug on every Korean turn.
    """
    if not v:
        return '"" (empty)'

    raw = v.encode("utf-8")
    n = len(raw)

    if n <= cap:
        return f'({n} bytes) "{v}"'

    # Cut in BYTES and decoded loosely. The cap is a byte count, so slicing characters would
    # overshoot it threefold on Korean - and a cut landing mid-character decodes to nothing rather
    # than raising, which is what "ignore" is for.
    return f'({n} bytes) "{raw[:cap].decode("utf-8", "ignore")}\u2026"'


def _dump_size(v):
    """The size and nothing else, for a field whose length is what a reader needs.

    History is the whole conversation replayed on every turn, so a dump that printed it grew with
    the thread — one turn carrying six earlier ones buried the fields around it under thousands of
    bytes nobody was reading. What the reader is checking here is the SHAPE: how many turns
    arrived, in which order, and how big each is. The text is what the console already shows.
    """
    if not v:
        return '"" (empty)'
    return f'({len(v.encode("utf-8"))} bytes)'

def dump_chat_request(request):
    """The request as it arrived, by shape rather than by content.

    Titled for the path it came down rather than for the message type alone: what a reader is
    placing is which hop produced this, and "ChatRequest" on its own does not say.
    """
    lines = ["", "mgmtd -> grpc -> ChatRequest"]
    for name in ("model", "message", "system_prompt", "session_id", "transaction_id"):
        if name == "message":
            cap = _MESSAGE_CAP
        else:
            cap = _DUMP_CAP
        lines.append(f"  {name:<15} {_dump_value(getattr(request, name), cap)}")
    lines.append(f"  history         {len(request.history)} turn(s)")
    for i, t in enumerate(request.history):
        lines.append(f"    [{i}] role    {_dump_value(t.role)}")
        # Size only. Deliberately not _dump_value: see _dump_size.
        lines.append(f"        content {_dump_size(t.content)}")
    return "\n".join(lines)

class ChatHandlers:
    """Chat + ListModels.

    A mixin: PretzelAiServicer composes it with the generated base. Kept out of the
    servicer because these methods change when this domain's contract does, and
    nothing else in the service has a reason to move with them.
    """

    def Chat(self, request, context):
        # DEBUG on purpose, and it stays there: `message` and `history` are whatever a person
        # typed, and the INFO line above deliberately reports only their sizes. Reading this is a
        # decision to read employee text, so it takes a decision to switch on.
        log.debug("%s", dump_chat_request(request))

        # The conversation so far, as the engine's own type. Filtered rather than trusted: this is
        # the wire boundary, and what arrives here was assembled by a browser.
        history = []
        for entry in request.history:
            if entry.role not in ("user", "assistant"):
                continue

            if not entry.content:
                continue

            history.append(Message(role=Role(entry.role), content=entry.content))

        # The two ids the appliance traces a scan by, both of them minted elsewhere: the browser
        # names the conversation and mgmtd names the request. The engine fills `transaction_id`
        # only if it arrives empty — see engine.new_transaction_id for why there is no third id.
        turn = Turn(session_id=request.session_id,
                    transaction_id=request.transaction_id,
                    app_user=_peer_user(context))

        # Where this actually goes — gateway or straight to the provider, inspected by AIRS or by
        # the gateway's inline hook or by nothing — was decided once at startup, in
        # deployment.guardrail.build. This handler cannot tell and must not try: a branch here would be
        # a second place the deployment matrix is decided, and the two would drift.
        engine = self.get_engine(CHAT)
        if engine is None:
            yield pretzel_ai_pb2.ChatChunk(done=True, error=_UNCONFIGURED)
            return

        # proto3 cannot tell "not sent" from "sent empty", so an empty string is read as the
        # first: the caller said nothing about the system prompt and this service's own stands.
        # A caller that wants NO system prompt has to reach the engine another way - see
        # Engine._opening_messages, which treats None and "" as different answers.
        if request.system_prompt:
            system_prompt = request.system_prompt
        else:
            system_prompt = None

        result = engine.run(
            request.message,
            model=request.model,
            system_prompt=system_prompt,
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

        if result.ok:
            error = ""
        else:
            error = result.error

        yield pretzel_ai_pb2.ChatChunk(
            done=True,
            error=error,
            result_json=json.dumps(document, ensure_ascii=False),
        )

    def ListModels(self, request, context):
        """The picker's catalog. Unary and cheap — it is read once per page load."""
        engine = self.get_engine(CHAT)
        if engine is None:
            return pretzel_ai_pb2.ModelList(error=_UNCONFIGURED)

        try:
            catalog = engine.catalog
            models = catalog.as_list()
        except Exception as exc:                    # noqa: BLE001 - reported to the console
            log.exception("ListModels failed")
            return pretzel_ai_pb2.ModelList(error=str(exc))

        log.debug("ListModels from %s: %d models", context.peer(), len(models))
        listed = []
        for entry in models:
            listed.append(pretzel_ai_pb2.Model(**entry))

        return pretzel_ai_pb2.ModelList(models=listed, default_model=catalog.default)


def _peer_user(context) -> str:
    """Who to file this scan under.

    mgmtd does not forward the signed-in operator today, so the peer address is the closest thing
    to an identity available here. Named as its own function because the day mgmtd does send a
    username, this is the one line that changes — and until then the scan logs should say plainly
    that the appliance, not a person, is what they identified.
    """
    peer = context.peer()
    if peer:
        return peer
    return "pretzel-ai"
