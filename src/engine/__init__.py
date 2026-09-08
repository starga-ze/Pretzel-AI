"""What a turn is, and what the engine that runs one is built on.

    chat.py    one model call, and that is the turn.

What is shared is here: the identity of a turn, what a finished turn looks like, and the
assembly an engine does before it can call anything. It is a base class with one subclass
today, kept apart from it because a turn's identity and result are read by callers that never
touch an engine - the console adapter and the benchmark both do.

There is no agent engine and no tool vocabulary. There was a hand-rolled loop here that
offered a model tools, scanned each call, ran them and fed the results back, and it never ran
a single one - the runtime was always empty. An agent loop is a thing to build on a framework
that already has one (LangGraph is the intended home), not to maintain half-written beside a
chat turn, and the scaffolding was costing more to keep honest than it was worth.

    ---------------------------------------------------------------------------------
    CURRENTLY: turns are served and nothing inspects them.

    completion/ serves the model call, so a turn runs end to end. No guardrail is built,
    so `self.guardrail` is None and every checkpoint below is commented out where it
    belongs rather than deleted.

    A reader must not take an uninspected turn as an allowed one. `TurnResult.verdicts`
    comes back empty, and empty means nothing looked - a different answer from "something
    looked and cleared it", and the distinction is what the checkpoints exist for.
    ---------------------------------------------------------------------------------
"""

from __future__ import annotations

import enum
import logging
import secrets
from dataclasses import dataclass, field
from typing import Any, Sequence

from src.completion import Completion, Message, Role
from src.deployment.catalog import Catalog

log = logging.getLogger("pretzel-ai.engine")

def new_transaction_id() -> str:
    """A transaction id for a turn that arrived without one.

    There used to be a third id here - `tr_id`, minted per turn beside the transaction id - and it
    did nothing. Two measurements retired it:

      * 2026-08-26: the scan API has TWO id slots, not three. It treats `tr_id` and `session_id`
        as one field under two names - send both and session_id wins - and only `transaction_id`
        is independent. Every console turn carries a session, so tr_id was discarded by the
        service on every call and correlated nothing outside this daemon's own log.
      * The same day it was moved out of the agent loop to one per TURN, which is exactly the
        grain `transaction_id` already had. Two fields, one meaning.

    So the appliance fills the transaction id when nobody else did rather than inventing a
    parallel one. The `tr_` prefix is kept and is deliberate: mgmtd mints `txn_*`, this mints
    `tr_*`, and a scan report says at a glance which end named the turn.
    """
    return "tr_" + secrets.token_hex(8)


class Checkpoint(enum.Enum):
    """The four points in a turn where something can be looked at.

    Values match the wire: deployment/config.py's POINT_* and the proto's Checkpoints message use
    these exact strings, so `service.active_points()` is compared against them without a
    translation in between. A second spelling here would be a second thing to keep in step.

    Not to be confused with a verdict's DIRECTION, which the guardrail vocabulary spells
    tool_input / tool_output. That says which way content was flowing when a finding was made;
    this says where in the turn the appliance stopped to look.
    """

    PROMPT = "prompt"           # before the model is called
    RESPONSE = "response"       # after it answers, before anyone sees it
    TOOL_CALL = "tool_call"     # after the model asks for a tool, BEFORE it runs
    TOOL_RESULT = "tool_result"  # after the tool ran, before its output re-enters the turn


@dataclass
class Turn:
    """Who this turn belongs to, and what the appliance traces it by.

    Handed in by the caller, except that the engine fills what the caller could not know: the
    resolved model, and a transaction id when none arrived. Both are filled in _open, before
    anything is sent, so every scan and every log line a turn produces carries the same pair.
    """

    session_id: str = ""
    transaction_id: str = ""
    app_user: str = ""
    model: str = ""


@dataclass
class TurnResult:
    """Everything the console needs, whatever happened."""

    ok: bool
    reply: str = ""
    code: str = ""
    error: str = ""

    model: str = ""
    session_id: str = ""
    transaction_id: str = ""

    # Every inspection this turn produced, in order. Empty while no guardrail is built - an
    # empty list means nothing looked, never that something looked and cleared it.
    verdicts: list = field(default_factory=list)

    usage: dict[str, Any] = field(default_factory=dict)
    latency_ms: int = 0
    status: int = 0
    raw: dict[str, Any] = field(default_factory=dict)


class Engine:
    """What an engine is, under whichever turn it runs.

    The transport and the guardrail are constructor arguments and nothing here knows which
    implementation it got. That is what makes the deployment a configuration rather than a
    branch - and `catalog` is separate from the rest for the same reason at a different
    scale: which models exist is a fact about the appliance, while everything below it is
    one service's settings and arrives per service from mgmtd.
    """

    def __init__(self, transport, guardrail, catalog: Catalog, *,
                 system_prompt: str = "", max_tokens: int = 4096,
                 fail_open: bool = False) -> None:
        # Two collaborators, not one holding the other. One decision picked them - see
        # deployment/guardrail.py - but running a turn calls them separately and at points this
        # engine chooses, so it holds them separately.
        self.transport = transport

        # None when nothing inspects. Not an absence to read as permission: it means no verdict
        # exists, which is a different answer from a verdict that allowed the turn.
        self.guardrail = guardrail

        # Appliance-wide: both services see the same models.
        self.catalog = catalog

        # This service's, and this service's only. mgmtd sends each service its own document.
        self.system_prompt = system_prompt
        self.max_tokens = max_tokens
        self.fail_open = fail_open

    # -- what a caller may ask ------------------------------------------------------------

    @property
    def describes(self) -> str:
        """One line for the startup log: what this service actually is.

        Both halves report "none" rather than being omitted. An operator reading this line
        has to be able to see that nothing serves and nothing inspects - a line that simply
        left them out would read like a healthy service.
        """
        line = f"transport={_names(self.transport)} · guardrail={_names(self.guardrail)}"

        if self.fail_open:
            line += " · fail-open"

        return line

    def run(self, message: str, *, model: str = "", system_prompt: str | None = None,
            history: Sequence[Message] = (), turn: Turn | None = None) -> TurnResult:
        raise NotImplementedError

    # -- what both do before they can call anything --------------------------------------

    def _open(self, message: str, model: str, turn: Turn | None):
        """Validate, resolve the model, and make sure the turn is named.

        Returns (message, turn, result) with `result.ok` already False, or (None, None,
        result) when the turn is over before it started. Both engines begin here so a bad
        request is refused the same way whichever one was asked.
        """
        message = (message or "").strip()
        if not message:
            return None, None, TurnResult(ok=False, code="BAD_REQUEST",
                                          error="message is required")

        model_id, error = self.catalog.resolve(model)
        if error:
            return None, None, TurnResult(ok=False, code="BAD_REQUEST", error=error)

        if turn is None:
            # No caller identity at all - a probe, or a test. The turn still runs; only its
            # tracing is thin.
            turn = Turn()

        turn.model = model_id
        if not turn.transaction_id:
            turn.transaction_id = new_transaction_id()

        result = TurnResult(ok=False, model=model_id, session_id=turn.session_id,
                            transaction_id=turn.transaction_id)
        return message, turn, result

    def _opening_messages(self, message: str, system_prompt: str | None,
                          history: Sequence[Message]) -> list[Message]:
        """System prompt, then the conversation so far, then this turn.

        `system_prompt` is None when the caller did not override this service's own, and "" when
        it deliberately asked for none - so the two are not the same request and are not folded
        together here.

        History goes in as its own messages rather than folded into the system prompt or into
        the message. Where a guardrail's scan scope is narrow, anything appended to the system
        prompt is never scanned at all - so "put the context in the system prompt" is the one
        arrangement that hides it from the control.
        """
        # None means the caller did not ask about the system prompt at all, so this service's own
        # stands. Any string - "" included - is the caller answering, and the answer is used.
        if system_prompt is None:
            prompt = self.system_prompt
        else:
            prompt = system_prompt

        messages: list[Message] = []

        # An empty prompt gets no SYSTEM message. Sending one with no content spends a message
        # telling the model nothing.
        if prompt:
            messages.append(Message(role=Role.SYSTEM, content=prompt))

        for earlier in history:
            messages.append(earlier)

        messages.append(Message(role=Role.USER, content=message))
        return messages

    def _accept(self, completion: Completion, result: TurnResult,
                latency: int) -> TurnResult | None:
        """What came back from the model, before anything is read out of it.

        Recording only. It reads no verdict and reaches no guardrail: a verdict that rides on the
        completion document - which is how an inline gateway hook delivers one - is that
        guardrail's business to find, and it is handed the completion at the RESPONSE checkpoint
        for exactly that. Two places pulling verdicts out of one turn is how a turn ends up
        reported as stopped by something nothing accounts for.

        `status` and `raw` are recorded before the ok check on purpose: a turn that FAILED is the
        one whose provider document somebody will want to read.

        Returns the finished TurnResult when the turn ends here, or None to carry on.
        """
        result.status = completion.status
        result.raw = completion.raw

        if completion.ok:
            if completion.usage:
                result.usage = completion.usage
            return None

        result.code = completion.code
        result.error = completion.error
        result.latency_ms = latency
        if completion.usage:
            result.usage = completion.usage
        return result

    def _answer(self, result: TurnResult, completion: Completion, latency: int) -> TurnResult:
        """Everything passed. This is the turn."""
        result.ok = True
        result.reply = completion.text
        result.latency_ms = latency
        return result

    # -- the checkpoints ------------------------------------------------------------------
    #
    # The enforcement rules live with the engine rather than with the guardrails on purpose:
    # everything else in the appliance either produces a verdict or serves a completion, and this
    # is the only thing that acts on either.
    #
    #   1. Nothing leaves before the prompt scan returns. On the direct transport the appliance is
    #      the only thing between the operator's words and a third-party model, and scanning after
    #      the call would mean the data has already left the building.
    #   2. Nothing reaches the operator before the response scan returns. This is what makes token
    #      streaming impossible on a guarded path - you cannot stream a token and then decide to
    #      block it - and why the handler re-streams a finished answer.
    #   3. A tool is scanned BEFORE it runs, never after. The other two are recoverable: a blocked
    #      prompt costs nothing, a blocked response costs a completion. A tool that already ran has
    #      changed something outside this process.
    #   4. NOT_INSPECTED does not pass. `fail_open` exists for the deployment that genuinely wants
    #      the other behaviour, and it has to be said out loud in config.

    def _inspect(self, checkpoint: Checkpoint, turn: Turn, result: TurnResult, latency: int,
                 **content) -> TurnResult | None:
        """One checkpoint, whichever of the four it is. → the TurnResult that ends the turn, or
        None to carry on.

        ONE method rather than four, because the engine's part is identical at every point: ask,
        record, decide whether the turn survives. What differs is only what is being looked at,
        and that travels in `content` - so chat calls it twice and an agent loop calls it four
        times, without either one owning a copy of these rules.

        The guardrail decides HOW it reaches a verdict. Calling the scan API and reading one off
        the completion document an inline gateway hook already annotated are the same question
        asked of two implementations, which is why RESPONSE is handed the whole completion rather
        than just its text.
        """
        if self.guardrail is None:
            # Nothing to ask. Not a pass: no verdict exists, and TurnResult.verdicts stays empty,
            # which the console draws as "uninspected".
            return None

        verdict = self.guardrail.inspect(checkpoint, turn, **content)

        # A "nothing inspects this by design" verdict is not a finding. Recording one per
        # checkpoint would bury the verdicts that are.
        if not getattr(verdict, "by_design", False):
            result.verdicts.append(verdict)

        if self._passes(verdict):
            return None

        return self._stopped(result, verdict, latency)

    def _passes(self, verdict) -> bool:
        """Whether the turn may continue past this verdict.

        Three ways through, and they are not the same decision:

        * The guardrail permitted it. Ordinary.
        * Nothing inspects this checkpoint BY DESIGN. The deployment says so, and stopping would
          be the appliance refusing the configuration it was given.
        * Nothing inspected it and something should have. Stops, unless `fail_open` is on - and
          that is the only place in the appliance where a turn proceeds uninspected by accident
          rather than by declaration.
        """
        if getattr(verdict, "permits", False):
            return True

        # Read as a wire word rather than through the Decision enum, the way console.py reads a
        # verdict: this file must keep working while guardrail/ is out of the tree.
        if _value(getattr(verdict, "decision", "")) != "not_inspected":
            return False

        if getattr(verdict, "by_design", False):
            return True

        if self.fail_open:
            log.warning("guardrail did not inspect the %s (%s) - fail-open is on, proceeding",
                        _value(getattr(verdict, "direction", "turn")),
                        getattr(verdict, "error", "") or "no reason given")
            return True

        return False

    def _stopped(self, result: TurnResult, verdict, latency_ms: int) -> TurnResult:
        """The turn a checkpoint ended. Two codes, because they are two different events."""
        result.latency_ms = latency_ms
        direction = _value(getattr(verdict, "direction", "turn"))

        if _value(getattr(verdict, "decision", "")) == "not_inspected":
            result.code = "NOT_INSPECTED"
            result.error = (getattr(verdict, "error", "")
                            or f"nothing inspected the {direction} of this turn")
        else:
            result.code = "BLOCKED"
            hits = ", ".join(getattr(verdict, "hits", ())) or "the guardrail"
            threats = ", ".join(getattr(verdict, "threats", ()))
            result.error = f"blocked on the {direction}: {hits}"
            if threats:
                result.error += f" ({threats})"

        log.info("turn stopped: code=%s direction=%s scan_id=%s",
                 result.code, direction, getattr(verdict, "scan_id", "") or "-")
        return result


def _value(member) -> str:
    """An enum member's value, or whatever it already was.

    The guardrail vocabulary - Decision, Direction - is out of the tree, so a verdict's fields
    arrive as whatever the implementation put there. Reading the wire word works for both the
    enum this file cannot import and the plain string that stands in for it.
    """
    return getattr(member, "value", member)


def _names(part) -> str:
    """How a transport or an inspector names itself in the startup log.

    Three answers, and they are different: the part is absent, or it describes itself, or it does
    not and its class name is the best available. CheckpointGate describes itself because the
    class name alone would say a gate is deployed without saying which of the four points it lets
    through, and that is the one fact a reader of this line needs.
    """
    if part is None:
        return "none"

    own_words = getattr(part, "describes", "")
    if own_words:
        return own_words

    return type(part).__name__
