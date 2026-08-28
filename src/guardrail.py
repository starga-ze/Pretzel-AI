"""What an inspection says, and who can say it — with no vendor in the vocabulary.

This module names the decision a guardrail reaches and the checkpoints it can be asked about.
Prisma AIRS implements it (src/airs/), and so does the Portkey gateway's inline hook, and so does
"nothing is inspecting this" — which is a real deployment and is written down here rather than
left as an absence, because a path with no guardrail should be as explicit in the code as one
with.

Two things are deliberately not here: how a verdict is obtained, and what is done about it.
Obtaining it belongs to an implementation; acting on it belongs to whoever owns the turn
(src/chat/engine.py). Keeping the three apart is what makes moving inspection between the
appliance and a gateway a matter of swapping one object.

The distinction the whole file exists for
----------------------------------------
A guardrail can fail two ways and they are not the same fact. It can rule against the content, or
it can never rule at all — the service errored, the call timed out, nothing was configured. Both
are "not allowed" to a boolean, and collapsing them is how a control that never ran gets reported
as one that ran and cleared. `Decision.NOT_INSPECTED` is that second case, kept separate on
purpose, and `Verdict.inspected` is the question to ask when the code needs to know which it has.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Protocol, Sequence


class Decision(enum.Enum):
    """The four states an inspection can end in.

    FLAGGED is the one a boolean hides: the guardrail found something and the content was
    forwarded anyway — an async check that cannot deny, or a profile configured to warn. Reporting
    that as ALLOW loses the finding; reporting it as BLOCK claims an enforcement that did not
    happen.
    """

    ALLOW = "allow"
    BLOCK = "block"
    FLAGGED = "flagged"
    NOT_INSPECTED = "not_inspected"

    @property
    def permits(self) -> bool:
        """True when the content may proceed.

        NOT_INSPECTED does NOT permit. That is a policy baked into the type: an appliance that
        cannot inspect should stop, and the alternative — proceeding because nothing said no —
        is the failure mode this codebase keeps finding in other people's guardrails. A caller
        that genuinely wants to proceed uninspected has to say so at the call site, where the
        decision is visible, rather than inherit it from a default here.
        """
        return self in (Decision.ALLOW, Decision.FLAGGED)


class Direction(enum.Enum):
    """Which leg of a turn was inspected. Not decoration: the same payload is benign in one
    direction and an attack in the other, and a report that does not say which is unreadable."""

    PROMPT = "prompt"
    RESPONSE = "response"
    CONTEXT = "context"      # retrieved material, before the model sees it
    TOOL_INPUT = "tool_input"
    TOOL_OUTPUT = "tool_output"


@dataclass(frozen=True)
class Detection:
    """One detector's finding. `hit` is carried even when false — "PII: none" is information, and
    a report that lists only hits can never say it."""

    id: str
    direction: Direction
    hit: bool


@dataclass(frozen=True)
class Masked:
    """Sensitive text the guardrail rewrote.

    `applied` is the fact that matters and the one most easily lost: a mask can be computed and
    NOT forwarded, which means the original went upstream. Two different outcomes, one field.
    """

    text: str
    patterns: tuple[str, ...] = ()
    applied: bool = False


@dataclass(frozen=True)
class Verdict:
    """One inspection, whatever happened to it."""

    decision: Decision
    direction: Direction

    # Whether an inspection actually took place. Distinct from the decision because
    # NOT_INSPECTED is reachable in more than one way, and because a caller that only wants to
    # know "did anything look at this" should not have to enumerate decisions to find out.
    inspected: bool = False

    # Enforcement, as opposed to opinion: the guardrail refused to pass the content on, rather
    # than reporting a finding and letting it through.
    enforced: bool = False

    detections: tuple[Detection, ...] = ()
    threats: tuple[str, ...] = ()          # named threats, e.g. "context poisoning"
    masked: Masked | None = None

    # Provenance. Everything an operator needs to find this exact scan in the vendor's console.
    scan_id: str = ""
    report_id: str = ""
    profile: str = ""
    profile_id: str = ""

    latency_ms: int = 0
    timed_out: bool = False
    errored: bool = False
    error: str = ""

    # Whether NOT_INSPECTED is the configuration or a failure. Both mean nothing looked at the
    # content and neither may be reported as a pass — but they are answered differently, and the
    # difference decides whether a turn stops. No guardrail is deployed on this checkpoint: that
    # is the operator's stated intent and the turn proceeds. A guardrail that was supposed to look
    # and could not: the turn stops, because proceeding would be the appliance deciding on its own
    # to run uninspected.
    by_design: bool = False

    @property
    def permits(self) -> bool:
        return self.decision.permits

    @property
    def hits(self) -> tuple[str, ...]:
        """Detector ids that actually fired, in a stable order."""
        return tuple(sorted({d.id for d in self.detections if d.hit}))

    @classmethod
    def not_inspected(cls, direction: Direction, reason: str = "") -> Verdict:
        """Nothing looked at this. The reason is carried because "no guardrail is configured" and
        "the guardrail errored" lead an operator to different places."""
        return cls(decision=Decision.NOT_INSPECTED, direction=direction,
                   inspected=False, errored=bool(reason), error=reason, by_design=False)

    @classmethod
    def uninspected_by_design(cls, direction: Direction) -> Verdict:
        """No guardrail is deployed on this path, and that is the configuration rather than a
        failure. Still NOT_INSPECTED — the content was not looked at, and the report must not
        imply otherwise — but with no error to chase."""
        return cls(decision=Decision.NOT_INSPECTED, direction=direction, inspected=False,
                   by_design=True)


@dataclass
class Turn:
    """The unit a guardrail is asked about, and the ids that let a scan be traced back.

    The three ids nest, coarsest first, and each is minted by whoever owns that unit:

        session_id      the conversation        the browser
        transaction_id  one operator request    mgmtd
        tr_id           one LLM round trip      this side, per iteration

    The last one is per round trip and not per request precisely because of the agent loop: one
    thing the operator asked for becomes several model calls, and a prompt scan has to be
    correlatable with the response scan of the same call and with no other.
    """

    session_id: str = ""
    transaction_id: str = ""
    tr_id: str = ""

    model: str = ""
    app_user: str = ""
    app_name: str = "pretzel-ai"


@dataclass(frozen=True)
class ToolCall:
    """A tool the model asked for, before it has been run.

    `server` and `ecosystem` are here because the guardrail's tool schema requires them and
    nothing downstream of the agent knows them: an LLM response names a function, not the MCP
    server it came from. Only the runtime holding the tool registry can say.
    """

    name: str
    arguments: str                  # JSON text, as the model emitted it
    call_id: str = ""
    server: str = ""
    ecosystem: str = "mcp"
    method: str = "tools/call"


class Guardrail(Protocol):
    """What every inspection point in the appliance talks to.

    One method per checkpoint rather than one `inspect(kind, payload)` because the checkpoints
    have different inputs and different consequences, and a single method would hide that behind
    a tagged union. An implementation that cannot serve a checkpoint returns NOT_INSPECTED for
    it — which is how the gateway's inline hook honestly reports that it never sees tool calls,
    instead of silently answering ALLOW.
    """

    def inspect_prompt(self, turn: Turn, prompt: str,
                       context: Sequence[str] = ()) -> Verdict:
        """Before the model is called. `context` is retrieved material (RAG), scanned as grounding
        rather than as the person's words."""
        ...

    def inspect_response(self, turn: Turn, prompt: str, response: str) -> Verdict:
        """After the model answers, before anyone sees it. The prompt goes along because a
        response is judged against what was asked."""
        ...

    def inspect_tool_call(self, turn: Turn, call: ToolCall) -> Verdict:
        """After the model asks for a tool, BEFORE it runs. The one checkpoint whose outcome is
        irreversible if skipped."""
        ...

    def inspect_tool_result(self, turn: Turn, call: ToolCall, output: str) -> Verdict:
        """After the tool ran, before its output re-enters the conversation. The classic indirect
        injection lands here."""
        ...


@dataclass
class NullGuardrail:
    """No inspection at all — a real deployment, written down.

    Customers run the appliance pointed straight at a model provider with nothing in between, and
    that shape needs a name in the code so the reports it produces say "nothing looked at this"
    rather than going quiet. Every method returns NOT_INSPECTED by design, never ALLOW.
    """

    def inspect_prompt(self, turn: Turn, prompt: str,
                       context: Sequence[str] = ()) -> Verdict:
        return Verdict.uninspected_by_design(Direction.PROMPT)

    def inspect_response(self, turn: Turn, prompt: str, response: str) -> Verdict:
        return Verdict.uninspected_by_design(Direction.RESPONSE)

    def inspect_tool_call(self, turn: Turn, call: ToolCall) -> Verdict:
        return Verdict.uninspected_by_design(Direction.TOOL_INPUT)

    def inspect_tool_result(self, turn: Turn, call: ToolCall, output: str) -> Verdict:
        return Verdict.uninspected_by_design(Direction.TOOL_OUTPUT)
