"""One turn, start to finish — and the order the checkpoints happen in.

This is where a verdict becomes a decision. Everything else in the appliance either produces a
verdict (src/guardrail.py and its implementations) or serves a completion (src/llm/); this file
is the only thing that acts on either, which is why the enforcement rules live here and nowhere
else.

The rules, and why each one
---------------------------
1. Nothing leaves before the prompt scan returns. On the direct path the appliance is the only
   thing standing between the operator's words and a third-party model, and scanning after the
   call would mean the data has already left the building.

2. Nothing reaches the operator before the response scan returns. This is what makes token
   streaming impossible on a guarded path — you cannot stream a token and then decide to block
   it — and it is why Chat re-streams a finished answer instead of proxying one.

3. A tool is scanned BEFORE it runs, never after. The other two checkpoints are recoverable: a
   blocked prompt costs nothing, a blocked response costs a completion. A tool that already ran
   has changed something outside this process.

4. NOT_INSPECTED does not pass. An out-of-band guardrail returns a verdict, not a refusal — the
   content is already in this process, and letting it through because nothing said no is the
   failure this codebase keeps finding in other people's deployments. `fail_open` exists for the
   deployment that genuinely wants the other behaviour, and it has to be said out loud in config.

What is NOT here
----------------
Whether a tool is *allowed* to run. `update_firewall_policy(rule_id="ALL", action="allow")`
contains nothing a scanner can object to; it is dangerous because of what it does, not what it
says. That is an authorization question and belongs to a tool registry — a separate concern with
a separate failure mode, and folding it in here would make both harder to reason about.
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

from src.airs.gateway import GatewayGuardrail
from src.guardrail import Decision, Direction, Guardrail, ToolCall, Turn, Verdict
from src.llm.catalog import Catalog
from src.llm.transport import (
    Completion, LlmTransport, Message, Role, ToolInvocation, ToolSpec,
)

log = logging.getLogger("pretzel-ai.chat")

# How many times the loop will let the model call tools before giving up. Not a safety control —
# the guardrail and the tool registry are — but a bill and a latency ceiling.
DEFAULT_MAX_ITERATIONS = 8

# Used only to read a verdict off a completion the gateway refused, for deployments whose own
# guardrail is not the one that refused it. Stateless, so one instance serves every engine.
_GATEWAY_READER = GatewayGuardrail(require_guardrail=False)


def new_tr_id() -> str:
    """One turn, and every scan it produces.

    Minted per turn rather than per model call, which is a correction rather than a preference.
    Measured 2026-08-26: the scan API has two id slots, not three — it treats `tr_id` and
    `session_id` as one field under two names (send both and session_id wins; send only tr_id and
    it is copied into session_id), and only `transaction_id` is independent. A per-round-trip
    tr_id was therefore discarded by the service on every call that carried a session, so it
    correlated nothing anywhere but in our own log. One per turn is what the appliance can
    actually mean, and it agrees with the transaction_id the same scans carry.
    """
    return "tr_" + secrets.token_hex(8)


@dataclass
class ToolRuntime:
    """Runs a tool the model asked for, and knows which server it belongs to.

    Injected rather than implemented here: today nothing is wired up and Chat never sees a tool
    call, while the agent service will hold an MCP client. The engine's loop is written against
    this interface so the day that arrives is a constructor argument, not a rewrite.
    """

    specs: tuple[ToolSpec, ...] = ()
    invoke: Callable[[ToolInvocation], str] | None = None

    def server_for(self, name: str) -> str:
        """The MCP server behind a tool. Required by the guardrail's tool schema, and knowable
        only here — a completion names a function, never where it came from."""
        for spec in self.specs:
            if spec.name == name:
                return spec.server
        return ""


@dataclass
class TurnResult:
    """Everything the console needs, whatever happened.

    `verdicts` is every inspection this turn produced, in order. A turn that called two tools
    carries five: prompt, tool input, tool output, prompt again, response. Reporting only the last
    one would hide the checkpoint that actually fired.
    """

    ok: bool
    reply: str = ""
    code: str = ""
    error: str = ""

    model: str = ""
    session_id: str = ""
    transaction_id: str = ""
    tr_id: str = ""

    verdicts: list[Verdict] = field(default_factory=list)
    usage: dict[str, Any] = field(default_factory=dict)
    latency_ms: int = 0
    iterations: int = 1
    status: int = 0
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def blocking_verdict(self) -> Verdict | None:
        """The inspection that stopped this turn, if one did."""
        for verdict in self.verdicts:
            if not verdict.permits:
                return verdict
        return None


class ChatEngine:
    """Runs turns: scan, call, scan, and — when tools are wired up — loop.

    The guardrail and the transport are constructor arguments and nothing here knows which
    implementation it got. That is what makes the deployment matrix a configuration rather than a
    branch: gateway or direct on one axis, AIRS or inline or nothing on the other.
    """

    def __init__(self, transport: LlmTransport, guardrail: Guardrail, catalog: Catalog, *,
                 system_prompt: str = "", max_tokens: int = 4096,
                 max_iterations: int = DEFAULT_MAX_ITERATIONS,
                 fail_open: bool = False,
                 tools: ToolRuntime | None = None) -> None:
        self._transport = transport
        self._guardrail = guardrail
        self._catalog = catalog
        self._system_prompt = system_prompt
        self._max_tokens = max_tokens
        self._max_iterations = max(1, max_iterations)
        self._fail_open = fail_open
        self._tools = tools or ToolRuntime()
        # Said once per process, not once per turn: whether the gateway is ALSO scanning is a fact
        # about the deployment, and repeating it on every turn would bury the turns.
        self._warned_double_scan = False

    @property
    def catalog(self) -> Catalog:
        return self._catalog

    @property
    def guardrail(self) -> Guardrail:
        """For callers that need a checkpoint without a turn — the benchmark scanning a prompt
        the model never has to answer. Not a hook for policy: `run` remains the only thing that
        decides what a verdict means."""
        return self._guardrail

    @property
    def describes(self) -> str:
        return (f"{self._transport.describes} · guardrail="
                f"{type(self._guardrail).__name__}"
                f"{' · fail-open' if self._fail_open else ''}")

    # ── One turn ─────────────────────────────────────────────────────────────────────────

    def run(self, message: str, *, model: str = "", system_prompt: str | None = None,
            history: Sequence[Message] = (), turn: Turn | None = None) -> TurnResult:
        """Scan, call, scan — looping while the model asks for tools."""
        message = (message or "").strip()
        if not message:
            return TurnResult(ok=False, code="BAD_REQUEST", error="message is required")

        model_id, error = self._catalog.resolve(model)
        if error:
            return TurnResult(ok=False, code="BAD_REQUEST", error=error)

        turn = turn or Turn()
        turn.model = model_id
        result = TurnResult(ok=False, model=model_id, session_id=turn.session_id,
                            transaction_id=turn.transaction_id)

        messages = self._opening_messages(message, system_prompt, history)
        total_latency = 0

        # One id for the whole turn, minted before the loop rather than inside it. Every scan this
        # turn produces — the prompt, each tool call, each tool result, the response — carries it,
        # so a turn that called three tools is one thing in the log and one thing in the scan
        # service's console rather than several unrelated ones. See new_tr_id.
        turn.tr_id = new_tr_id()
        result.tr_id = turn.tr_id

        for iteration in range(1, self._max_iterations + 1):
            result.iterations = iteration

            # ── 1. Before the model sees it ──
            prompt_verdict = self._guardrail.inspect_prompt(turn, message)
            # A "nothing inspects this by design" verdict is not a finding; recording one per
            # iteration would bury the verdicts that are.
            if not prompt_verdict.by_design:
                result.verdicts.append(prompt_verdict)
            if not self._passes(prompt_verdict):
                return self._stopped(result, prompt_verdict, total_latency)

            # ── 2. The call ──
            completion = self._transport.complete(
                model_id, messages, tools=self._tools.specs,
                max_tokens=self._max_tokens, trace_id=turn.session_id or turn.tr_id)
            total_latency += completion.latency_ms
            result.status = completion.status
            result.raw = completion.raw

            # An inline guardrail's verdict rides on this document rather than being asked for.
            inline = self._read_inline(completion)
            if inline is not None:
                result.verdicts.append(inline)

            if not completion.ok:
                # A gateway can refuse a turn even when this appliance inspects nothing: the
                # plugin over there is not ours to switch off, and `route.guardrail='none'` says
                # what WE do, never what it does. Recording the block with no verdict beside it
                # would leave the console showing a stop that nothing accounts for.
                if completion.code == "BLOCKED" and not result.verdicts:
                    result.verdicts.append(self._gateway_block_verdict(completion))
                result.code = completion.code
                result.error = completion.error
                result.latency_ms = total_latency
                if completion.usage:
                    result.usage = completion.usage
                return result

            if completion.usage:
                result.usage = completion.usage

            # ── 3. Tools, if the model asked ──
            if completion.wants_tools:
                if self._tools.invoke is None:
                    # Nothing is wired up to run them. Reported rather than ignored: a turn that
                    # ended because the appliance cannot do what the model asked is not a turn
                    # that answered.
                    result.code = "TOOLS_UNAVAILABLE"
                    result.error = ("the model asked for a tool and no tool runtime is "
                                    "configured on this appliance")
                    result.latency_ms = total_latency
                    return result

                messages = list(messages) + [_assistant_turn(completion)]
                stopped = self._run_tools(turn, completion.tool_calls, messages, result)
                if stopped is not None:
                    return self._stopped(result, stopped, total_latency)
                continue        # back to the model with the tool results in hand

            # ── 4. Before anyone sees it ──
            response_verdict = self._guardrail.inspect_response(turn, message, completion.text)
            if not response_verdict.by_design:
                result.verdicts.append(response_verdict)
            if not self._passes(response_verdict):
                return self._stopped(result, response_verdict, total_latency)

            result.ok = True
            result.reply = completion.text
            result.latency_ms = total_latency
            return result

        result.code = "LOOP_LIMIT"
        result.error = f"the model kept asking for tools after {self._max_iterations} rounds"
        result.latency_ms = total_latency
        return result

    # ── Steps ────────────────────────────────────────────────────────────────────────────

    def _run_tools(self, turn: Turn, calls: Sequence[ToolInvocation],
                   messages: list[Message], result: TurnResult) -> Verdict | None:
        """Scan, run, scan — per call. Returns the verdict that stopped the turn, or None.

        Order is the point. Every call is inspected before ANY of them runs, because a batch the
        model asked for in one breath should not have half of it executed before the guardrail
        objects to the other half.
        """
        planned: list[tuple[ToolInvocation, ToolCall]] = []
        for invocation in calls:
            call = ToolCall(name=invocation.name, arguments=invocation.arguments,
                            call_id=invocation.call_id,
                            server=self._tools.server_for(invocation.name))
            verdict = self._guardrail.inspect_tool_call(turn, call)
            result.verdicts.append(verdict)
            if not self._passes(verdict):
                return verdict
            planned.append((invocation, call))

        for invocation, call in planned:
            try:
                output = self._tools.invoke(invocation)      # type: ignore[misc]
            except Exception as exc:                          # noqa: BLE001 - reported to the model
                # The model is told the tool failed rather than the turn being abandoned: an agent
                # that can see an error can try something else, and a turn that vanishes cannot.
                log.warning("tool %s raised: %s", invocation.name, exc)
                output = f'{{"error": {json_str(str(exc)[:200])}}}'

            verdict = self._guardrail.inspect_tool_result(turn, call, output)
            result.verdicts.append(verdict)
            if not self._passes(verdict):
                return verdict

            messages.append(Message(role=Role.TOOL, content=output,
                                    tool_call_id=invocation.call_id))
        return None

    def _opening_messages(self, message: str, system_prompt: str | None,
                          history: Sequence[Message]) -> list[Message]:
        """System prompt, then the conversation so far, then this turn.

        History goes in as its own messages rather than folded into the system prompt or into the
        message. Where a guardrail's scan scope is narrow, anything appended to the system prompt
        is never scanned at all — so "put the context in the system prompt" is the one arrangement
        that hides it from the control.
        """
        messages: list[Message] = []
        prompt = self._system_prompt if system_prompt is None else system_prompt
        if prompt:
            messages.append(Message(role=Role.SYSTEM, content=prompt))
        messages.extend(history)
        messages.append(Message(role=Role.USER, content=message))
        return messages

    def _gateway_block_verdict(self, completion: Completion) -> Verdict:
        """The gateway stopped this turn and this appliance was not the one asking.

        Read out of the completion rather than invented, so the scan id and the detectors are the
        gateway's own and an operator can find the scan in the vendor's console.
        """
        verdict = _GATEWAY_READER.read(completion.raw, Direction.RESPONSE)
        if verdict.inspected:
            return verdict
        return Verdict(decision=Decision.BLOCK, direction=Direction.RESPONSE,
                       inspected=True, enforced=True,
                       error=completion.error or "the gateway denied this turn")

    def _read_inline(self, completion: Completion) -> Verdict | None:
        """A verdict the transport's gateway already reached, if this guardrail reads them.

        Also the one place double scanning becomes visible. Whether a gateway inspects anything is
        configured in the GATEWAY's console, not here — so an appliance set to scan directly can
        find itself paying for two scans of the same content, one of which it then discards. That
        is a real cost and a real latency, and nothing else in the system is positioned to notice
        it: the config cannot say, and the gateway does not announce it.
        """
        reader = getattr(self._guardrail, "read", None)

        if reader is None:
            if not self._warned_double_scan and _carries_hook_results(completion.raw):
                self._warned_double_scan = True
                log.warning(
                    "the gateway is also running a guardrail on these turns, and this "
                    "appliance is scanning directly — every turn is being inspected twice. "
                    "Disable the plugin on the gateway config to keep the appliance's scan "
                    "(which also covers tool calls), or set route.guardrail='gateway' to keep "
                    "the gateway's")
            return None

        if not completion.raw:
            return None
        verdict = reader(completion.raw, Direction.RESPONSE)
        return verdict if verdict.inspected or verdict.errored else None

    def _passes(self, verdict: Verdict) -> bool:
        """Whether the turn may continue past this verdict.

        Three ways through, and they are not the same decision:

        * The guardrail permitted it. Ordinary.
        * Nothing inspects this checkpoint BY DESIGN. The deployment says so — no guardrail is
          configured, or an inline one reaches its verdict during the model call rather than
          before it — and stopping would be the appliance refusing the configuration it was given.
        * Nothing inspected it and something should have. Stops, unless `fail_open` is on, and
          that is the only place in the appliance where a turn proceeds uninspected by accident
          rather than by declaration.
        """
        if verdict.permits:
            return True
        if verdict.decision is not Decision.NOT_INSPECTED:
            return False
        if verdict.by_design:
            return True
        if self._fail_open:
            log.warning("guardrail did not inspect the %s (%s) — fail-open is on, proceeding",
                        verdict.direction.value, verdict.error or "no reason given")
            return True
        return False

    def _stopped(self, result: TurnResult, verdict: Verdict, latency_ms: int) -> TurnResult:
        result.latency_ms = latency_ms
        if verdict.decision is Decision.NOT_INSPECTED:
            result.code = "NOT_INSPECTED"
            result.error = (verdict.error
                            or f"nothing inspected the {verdict.direction.value} of this turn")
        else:
            result.code = "BLOCKED"
            hits = ", ".join(verdict.hits) or "the guardrail"
            threats = f" ({', '.join(verdict.threats)})" if verdict.threats else ""
            result.error = f"blocked on the {verdict.direction.value}: {hits}{threats}"
        log.info("turn stopped: code=%s direction=%s scan_id=%s",
                 result.code, verdict.direction.value, verdict.scan_id or "-")
        return result


def _carries_hook_results(doc: dict[str, Any]) -> bool:
    """Whether a completion came back with a gateway guardrail's verdict attached."""
    hooks = doc.get("hook_results") if isinstance(doc, dict) else None
    if not isinstance(hooks, dict):
        return False
    return any(hooks.get(key) for key in ("before_request_hooks", "after_request_hooks"))


def _assistant_turn(completion: Completion) -> Message:
    """The model's tool request, replayed back to it verbatim.

    Its own words, unedited: a provider validates that every tool_call_id it issued comes back
    answered, and rewriting the turn is how that check starts failing for reasons nobody can see.
    """
    return Message(role=Role.ASSISTANT, content=completion.text or None,
                   tool_calls=completion.tool_calls)


def json_str(text: str) -> str:
    """A JSON string literal, for building a tool-error payload without importing json here."""
    escaped = text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'"{escaped}"'
