"""Whatever the AI gateway is configured to do — reported faithfully.

This is the deferring guardrail. It makes no scan request and enforces no policy of its own; the
gateway calls AIRS on the appliance's behalf, folds the result into `hook_results` on the
completion, and this class reads it. Choosing it means saying "the gateway's configuration
governs this", which is a real answer and the one you want when the thing under test IS the
gateway.

That is also why the absence of a verdict is not automatically an error. Whether a gateway
inspects anything is decided in the gateway's own console, and an appliance that delegates has no
standing to insist. It reports `uninspected` and lets the turn through — visibly, on the console's
own verdict pill — unless the operator has said `require_guardrail`, at which point the claim is
theirs and its violation is theirs to hear about.

That difference is the whole reason both exist, and it is not a matter of taste:

  * Coverage. The gateway builds its scan request from a chat completion by extracting text
    `content` and concatenating it. `tool_calls` are a sibling of `content`, and `tools` is not in
    `messages` at all, so neither reaches the scanner. Measured on this appliance: the same
    injection blocks as a user message and passes inside a tool call.
  * Timing. The verdict is a by-product of the model call. There is no way to ask about a tool
    before running it, because asking means calling the model.
  * Enforcement. A block here is the gateway refusing to forward; the appliance never holds the
    content. That is genuinely stronger than scanning locally — the one thing this direction wins.

So the tool checkpoints below return NOT_INSPECTED rather than ALLOW. Answering ALLOW would be
this class claiming a coverage it does not have, and that claim is precisely how a gap becomes
invisible.
"""

from __future__ import annotations

import logging
from typing import Any, Sequence

from src.guardrail import Decision, Detection, Direction, Masked, ToolCall, Turn, Verdict

log = logging.getLogger("pretzel-ai.airs")

# The gateway reports the prompt leg and the response leg as separate hook lists.
_PHASES = (("before_request_hooks", Direction.PROMPT),
           ("after_request_hooks", Direction.RESPONSE))

_DETECTION_FIELDS = ("prompt_detected", "response_detected", "tool_detected")


class GatewayGuardrail:
    """Defers to the gateway: reads the verdict it reached, if it reached one.

    `route.guardrail = "gateway"` does not turn inspection on. Nothing in this appliance can — the
    plugin is enabled, or not, in the gateway's own console. What the setting says is that this
    appliance will not scan on its own and will report whatever the gateway did.

    `require_guardrail` is where that stops being enough. Delegating is right while the gateway is
    the thing under test; in production an operator usually does want to hear about it when the
    plugin quietly stops being attached, because a completion with no `hook_results` is
    indistinguishable from one that was never meant to be inspected.

        require_guardrail=False  (default)  absent verdict → `uninspected`, the turn proceeds, and
                                 the console's verdict pill says so. Delegation, honestly reported.

        require_guardrail=True   the operator asserted a gateway guardrail exists. Its absence is
                                 a misconfiguration — NOT_INSPECTED, and the turn stops.
    """

    def __init__(self, require_guardrail: bool = False) -> None:
        self._required = require_guardrail

    def read(self, doc: dict[str, Any], direction: Direction = Direction.PROMPT) -> Verdict:
        """Fold `hook_results` from a completion into a Verdict.

        `direction` labels the verdict as a whole; individual detections keep the direction of the
        hook that produced them, so a response-side finding is never filed as a prompt one.
        """
        hooks = doc.get("hook_results") if isinstance(doc, dict) else None
        if not isinstance(hooks, dict):
            return self._absent(direction)

        state = _HookState()
        for key, hook_direction in _PHASES:
            for hook in hooks.get(key) or []:
                if isinstance(hook, dict):
                    state.absorb(hook, hook_direction)

        if not state.present:
            # hook_results existed but held no hook: the plugin is attached and produced nothing.
            return self._absent(direction)

        # Four states, and the dangerous one is third. `ruled` says at least one check came back
        # with a verdict on the content; `check_error` says at least one never did. A hook whose
        # AIRS call errored, with fail_on_error off, leaves its own verdict true — so a guardrail
        # that never looked is byte-identical to one that looked and cleared, unless this branch
        # is the one that speaks.
        if state.check_error and not state.ruled:
            decision, inspected = Decision.NOT_INSPECTED, False
        elif not state.any_fail:
            decision, inspected = Decision.ALLOW, True
        elif state.denied:
            decision, inspected = Decision.BLOCK, True
        else:
            decision, inspected = Decision.FLAGGED, True

        masked = state.masked
        if masked is not None:
            # `transformed` is the gateway saying it forwarded the rewritten text. A mask computed
            # and not applied means the original went upstream, which is the opposite outcome.
            masked = Masked(text=masked.text, patterns=masked.patterns,
                            applied=state.transformed)

        return Verdict(
            decision=decision,
            direction=direction,
            inspected=inspected,
            enforced=state.denied,
            detections=tuple(state.detections),
            threats=(),                 # the gateway's payload carries no named threats
            masked=masked,
            scan_id=state.scan_id,
            report_id=state.report_id,
            profile=state.profile,
            profile_id=state.profile_id,
            latency_ms=state.latency,
            timed_out=state.timed_out,
            errored=state.errored or state.check_error,
            error=state.error_detail,
        )

    # ── Guardrail protocol ───────────────────────────────────────────────────────────────
    #
    # None of these can make a request: this guardrail only ever reads a verdict that came back
    # with a completion. They report that plainly instead of guessing.

    def _absent(self, direction: Direction) -> Verdict:
        """No verdict came back with the completion."""
        if not self._required:
            return Verdict.uninspected_by_design(direction)
        return Verdict.not_inspected(
            direction,
            "route.require_guardrail is set but the gateway returned no guardrail result — check "
            "that the AIRS plugin is enabled on the gateway config this appliance's key routes "
            "through")

    def inspect_prompt(self, turn: Turn, prompt: str,
                       context: Sequence[str] = ()) -> Verdict:
        # Nothing to ask before the call: on this path the inspection IS the call.
        return Verdict.uninspected_by_design(Direction.PROMPT)

    def inspect_response(self, turn: Turn, prompt: str, response: str) -> Verdict:
        # The response verdict arrives on the completion and is read there, not here.
        return Verdict.uninspected_by_design(Direction.RESPONSE)

    def inspect_tool_call(self, turn: Turn, call: ToolCall) -> Verdict:
        return Verdict.not_inspected(
            Direction.TOOL_INPUT,
            "the gateway's inline hook does not receive tool calls")

    def inspect_tool_result(self, turn: Turn, call: ToolCall, output: str) -> Verdict:
        return Verdict.not_inspected(
            Direction.TOOL_OUTPUT,
            "the gateway's inline hook does not receive tool results")


class _HookState:
    """Accumulates what the hook lists say, so `read` stays a decision and not a parse."""

    def __init__(self) -> None:
        self.present = False
        self.any_fail = False
        self.denied = False
        self.transformed = False
        self.ruled = False
        self.check_error = False
        self.timed_out = False
        self.errored = False
        self.latency = 0
        self.profile = ""
        self.profile_id = ""
        self.scan_id = ""
        self.report_id = ""
        self.error_detail = ""
        self.detections: list[Detection] = []
        self.masked: Masked | None = None

    def absorb(self, hook: dict[str, Any], direction: Direction) -> None:
        self.present = True

        # verdict defaults True: a hook that reported none has not failed.
        if hook.get("verdict", True) is False:
            self.any_fail = True
        # softDeny200 is a block wearing a 200. Read as anything else, enforcement looks off when
        # it is on.
        self.denied = self.denied or bool(hook.get("deny") or hook.get("softDeny200"))
        self.transformed = self.transformed or bool(hook.get("transformed", False))
        self.latency = max(self.latency, int(hook.get("execution_time") or 0))

        for check in hook.get("checks") or []:
            if isinstance(check, dict):
                self._absorb_check(check, direction)

    def _absorb_check(self, check: dict[str, Any], direction: Direction) -> None:
        # The error is read BEFORE the data, because a check that errored has none.
        error = check.get("error")
        if error:
            self.check_error = True
            if not self.error_detail:
                detail = error.get("message", "") if isinstance(error, dict) else str(error)
                self.error_detail = str(detail)[:200]

        data = check.get("data")
        if not isinstance(data, dict):
            return
        self.ruled = True

        self.profile = self.profile or str(data.get("profile_name", ""))
        self.profile_id = self.profile_id or str(data.get("profile_id", ""))
        self.scan_id = self.scan_id or str(data.get("scan_id", ""))
        self.report_id = self.report_id or str(data.get("report_id", ""))
        self.timed_out = self.timed_out or bool(data.get("timeout", False))
        self.errored = self.errored or bool(data.get("error", False))

        # Every category the service reported, hit or not, with names taken from the payload
        # rather than a list compiled here. A category added tomorrow then appears on its own; a
        # hard-coded list would drop it, and "not shown" reads exactly like "not detected".
        for field in _DETECTION_FIELDS:
            block = data.get(field)
            if not isinstance(block, dict):
                continue
            for name, hit in block.items():
                if isinstance(hit, bool):
                    self.detections.append(Detection(id=name, direction=direction, hit=hit))

        if self.masked is None:
            self.masked = _masked(data.get("prompt_masked_data"))


def _masked(raw: Any) -> Masked | None:
    if not isinstance(raw, dict) or not raw.get("data"):
        return None
    patterns = tuple(
        str(p["pattern"]) for p in (raw.get("pattern_detections") or [])
        if isinstance(p, dict) and isinstance(p.get("pattern"), str))
    return Masked(text=str(raw["data"]), patterns=patterns, applied=False)
