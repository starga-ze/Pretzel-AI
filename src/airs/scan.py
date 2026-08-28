"""Prisma AIRS as a Guardrail: ask it about a checkpoint, get a Verdict.

The translation layer. client.py knows the wire; src/guardrail.py knows the vocabulary; this file
is the only place that knows both, so replacing AIRS with another service means writing one more
file of this shape and changing a line of config.

What the appliance gains by calling the service directly, rather than reading the verdict off an
AI gateway's inline hook, is the agent surface. A gateway hook builds its scan request from a chat
completion, and a chat completion has no field for which MCP server a tool belongs to — so tool
calls, tool results and tool descriptions reach the scanner as, at best, concatenated prose, and
in the gateway this codebase measured, not at all. Every `inspect_tool_*` method here exists
because that gap is real and this is where it closes.
"""

from __future__ import annotations

import logging
from typing import Any, Sequence

from src.airs.client import AirsClient, AirsError, ScanContent, ToolEvent
from src.guardrail import Decision, Detection, Direction, Masked, ToolCall, Turn, Verdict

log = logging.getLogger("pretzel-ai.airs")

# Which detector block of the response describes which direction. The service reports prompt and
# response findings at the top level and tool findings nested under tool_detected.
_PROMPT_BLOCK = "prompt_detected"
_RESPONSE_BLOCK = "response_detected"


class AirsGuardrail:
    """Implements src.guardrail.Guardrail against the AIRS scan API."""

    def __init__(self, client: AirsClient) -> None:
        self._client = client

    # ── Checkpoints ──────────────────────────────────────────────────────────────────────

    def inspect_prompt(self, turn: Turn, prompt: str,
                       context: Sequence[str] = ()) -> Verdict:
        """The person's words, plus whatever was retrieved to answer them.

        Retrieved material rides in `context` rather than being pasted into the prompt. The two
        are judged differently — grounding is a question about the context, injection a question
        about the prompt — and merging them asks the wrong one of both.
        """
        content = ScanContent(prompt=prompt,
                              context="\n\n".join(c for c in context if c) or None)
        return self._run([content], turn, Direction.PROMPT)

    def inspect_response(self, turn: Turn, prompt: str, response: str) -> Verdict:
        """The model's answer, judged against what was asked.

        Both fields go in one content element on purpose: a response alone cannot be told apart
        from a response that is only harmful because of the request behind it.
        """
        return self._run([ScanContent(prompt=prompt, response=response)],
                         turn, Direction.RESPONSE)

    def inspect_tool_call(self, turn: Turn, call: ToolCall) -> Verdict:
        """Before the tool runs. The only checkpoint whose skip cannot be undone.

        Note what is scanned: the arguments the model chose. A tool call whose arguments are
        benign passes here even when the call itself is catastrophic — `rule_id=ALL,
        action=allow` contains nothing malicious to find. That is an authorization question, not
        a detection one, and it belongs to the tool registry rather than to any scanner.
        """
        event = ToolEvent(server=call.server or "unknown", tool=call.name,
                          ecosystem=call.ecosystem, method=call.method,
                          input=call.arguments or "{}")
        return self._run([ScanContent(tool_event=event)], turn, Direction.TOOL_INPUT)

    def inspect_tool_result(self, turn: Turn, call: ToolCall, output: str) -> Verdict:
        """After the tool ran, before its output re-enters the conversation.

        Indirect prompt injection arrives here: a document, an issue body, a file the agent was
        told to read. The tool did what it was asked; what came back is the attack.
        """
        event = ToolEvent(server=call.server or "unknown", tool=call.name,
                          ecosystem=call.ecosystem, method=call.method,
                          input=call.arguments or "{}", output=output or "{}")
        return self._run([ScanContent(tool_event=event)], turn, Direction.TOOL_OUTPUT)

    # ── Plumbing ─────────────────────────────────────────────────────────────────────────

    def _run(self, contents: list[ScanContent], turn: Turn, direction: Direction) -> Verdict:
        try:
            doc, latency_ms = self._client.scan(
                contents, tr_id=turn.tr_id, session_id=turn.session_id,
                transaction_id=turn.transaction_id, app_name=turn.app_name,
                app_user=turn.app_user, ai_model=turn.model)
        except AirsError as exc:
            # NOT_INSPECTED, never ALLOW. The caller decides what to do about an unavailable
            # guardrail; this layer's job is to report accurately that none ran.
            log.warning("airs: %s scan unavailable (%s)", direction.value, exc)
            return Verdict.not_inspected(direction, str(exc))

        return _to_verdict(doc, direction, latency_ms)


def _to_verdict(doc: dict[str, Any], direction: Direction, latency_ms: int) -> Verdict:
    """The service's document, folded into the vocabulary the rest of the appliance speaks."""
    action = str(doc.get("action", "")).lower()
    category = str(doc.get("category", "")).lower()

    detections, threats, masked = _findings(doc, direction)

    # The service's own error and timeout flags decide whether this counts as an inspection at
    # all. A document that says allow while reporting that a detection service errored is not a
    # clean pass — it is a pass nobody checked, and reading it as ALLOW is the exact mistake this
    # type exists to prevent.
    errored = bool(doc.get("error", False))
    timed_out = bool(doc.get("timeout", False))
    service_failed = errored or timed_out or category in ("error", "timeout")

    if service_failed and action != "block":
        decision = Decision.NOT_INSPECTED
        inspected = False
    elif action == "block":
        decision = Decision.BLOCK
        inspected = True
    elif any(d.hit for d in detections):
        # Something was found and the content was passed anyway. Neither allow nor block.
        decision = Decision.FLAGGED
        inspected = True
    elif action == "allow":
        decision = Decision.ALLOW
        inspected = True
    else:
        decision = Decision.NOT_INSPECTED
        inspected = False

    return Verdict(
        decision=decision,
        direction=direction,
        inspected=inspected,
        enforced=(decision is Decision.BLOCK),
        detections=detections,
        threats=threats,
        masked=masked,
        scan_id=str(doc.get("scan_id", "")),
        report_id=str(doc.get("report_id", "")),
        profile=str(doc.get("profile_name", "")),
        profile_id=str(doc.get("profile_id", "")),
        latency_ms=latency_ms,
        timed_out=timed_out,
        errored=errored,
        error=_first_error(doc) if service_failed else "",
    )


def _findings(doc: dict[str, Any],
              direction: Direction) -> tuple[tuple[Detection, ...], tuple[str, ...], Masked | None]:
    """Detections, named threats and masked text, from whichever block describes this direction."""
    detections: list[Detection] = []
    threats: list[str] = []
    masked: Masked | None = None

    if direction in (Direction.TOOL_INPUT, Direction.TOOL_OUTPUT):
        block = "input_detected" if direction is Direction.TOOL_INPUT else "output_detected"
        tool = doc.get("tool_detected")
        entries = ((tool or {}).get(block) or {}).get("detection_entries") or []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            for name, hit in (entry.get("detections") or {}).items():
                if isinstance(hit, bool):
                    detections.append(Detection(id=name, direction=direction, hit=hit))
            threats.extend(str(t) for t in (entry.get("threats") or []))
            masked = masked or _masked(entry.get("masked_data"))
        return tuple(detections), tuple(dict.fromkeys(threats)), masked

    # Prompt and response scans report both blocks; each names its own direction so a response
    # finding is never filed as a prompt one.
    for block, block_direction in ((_PROMPT_BLOCK, Direction.PROMPT),
                                   (_RESPONSE_BLOCK, Direction.RESPONSE)):
        for name, hit in (doc.get(block) or {}).items():
            if isinstance(hit, bool):
                detections.append(Detection(id=name, direction=block_direction, hit=hit))

    masked = _masked(doc.get("response_masked_data")) or _masked(doc.get("prompt_masked_data"))
    return tuple(detections), (), masked


def _masked(raw: Any) -> Masked | None:
    if not isinstance(raw, dict) or not raw.get("data"):
        return None
    patterns = tuple(
        str(p.get("pattern")) for p in (raw.get("pattern_detections") or [])
        if isinstance(p, dict) and p.get("pattern"))
    # `applied` stays False here: this layer knows a mask was computed, not whether anything
    # forwarded it. Only the code that chose which text to send can say, and it sets the flag.
    return Masked(text=str(raw["data"]), patterns=patterns, applied=False)


def _first_error(doc: dict[str, Any]) -> str:
    """The service names which detector failed and how; that is more use than "error: true"."""
    for entry in doc.get("errors") or []:
        if not isinstance(entry, dict):
            continue
        parts = [str(entry.get(k)) for k in ("feature", "content_type", "status") if entry.get(k)]
        if parts:
            return " / ".join(parts)
    if doc.get("timeout"):
        return "a detection service timed out"
    return "a detection service reported an error"
