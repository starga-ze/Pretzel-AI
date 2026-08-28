"""TurnResult, in the shape the console already parses.

A contract adapter and nothing else. The browser reads specific keys out of `result_json` — a
field renamed here is a field the console silently stops showing — so the engine's own vocabulary
stops at this file and the wire keeps the names it has always had.

Two shapes have to be reconciled. The engine produces a LIST of verdicts, because one turn can
now inspect five things: prompt, tool input, tool output, prompt again, response. The console
expects ONE `scan` object and tells the directions apart by reading `categories[].direction`. So
the merge below is lossless in the way that matters — every detection keeps the direction it was
found in — and lossy only in the way the console never used: which iteration of an agent loop a
finding came from.
"""

from __future__ import annotations

from typing import Any

from src.chat.engine import TurnResult
from src.guardrail import Decision, Direction, Verdict

# The console's own words. Its four states map onto the engine's, except that it says
# "uninspected" where the engine says NOT_INSPECTED.
_CONSOLE_VERDICT = {
    Decision.ALLOW: "allow",
    Decision.BLOCK: "block",
    Decision.FLAGGED: "flagged",
    Decision.NOT_INSPECTED: "uninspected",
}

# Which verdict wins when a turn produced several. Ordered by how much an operator needs to see
# it: a block is the answer, a flag is a finding that got through, an uninspected checkpoint is a
# gap, and allow is the absence of all three.
_PRECEDENCE = (Decision.BLOCK, Decision.FLAGGED, Decision.NOT_INSPECTED, Decision.ALLOW)


def to_document(result: TurnResult) -> dict[str, Any]:
    """The turn document mgmtd files and the console renders."""
    doc: dict[str, Any] = {
        "ok": result.ok,
        "model": result.model,
        "scan": _scan(result),
        "latency_ms": result.latency_ms,
    }

    if result.status:
        doc["status"] = result.status
    if result.code:
        doc["code"] = result.code
    if result.error:
        doc["error"] = result.error
    if result.reply:
        doc["reply"] = result.reply
    if result.usage:
        doc["usage"] = result.usage
        # Flattened too: the console reads these directly rather than reaching into usage.
        doc["tokens_in"] = int(result.usage.get("prompt_tokens", 0) or 0)
        doc["tokens_out"] = int(result.usage.get("completion_tokens", 0) or 0)

    # The three ids, so a turn on screen can be found in the vendor's console. tr_id is the last
    # round trip's — with tools there were several, and the newest is the one that produced the
    # answer being looked at.
    for key, value in (("session_id", result.session_id),
                       ("transaction_id", result.transaction_id),
                       ("tr_id", result.tr_id)):
        if value:
            doc[key] = value

    # Only when the turn actually looped. A 1 on every ordinary turn would be noise, and its
    # absence is what makes its presence mean something.
    if result.iterations > 1:
        doc["iterations"] = result.iterations
    return doc


def _scan(result: TurnResult) -> dict[str, Any]:
    """Every inspection this turn made, folded into the one object the console reads."""
    verdicts = [v for v in result.verdicts if v.inspected or v.errored]
    if not verdicts:
        # No hook on this call's path. The console draws "uninspected" for this, which is the
        # honest thing to draw — not a pass.
        return {"present": False}

    lead = _lead(verdicts)
    categories = [
        {"id": d.id, "direction": d.direction.value, "hit": d.hit}
        for v in verdicts for d in v.detections
    ]
    threats = sorted({t for v in verdicts for t in v.threats})

    scan: dict[str, Any] = {
        "present": True,
        "verdict": _CONSOLE_VERDICT[lead.decision],
        "direction": lead.direction.value,
        "enforced": any(v.enforced for v in verdicts),
        "async": False,             # the engine's checkpoints are all synchronous
        "action": "block" if lead.enforced else "allow",
        "profile": _first(verdicts, "profile"),
        "profile_id": _first(verdicts, "profile_id"),
        "scan_id": lead.scan_id or _first(verdicts, "scan_id"),
        "report_id": lead.report_id or _first(verdicts, "report_id"),
        "latency_ms": max((v.latency_ms for v in verdicts), default=0),
        "timeout": any(v.timed_out for v in verdicts),
        "error": any(v.errored for v in verdicts),
        "categories": categories,
    }

    # Named threats are new with the direct scan path — the gateway's payload has none — so the
    # key is present only when there is something in it rather than as an empty list the console
    # would have to know to ignore.
    if threats:
        scan["threats"] = threats

    detail = next((v.error for v in verdicts if v.error), "")
    if detail:
        # Absent means nothing went wrong, which is true when it is absent.
        scan["error_detail"] = detail

    masked = next((v.masked for v in verdicts if v.masked), None)
    if masked is not None:
        scan["masked"] = {"text": masked.text,
                          "patterns": list(masked.patterns),
                          "applied": masked.applied}
    return scan


def _lead(verdicts: list[Verdict]) -> Verdict:
    """The verdict that speaks for the turn."""
    for decision in _PRECEDENCE:
        for verdict in verdicts:
            if verdict.decision is decision:
                return verdict
    return verdicts[-1]


def _first(verdicts: list[Verdict], attr: str) -> str:
    for verdict in verdicts:
        value = getattr(verdict, attr, "")
        if value:
            return str(value)
    return ""
