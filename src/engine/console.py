"""TurnResult, in the shape the console already parses.

A contract adapter and nothing else. The browser reads specific keys out of `result_json` - a
field renamed here is a field the console silently stops showing - so the engine's own
vocabulary stops at this file and the wire keeps the names it has always had.

It lives beside the engine rather than with the guardrail because its input is a TurnResult.
The verdicts it folds are only one of the things a turn produces.

Two shapes have to be reconciled. The engine produces a LIST of verdicts, because one turn can
inspect two things: the prompt and the response. The console
expects ONE `scan` object and tells the directions apart by reading `categories[].direction`.
The merge below is lossless in the way that matters - every detection keeps the direction it
was found in - and lossy only in the way the console never used: which iteration of an agent
loop a finding came from.

    ---------------------------------------------------------------------------------
    CURRENTLY no guardrail is built, so `result.verdicts` is always empty and every turn
    reports {"present": False}. The console draws that as "uninspected", which is the
    honest thing to draw - it is not a pass.

    The fold below reads verdicts through getattr rather than importing the Verdict
    vocabulary, so this file does not depend on a package that is not here. When the
    guardrail comes back this is where its types get imported properly again.
    ---------------------------------------------------------------------------------
"""

from __future__ import annotations

from typing import Any

from src.engine import TurnResult

# The console's own words. Its four states map onto the engine's, except that it says
# "uninspected" where the engine says NOT_INSPECTED.
_CONSOLE_VERDICT = {
    "allow": "allow",
    "block": "block",
    "flagged": "flagged",
    "not_inspected": "uninspected",
}

# Which verdict wins when a turn produced several. Ordered by how much an operator needs to see
# it: a block is the answer, a flag is a finding that got through, an uninspected checkpoint is
# a gap, and allow is the absence of all three.
_PRECEDENCE = ("block", "flagged", "not_inspected", "allow")


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

    # The two ids, so a turn on screen can be found in the vendor's console.
    for key, value in (("session_id", result.session_id),
                       ("transaction_id", result.transaction_id)):
        if value:
            doc[key] = value

    return doc


def _scan(result: TurnResult) -> dict[str, Any]:
    """Every inspection this turn made, folded into the one object the console reads."""
    # A verdict that neither looked nor failed to look has nothing to report, and folding it in
    # would put an empty entry in a list the console reads as findings.
    verdicts = []
    for verdict in result.verdicts:
        if getattr(verdict, "inspected", False) or getattr(verdict, "errored", False):
            verdicts.append(verdict)
    if not verdicts:
        # Nothing looked at this turn. The console draws "uninspected" for this, which is the
        # honest thing to draw - not a pass.
        return {"present": False}

    lead = _lead(verdicts)

    # Every detection from every checkpoint, flattened but each keeping the direction it was found
    # in - that field is how the console tells a prompt finding from a response one.
    categories = []
    for verdict in verdicts:
        for detection in getattr(verdict, "detections", ()):
            categories.append({"id": detection.id,
                               "direction": _value(detection.direction),
                               "hit": detection.hit})

    named_threats = set()
    for verdict in verdicts:
        for threat in getattr(verdict, "threats", ()):
            named_threats.add(threat)
    threats = sorted(named_threats)

    scan: dict[str, Any] = {
        "present": True,
        "verdict": _CONSOLE_VERDICT.get(_value(lead.decision), _value(lead.decision)),
        "direction": _value(lead.direction),
        "enforced": _any(verdicts, "enforced"),
        "async": False,             # the engine's checkpoints are all synchronous
        "action": "block" if getattr(lead, "enforced", False) else "allow",
        "profile": _first(verdicts, "profile"),
        "profile_id": _first(verdicts, "profile_id"),
        "scan_id": getattr(lead, "scan_id", "") or _first(verdicts, "scan_id"),
        "report_id": getattr(lead, "report_id", "") or _first(verdicts, "report_id"),
        "latency_ms": _slowest(verdicts),
        "timeout": _any(verdicts, "timed_out"),
        "error": _any(verdicts, "errored"),
        "categories": categories,
    }

    # Named threats are new with the direct scan path - the gateway's payload has none - so the
    # key is present only when there is something in it rather than as an empty list the console
    # would have to know to ignore.
    if threats:
        scan["threats"] = threats

    detail = ""
    for verdict in verdicts:
        if getattr(verdict, "error", ""):
            detail = verdict.error
            break
    if detail:
        # Absent means nothing went wrong, which is true when it is absent.
        scan["error_detail"] = detail

    masked = None
    for verdict in verdicts:
        if getattr(verdict, "masked", None):
            masked = verdict.masked
            break
    if masked is not None:
        scan["masked"] = {"text": masked.text,
                          "patterns": list(masked.patterns),
                          "applied": masked.applied}
    return scan


def _lead(verdicts: list):
    """The verdict that speaks for the turn."""
    for decision in _PRECEDENCE:
        for verdict in verdicts:
            if _value(verdict.decision) == decision:
                return verdict
    return verdicts[-1]


def _first(verdicts: list, attr: str) -> str:
    """The first verdict that has this field filled in, as text. "" when none does."""
    for verdict in verdicts:
        value = getattr(verdict, attr, "")
        if value:
            return str(value)
    return ""


def _any(verdicts: list, attr: str) -> bool:
    """True when ANY checkpoint reported this. The turn is enforced, timed out or errored if one
    of its inspections was, not only if the last one was."""
    for verdict in verdicts:
        if getattr(verdict, attr, False):
            return True
    return False


def _slowest(verdicts: list) -> int:
    """The longest single inspection, not their sum: they run at different points in the turn and
    adding them would report a wait nobody had."""
    longest = 0
    for verdict in verdicts:
        latency = getattr(verdict, "latency_ms", 0)
        if latency > longest:
            longest = latency
    return longest


def _value(member) -> str:
    """An enum member's value, or whatever it already was."""
    return getattr(member, "value", member)
