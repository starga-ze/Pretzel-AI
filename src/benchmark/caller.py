"""One benchmark prompt, executed and scored — through whichever route the appliance is set to.

Split out of runner.py, which now owns scheduling and scoring and nothing about transport. A case
goes out the same way an operator's turn does: the engine built by factory.build_engine, holding
whichever transport and guardrail `route` selected. A run therefore measures the deployment that
is actually configured rather than a second path maintained beside it — the old runner spoke to
the gateway with its own urllib client, and that client drifted from the one serving turns.

The one thing this file adds on top of the engine is knowing when the model is unnecessary.
------------------------------------------------------------------------------------------
A prompt-direction case asks "does the guardrail block this prompt". Answering it needs a scan,
not a completion. Running one anyway was the single largest cost in the runs this repo has: 1,125
of run 10's 1,500 cases called a model whose answer was never read, and the resulting token rate
was what drove the 429s that then had to be scored around.

So a prompt-direction case is scanned and stopped. A response-direction case still needs the
model, because there is no response to inspect until one exists.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from src.chat.engine import ChatEngine, TurnResult, new_tr_id
from src.guardrail import Decision, Direction, Turn, Verdict

log = logging.getLogger("pretzel-ai.benchmark")

# Rows whose question is about the prompt alone. Anything else needs a completion to judge.
PROMPT_ONLY_TARGETS = frozenset(("prompt", ""))


@dataclass
class CaseResult:
    """What one prompt produced, in the shape runner.classify and the store expect."""

    verdict: str = "allow"          # allow | block | flagged | not_inspected | error
    scan_id: str = ""
    detectors: list[str] = field(default_factory=list)
    caught: str = "-"               # 요청 | 응답 | 요청+응답 | -
    response: str = ""
    tool_calls: Any = None
    http_status: int | None = None
    latency_ms: int = 0
    completed: bool = False
    threats: list[str] = field(default_factory=list)
    raw_request: Any = None
    raw_response: Any = None
    error: str = ""

    def as_row(self) -> dict[str, Any]:
        """The dict the runner has always passed around, so scoring and storage are unchanged."""
        return {
            "verdict": self.verdict, "scan_id": self.scan_id, "detectors": self.detectors,
            "caught": self.caught, "response": self.response, "tool_calls": self.tool_calls,
            "http_status": self.http_status, "latency_ms": self.latency_ms,
            "completed": self.completed, "threats": self.threats,
            "raw_request": self.raw_request, "raw_response": self.raw_response,
            "error": self.error,
        }


class EngineCaller:
    """Runs one benchmark row through the configured engine.

    Callable so ThreadPoolExecutor.map can drive it, which is how the runner has always
    parallelised a set.
    """

    def __init__(self, engine: ChatEngine, *, scan_only_prompts: bool = True) -> None:
        self._engine = engine
        self._scan_only = scan_only_prompts

    @property
    def model(self) -> str:
        return self._engine.catalog.default

    @property
    def describes(self) -> str:
        return self._engine.describes

    def __call__(self, case: tuple[dict[str, Any], int]) -> dict[str, Any]:
        row, run_id = case
        # One tr_id per case, and the run and prompt in it: a scan an operator asks about later is
        # findable by the name of the run that produced it.
        turn = Turn(session_id=f"bench-{run_id}",
                    transaction_id=f"bench-{run_id}-{row['prompt_id']}",
                    tr_id=new_tr_id(),
                    app_name="pretzel-ai-benchtest",
                    app_user="benchtest")

        prompt_only = (self._scan_only
                       and str(row.get("scan_target", "")) in PROMPT_ONLY_TARGETS)
        if prompt_only:
            return self._scan_prompt(row, turn).as_row()
        return self._full_turn(row, turn).as_row()

    # ── The two shapes a case can take ───────────────────────────────────────────────────

    def _scan_prompt(self, row: dict[str, Any], turn: Turn) -> CaseResult:
        """Prompt-direction: ask the guardrail, never the model."""
        started = time.monotonic()
        verdict = self._engine.guardrail.inspect_prompt(turn, row["prompt"])
        latency = int((time.monotonic() - started) * 1000)

        result = _from_verdicts([verdict], latency)
        result.raw_request = {"scan_target": "prompt", "prompt": row["prompt"]}
        result.completed = False        # no model was asked, and none was needed
        return result

    def _full_turn(self, row: dict[str, Any], turn: Turn) -> CaseResult:
        """Response-direction: the model has to answer before there is anything to inspect."""
        turn_result: TurnResult = self._engine.run(row["prompt"], turn=turn)

        result = _from_verdicts(turn_result.verdicts, turn_result.latency_ms)
        result.response = turn_result.reply
        result.http_status = turn_result.status or None
        result.completed = bool(turn_result.reply)
        result.raw_request = {"scan_target": row.get("scan_target", ""),
                              "prompt": row["prompt"], "model": turn_result.model}
        result.raw_response = turn_result.raw or None

        if turn_result.code in ("UNREACHABLE", "BAD_ROUTE", "BAD_RESPONSE", "UPSTREAM_ERROR",
                                "TOOLS_UNAVAILABLE", "LOOP_LIMIT"):
            # The turn failed for reasons with nothing to do with security. Marked as its own
            # outcome so scoring excludes it instead of counting it as a guardrail miss.
            result.verdict = "error"
            result.error = turn_result.error[:200]
        return result


def _from_verdicts(verdicts: list[Verdict], latency_ms: int) -> CaseResult:
    """Fold the engine's verdicts into the flat shape scoring reads."""
    real = [v for v in verdicts if v.inspected or v.errored]
    if not real:
        return CaseResult(verdict="not_inspected", latency_ms=latency_ms)

    lead = next((v for v in real if v.decision is Decision.BLOCK), None) \
        or next((v for v in real if v.decision is Decision.FLAGGED), None) \
        or next((v for v in real if v.decision is Decision.NOT_INSPECTED), None) \
        or real[0]

    hits = {(d.id, d.direction) for v in real for d in v.detections if d.hit}
    directions = {d for _, d in hits}
    # The console's words, kept because the stored rows are read beside older runs.
    caught = ("요청+응답" if len(directions) > 1
              else "요청" if directions & {Direction.PROMPT, Direction.TOOL_INPUT}
              else "응답" if directions & {Direction.RESPONSE, Direction.TOOL_OUTPUT}
              else "-")

    return CaseResult(
        verdict=lead.decision.value,
        scan_id=lead.scan_id or next((v.scan_id for v in real if v.scan_id), ""),
        detectors=sorted({name for name, _ in hits}),
        caught=caught,
        threats=sorted({t for v in real for t in v.threats}),
        latency_ms=latency_ms,
        error=next((v.error for v in real if v.error), ""))
