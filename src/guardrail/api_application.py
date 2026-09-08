"""The Prisma AIRS guardrail: this appliance calls the scan API and holds the enforcement point.

One of the two axes of a deployment, and only one. Nothing here knows which transport carries the
completion - see deployment/transport.py - so a guardrail can be added to a deployment without
moving its traffic.

Built on the vendor's Python SDK, and on its highest layer
-----------------------------------------------------------
`aisecurity.scan.inline.Scanner.sync_scan` is the call. Not the generated client underneath it,
and not HTTP: this file is also the shortest honest answer to "how do I put Prisma AIRS in front of
my model", and a customer adopting it should be able to read the scan call here and recognise the
one in the vendor's own quickstart. A hand-rolled request would be faster to tune and worth
nobody's time to copy.

`inline` rather than `asyncio` because a turn runs on a gRPC worker thread. The async half of the
SDK pulls aiohttp and an event loop this process does not have.

What that layer costs, stated because it is not free
---------------------------------------------------
Three limits come from using the wrapper rather than the generated client below it. All three are
answerable one layer down, and that is a later change - see the module TODO in
deployment/guardrail.py.

  1. ONE content element per scan. `ScanExecutor.sync_request` wraps the Content in a
     one-element `contents` list, so a turn is scanned alone. AIRS reads `contents` as a
     conversation and judges its LAST element, so the judged content is the same either way -
     what is lost is the earlier turns as CONTEXT, which is what the ungrounded detector reads.
     History is therefore not sent at all rather than sent somewhere it would not be read.
  2. NO per-request timeout. `_request_timeout` exists on the generated `ScansApi.scan_sync_request`
     and the wrapper does not forward it, so `airs_timeout_sec` cannot be applied here. The builder
     says so out loud on every build rather than letting a configured number look effective.
  3. The API key is fixed at FIRST USE, for the life of the process. `ScanExecutor` is a
     `@singleton` and freezes the key into a default header when it is constructed. A key rotated
     through ApplyConfig reaches this object and not that one, so rotation needs a daemon restart.

The vocabulary is here too
--------------------------
Decision, Direction, Detection, Masked and Verdict belong to a guardrail package rather than to
this implementation, and they will move when a second one exists. They are here because there is
one, and a package of five files with one import each says less than this does.

The distinction the vocabulary exists for: a guardrail can rule AGAINST content, or it can never
rule at all. Both are "not allowed" to a boolean, and collapsing them is how a control that never
ran gets reported as one that ran and cleared. `Decision.NOT_INSPECTED` is the second case.
"""

from __future__ import annotations

import enum
import logging
import time
from dataclasses import dataclass
from typing import Any

import aisecurity
from aisecurity.exceptions import AISecSDKException
from aisecurity.generated_openapi_client import AiProfile
from aisecurity.generated_openapi_client.models.metadata import Metadata
from aisecurity.scan.inline.scanner import Scanner
from aisecurity.scan.models.content import Content

from src.engine import Checkpoint

log = logging.getLogger("pretzel-ai.guardrail.api_application")

# What this appliance calls itself in a scan report. Fixed rather than configured: it names the
# software, not the deployment, and an operator who could edit it could make two appliances
# indistinguishable in the vendor's console.
APP_NAME = "pretzel-ai"

# How much scanned text one request may carry, in BYTES.
#
# Measured 2026-08-27: the scan API answers 413 at roughly 2 MiB of total request body, and a 413
# is not retryable - the turn is simply lost. The SDK's own ceilings do not prevent it. They are
# per FIELD (2 MiB prompt, 2 MiB response, 100 MiB context), so two fields can pass validation and
# still exceed the body limit together; and they count CHARACTERS, so Korean text at three bytes
# per character clears a 2 MiB check at a third of the size that actually arrives.
#
# So the clip is here, in bytes, shared across the fields of one request, and under the limit by
# enough to cover the JSON envelope, the ids and the profile name.
MAX_SCAN_BYTES = 1_500_000

# Retries inside the SDK, on 500/502/503/504 only. Lower than the SDK's default of 5 because a
# turn is a person waiting: with no timeout available (see the module docstring) each retry is
# unbounded, and five of them in series is a wait nobody will sit through.
NUM_RETRIES = 2


# -- what an inspection says ------------------------------------------------------------


class Decision(enum.Enum):
    """The four states an inspection can end in.

    FLAGGED is the one a boolean hides: the guardrail found something and the content was
    forwarded anyway - a profile configured to alert rather than block. Reporting that as ALLOW
    loses the finding; reporting it as BLOCK claims an enforcement that did not happen.
    """

    ALLOW = "allow"
    BLOCK = "block"
    FLAGGED = "flagged"
    NOT_INSPECTED = "not_inspected"

    @property
    def permits(self) -> bool:
        """True when the content may proceed.

        NOT_INSPECTED does NOT permit. That is a policy baked into the type: an appliance that
        cannot inspect should stop, and the alternative - proceeding because nothing said no - is
        the failure this codebase exists to prevent. A caller that genuinely wants to proceed
        uninspected has to say so at the call site (Engine.fail_open), where it is visible.
        """
        return self in (Decision.ALLOW, Decision.FLAGGED)


class Direction(enum.Enum):
    """Which leg of a turn was inspected. Not decoration: the same payload is benign in one
    direction and an attack in the other, and a report that does not say which is unreadable.

    Not to be confused with a Checkpoint, which says WHERE in the turn the appliance stopped to
    look. The two are spelled differently on purpose - `tool_call` is a checkpoint and a proto
    field, `tool_input` is the direction content was flowing when a finding was made.
    """

    PROMPT = "prompt"
    RESPONSE = "response"
    CONTEXT = "context"          # retrieved material, before the model sees it
    TOOL_INPUT = "tool_input"
    TOOL_OUTPUT = "tool_output"


@dataclass(frozen=True)
class Detection:
    """One detector's finding. `hit` is carried even when false - "PII: none" is information, and
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

    # Whether an inspection actually took place. Distinct from the decision because NOT_INSPECTED
    # is reachable in more than one way, and because a caller that only wants to know "did
    # anything look at this" should not have to enumerate decisions to find out.
    inspected: bool = False

    # Enforcement, as opposed to opinion: the guardrail refused to pass the content on, rather
    # than reporting a finding and letting it through.
    enforced: bool = False

    detections: tuple[Detection, ...] = ()
    threats: tuple[str, ...] = ()
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
    # content and neither may be reported as a pass - but they are answered differently, and the
    # difference decides whether the turn stops. This checkpoint is switched off: that is the
    # operator's stated intent and the turn proceeds. The scan could not be reached: the turn
    # stops, because proceeding would be the appliance deciding on its own to run uninspected.
    by_design: bool = False

    @property
    def permits(self) -> bool:
        return self.decision.permits

    @property
    def hits(self) -> tuple[str, ...]:
        """Detector ids that actually fired, in a stable order."""
        return tuple(sorted({d.id for d in self.detections if d.hit}))

    @classmethod
    def not_inspected(cls, direction: Direction, reason: str = "") -> "Verdict":
        """Nothing looked at this, and something should have. The reason is carried because "the
        scan timed out" and "no profile is set" send an operator to different places."""
        return cls(decision=Decision.NOT_INSPECTED, direction=direction,
                   inspected=False, errored=bool(reason), error=reason, by_design=False)

    @classmethod
    def uninspected_by_design(cls, direction: Direction) -> "Verdict":
        """This checkpoint is switched off. Still NOT_INSPECTED - the content was not looked at
        and the report must not imply otherwise - but with no error to chase."""
        return cls(decision=Decision.NOT_INSPECTED, direction=direction, inspected=False,
                   by_design=True)


# -- the guardrail ----------------------------------------------------------------------


# Where in the turn the appliance stopped, and which way the content was flowing when it did.
_DIRECTIONS = {
    Checkpoint.PROMPT: Direction.PROMPT,
    Checkpoint.RESPONSE: Direction.RESPONSE,
    Checkpoint.TOOL_CALL: Direction.TOOL_INPUT,
    Checkpoint.TOOL_RESULT: Direction.TOOL_OUTPUT,
}


class ApiApplicationGuardrail:
    """Calls the Prisma AIRS scan API, one request per checkpoint.

    Holds the checkpoint gate itself rather than being wrapped in one. The two are separable in
    principle - which points are live is configuration, and calling the API is this class's job -
    but a wrapper that answered `uninspected_by_design` for three of four points and delegated the
    fourth would be a class whose whole content is a dictionary lookup this one already does.
    """

    def __init__(self, api_key: str, endpoint: str, profile_name: str, points, *,
                 timeout_sec: float = 0.0) -> None:
        # Process-global, and the SDK offers no other way in. Called before the Scanner is built
        # because the executor underneath it reads this configuration once, when it is first
        # constructed, and holds what it read - see the module docstring, limit 3.
        aisecurity.init(api_key=api_key, api_endpoint=endpoint, num_retries=NUM_RETRIES)

        self._scanner = Scanner()
        self._profile = AiProfile(profile_name=profile_name)
        self._profile_name = profile_name

        # Which of the four this service runs, already intersected against what the service has -
        # see ServiceConfig.active_points(). Held as a set of Checkpoint so `inspect` answers the
        # question with a membership test rather than by re-deriving the intersection.
        self._points = frozenset(points)

        # Carried only so `describes` can report what was configured. Nothing applies it: the
        # wrapper does not forward a timeout. Kept rather than dropped so the log line an operator
        # reads says the number they typed, beside the warning that it is not in effect.
        self._timeout_sec = timeout_sec

    @property
    def describes(self) -> str:
        """How this guardrail names itself in the startup log.

        The profile and the live points, because those are the two facts a scan report is read
        against: a point that is off produces no findings, and "no findings" and "nobody looked"
        are the same line in a report that does not say which.
        """
        points = "+".join(p.value for p in Checkpoint if p in self._points) or "none"
        return f"AIRS api_application (profile={self._profile_name}, checkpoints={points})"

    # -- the one method the engine calls -------------------------------------------------

    def inspect(self, checkpoint: Checkpoint, turn, **content) -> Verdict:
        """One checkpoint, whichever of the four it is.

        ONE method rather than four because the engine's part is identical at every point - see
        Engine._inspect. What differs is only what is being looked at, and that arrives in
        `content`: `prompt` at the prompt checkpoint, `prompt` and `completion` at the response
        one.

        Never raises. A guardrail that threw mid-turn would fail the RPC rather than the turn, and
        the console would show a broken appliance where the honest answer is "nothing inspected
        this". Every failure leaves here as NOT_INSPECTED with a reason, which stops the turn
        unless the deployment declared fail_open.
        """
        direction = _DIRECTIONS.get(checkpoint, Direction.PROMPT)

        if checkpoint not in self._points:
            return Verdict.uninspected_by_design(direction)

        scanned, error = _content_for(checkpoint, content)
        if error:
            return Verdict.not_inspected(direction, error)

        started = time.monotonic()
        try:
            response = self._scanner.sync_scan(
                ai_profile=self._profile,
                content=scanned,
                # No `tr_id`. Measured 2026-08-26: the scan API treats `tr_id` and `session_id` as
                # one slot and session_id wins, so sending both discards one of them on every
                # call. Only `transaction_id` is independent.
                session_id=turn.session_id or None,
                transaction_id=turn.transaction_id or None,
                metadata=Metadata(app_name=APP_NAME,
                                  app_user=turn.app_user or None,
                                  ai_model=turn.model or None),
            )
        except AISecSDKException as exc:
            # The SDK's one exception type, for everything from a rejected payload to a 5xx. The
            # HTTP status does not survive the wrapper, so the message is all there is to report.
            latency = int((time.monotonic() - started) * 1000)
            log.warning("scan failed (%s, %dms): %s", direction.value, latency, exc)
            return Verdict.not_inspected(direction, f"the AIRS scan failed: {exc}")
        except Exception as exc:                                    # noqa: BLE001
            # Anything the SDK did not wrap. Caught for the same reason as above: this method's
            # contract with the engine is that it returns a verdict.
            latency = int((time.monotonic() - started) * 1000)
            log.warning("scan failed (%s, %dms): %r", direction.value, latency, exc)
            return Verdict.not_inspected(direction, f"the AIRS scan failed: {exc}")

        latency = int((time.monotonic() - started) * 1000)
        verdict = _to_verdict(response, direction, latency)

        log.debug("scan (direction=%s, decision=%s, scan_id=%s, hits=[%s], latency=%dms)",
                  direction.value, verdict.decision.value, verdict.scan_id or "-",
                  ",".join(verdict.hits), latency)
        return verdict


# -- the turn, as one scan request ------------------------------------------------------


def _content_for(checkpoint: Checkpoint, content: dict) -> tuple[Content | None, str]:
    """→ (Content, "") or (None, why not).

    The prompt is sent again at the response checkpoint, and that is not redundancy: a response is
    judged against what was asked for, and a scan given the answer alone rules on it out of
    context.

    History is not sent. It would go in `context`, which the injection detector does not read
    (measured 2026-08-27), and the earlier turns of a conversation belong in earlier `contents`
    elements - which this SDK layer cannot send. Neither arrangement gets history judged, so the
    honest one is the one that does not pay for it in body size.
    """
    budget = MAX_SCAN_BYTES

    if checkpoint is Checkpoint.PROMPT:
        prompt, budget = _clip(content.get("prompt") or "", budget)
        if not prompt:
            return None, "there was no prompt to scan"
        return Content(prompt=prompt), ""

    if checkpoint is Checkpoint.RESPONSE:
        completion = content.get("completion")
        answer = getattr(completion, "text", "") or ""
        if not answer:
            return None, "there was no response to scan"

        # The answer takes the budget first. It is the content being judged at this checkpoint;
        # the prompt beside it is context, and context is what may be cut short.
        answer, budget = _clip(answer, budget)
        prompt, budget = _clip(content.get("prompt") or "", budget)
        return Content(prompt=prompt or None, response=answer), ""

    # TOOL_CALL and TOOL_RESULT. Unreachable today - chat has no tools, so `active_points()` can
    # never make either live - and answered rather than assumed: a scan needs a ToolEvent, and
    # this appliance has no tool vocabulary to build one from since the agent engine was removed.
    return None, (f"the {checkpoint.value} checkpoint is configured but this appliance has no "
                  "tool vocabulary to scan")


def _clip(text: str, budget: int) -> tuple[str, int]:
    """→ (text within the byte budget, what is left of it).

    Cut on a character boundary, not a byte one: a half-encoded character would make the request
    body invalid rather than merely short. The cut is logged because a truncated scan is a scan
    that ruled on less than the model was given, and that is a fact about the verdict.
    """
    if budget <= 0:
        return "", 0

    encoded = text.encode("utf-8")
    if len(encoded) <= budget:
        return text, budget - len(encoded)

    clipped = encoded[:budget].decode("utf-8", errors="ignore")
    log.warning("scanned content clipped to %d bytes (was %d) - the verdict rules on less than "
                "the model was given", budget, len(encoded))
    return clipped, 0


# -- the scan response, as a verdict ----------------------------------------------------


def _to_verdict(response, direction: Direction, latency_ms: int) -> Verdict:
    """One ScanResponse, in this appliance's vocabulary.

    `action` and `category` are two axes and both are read. `action` says what the profile did -
    block or allow - and `category` says what it thought: malicious or benign. Allowed AND
    malicious is a real outcome, the one a profile configured to alert produces, and it is FLAGGED
    rather than ALLOW because the finding has to survive into the report.
    """
    action = (getattr(response, "action", "") or "").lower()
    category = (getattr(response, "category", "") or "").lower()

    if action == "block":
        decision = Decision.BLOCK
    elif category == "malicious":
        decision = Decision.FLAGGED
    else:
        decision = Decision.ALLOW

    detections = _detections(response, direction)

    # A detection service that errored or timed out is reported beside the verdict rather than
    # instead of it. AIRS still ruled - on whatever the remaining detectors saw - and replacing a
    # real decision with NOT_INSPECTED would discard a block that did happen.
    errors = getattr(response, "errors", None) or []
    error_text = ""
    if errors:
        named = []
        for entry in errors:
            feature = _value(getattr(entry, "feature", "")) or "a detector"
            status = _value(getattr(entry, "status", "")) or "failed"
            named.append(f"{feature}: {status}")
        error_text = "; ".join(named)

    return Verdict(
        decision=decision,
        direction=direction,
        inspected=True,
        enforced=decision is Decision.BLOCK,
        detections=detections,
        threats=_threats(response),
        masked=_masked(response, direction),
        scan_id=getattr(response, "scan_id", "") or "",
        report_id=getattr(response, "report_id", "") or "",
        profile=getattr(response, "profile_name", "") or "",
        profile_id=getattr(response, "profile_id", "") or "",
        latency_ms=latency_ms,
        timed_out=bool(getattr(response, "timeout", False)),
        errored=bool(getattr(response, "error", False)) or bool(errors),
        error=error_text,
    )


def _detections(response, direction: Direction) -> tuple[Detection, ...]:
    """Every detector the response named, hit or not.

    Read off whichever of `prompt_detected` / `response_detected` this direction produced. The
    fields are booleans named for the detector - `injection`, `dlp`, `url_cats` - so the model's
    own dict IS the finding list, and enumerating them here would be a second copy of the vendor's
    detector roster to keep in step.
    """
    if direction is Direction.RESPONSE:
        detected = getattr(response, "response_detected", None)
    else:
        detected = getattr(response, "prompt_detected", None)

    if detected is None:
        return ()

    found = []
    for name, value in _as_dict(detected).items():
        if isinstance(value, bool):
            found.append(Detection(id=name, direction=direction, hit=value))

    found.sort(key=lambda d: d.id)
    return tuple(found)


def _threats(response) -> tuple[str, ...]:
    """Named threats, where the profile produced any.

    Distinct from a detector id: `injection` is which detector fired, "context poisoning" is what
    it says the content was doing. Only the ones that fired are named, so an empty tuple means no
    threat was named rather than that none was looked for.
    """
    details = getattr(response, "prompt_detection_details", None)
    names = set()

    for source in (details, getattr(response, "response_detection_details", None)):
        if source is None:
            continue
        for key, value in _as_dict(source).items():
            if isinstance(value, str) and value:
                names.add(value)
            elif isinstance(value, dict):
                verdict = value.get("verdict") or value.get("threat")
                if isinstance(verdict, str) and verdict:
                    names.add(verdict)

    return tuple(sorted(names))


def _masked(response, direction: Direction) -> Masked | None:
    """Sensitive text the scan rewrote, when it produced any.

    `applied` is False here and that is the truth rather than a placeholder: this appliance does
    not forward the masked text in place of the original. The mask is reported so an operator can
    see what was found; substituting it into the turn is a separate decision nobody has made.
    """
    if direction is Direction.RESPONSE:
        data = getattr(response, "response_masked_data", None)
    else:
        data = getattr(response, "prompt_masked_data", None)

    if data is None:
        return None

    text = getattr(data, "data", "") or ""
    if not text:
        return None

    patterns = []
    for entry in getattr(data, "pattern_detections", None) or []:
        name = getattr(entry, "name", "") or getattr(entry, "pattern", "")
        if name:
            patterns.append(str(name))

    return Masked(text=text, patterns=tuple(patterns), applied=False)


def _as_dict(model) -> dict[str, Any]:
    """A generated model as a plain dict, however this SDK version spells that."""
    for name in ("to_dict", "model_dump", "dict"):
        method = getattr(model, name, None)
        if callable(method):
            try:
                value = method()
            except Exception:                                       # noqa: BLE001
                continue
            if isinstance(value, dict):
                return value
    return {}


def _value(member) -> str:
    """An enum member's value, or whatever it already was."""
    return str(getattr(member, "value", member) or "")
