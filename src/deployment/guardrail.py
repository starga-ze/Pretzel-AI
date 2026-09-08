"""Who inspects a turn, built from one service's configuration.

The other axis, and only that one. This module never decides which transport serves the
completion - transport.py does, asked for by name in engine.py - so a guardrail can be added to a
deployment without moving its traffic, and a transport can be changed without changing who looks
at it.

    api_application   this appliance calls the Prisma AIRS scan API and holds the enforcement
                      point. Valid on EITHER transport
    (none)            nobody inspects. Expressed as None by the caller, not as a builder here

Reading a verdict off a completion an AI gateway already annotated used to be a third option here.
It is gone: what it bought was inspection this appliance could not describe, configure or report
on - the profile, the detectors and the thresholds all lived in someone else's console - and it
could not see tool calls at all, which is the surface the agent service exists for. The gateway is
a transport now, and nothing else.

The vocabulary a verdict speaks - Verdict, Decision, the four directions - is not here. That
belongs with the implementation that produces it; this module reads a ServiceConfig and returns
the object it names.

TODO: the SDK's wrapper layer, and what it costs
------------------------------------------------
guardrail/api_application.py calls `Scanner.sync_scan`, which is the vendor's own highest-level
entry point and therefore the version a customer can lift. Three limits come with it, all of them
answerable one layer down at the generated `ScansApi`:

  1. one `contents` element per scan, so a conversation cannot be sent as context
  2. no per-request timeout, so `airs_timeout_sec` is configured and not applied - a hung scan
     holds a gRPC worker with nothing to interrupt it
  3. the API key is frozen into a process-wide singleton at first use, so rotating it through
     ApplyConfig needs a daemon restart

Moving to the generated client fixes all three and keeps the SDK's models, its urllib3 pool and
its retries. It costs this file its value as sample code, which is why it has not been done yet.
"""

import logging

from src.deployment import config as cfg
from src.engine import Checkpoint
from src.guardrail.api_application import ApiApplicationGuardrail

log = logging.getLogger("pretzel-ai.deployment.guardrail")


class GuardrailError(Exception):
    """The configuration names a guardrail that cannot be built. Raised at build time, never
    mid-turn."""


def api_application(service: "cfg.ServiceConfig", config: "cfg.Config"):
    """This appliance calls the Prisma AIRS scan API and holds the enforcement point.

    Refused rather than served uninspected. A service configured to be inspected must not come up
    as one that is not - that is the failure this codebase keeps finding in other people's
    deployments, and it is not going to be introduced here by a fallback.

    The two refusals below are the two things the scan call cannot be made without. Both are
    checked HERE rather than at the first turn: a deployment that cannot inspect should be refused
    at the push, where the operator is looking at the console, not hours later on somebody's turn.
    """
    if not config.airs_api_key:
        raise GuardrailError("the AIRS guardrail is selected but no API key is stored")

    if not service.airs_profile_name:
        raise GuardrailError("the AIRS guardrail is selected but no profile name is set")

    active = service.active_points()
    _warn_about_switched_off(service, active)

    # Configured and not applied - see this module's TODO. Said on every build rather than once at
    # import, because the number an operator typed is in the document being built and this is the
    # line that sits beside it in the log.
    log.warning("service %s: airs_timeout_sec=%.1fs is not applied - the SDK's sync_scan takes no "
                "timeout, so a scan that hangs holds the turn", service.name,
                service.airs_timeout_sec)

    try:
        return ApiApplicationGuardrail(
            api_key=config.airs_api_key,
            endpoint=cfg.AIRS_ENDPOINT,
            profile_name=service.airs_profile_name,
            points=[Checkpoint(point) for point in active],
            timeout_sec=service.airs_timeout_sec,
        )
    except GuardrailError:
        raise
    except Exception as exc:                                        # noqa: BLE001
        # The SDK validates its own arguments and raises its own type. Whatever it says, a
        # guardrail that could not be constructed is a configuration this appliance refuses -
        # translated here so engine.py has one exception type to catch per axis.
        raise GuardrailError(f"the AIRS guardrail could not be built: {exc}") from exc


def _warn_about_switched_off(service: "cfg.ServiceConfig", active: tuple) -> None:
    """Only what an operator turned off, never what this deployment does not have.

    Warning about a point the service cannot serve - the two tool checkpoints on chat - would fire
    on every correct deployment, which is how a warning stops being read.
    """
    switched_off = []
    for point in service.available_points():
        if point not in active:
            switched_off.append(point)

    if not switched_off:
        return

    log.warning("service %s: checkpoints switched off: %s - these report NOT_INSPECTED rather "
                "than allowing", service.name, ", ".join(switched_off))
