"""Who inspects a turn, built from one service's configuration.

The other axis, and only that one. This module never decides which transport serves the
completion - transport.py does, asked for by name in engine.py - so a guardrail can be added to a
deployment without moving its traffic, and a transport can be changed without changing who looks
at it.

    api_application   this appliance calls the Prisma AIRS scan API and holds the enforcement
                      point. Valid on EITHER transport         [not built - see below]
    (none)            nobody inspects. Expressed as None by the caller, not as a builder here

Reading a verdict off a completion an AI gateway already annotated used to be a third option here.
It is gone: what it bought was inspection this appliance could not describe, configure or report
on - the profile, the detectors and the thresholds all lived in someone else's console - and it
could not see tool calls at all, which is the surface the agent service exists for. The gateway is
a transport now, and nothing else.

The vocabulary a verdict speaks - Verdict, Decision, the four checkpoints - is not here. That
belongs with the implementations that produce it; this module reads a ServiceConfig and returns
the object it names.
"""

import logging

# from src.guardrail.airs import AirsGuardrail
# from src.guardrail.airs_client import AirsClient, AirsConfig
# from src.guardrail.gate import CheckpointGate
# from src.guardrail.gateway import GatewayGuardrail
from src.deployment import config as cfg

log = logging.getLogger("pretzel-ai.deployment.guardrail")


class GuardrailError(Exception):
    """The configuration names a guardrail that cannot be built. Raised at build time, never
    mid-turn."""


def api_application(service: "cfg.ServiceConfig", config: "cfg.Config"):
    """This appliance calls the Prisma AIRS scan API and holds the enforcement point.

    Refused rather than served uninspected. A service configured to be inspected must not come up
    as one that is not - that is the failure this codebase keeps finding in other people's
    deployments, and it is not going to be introduced here by a fallback.
    """
    raise GuardrailError("the AIRS guardrail is not built on this appliance yet")

    # if not config.airs_api_key:
    #     raise GuardrailError("the AIRS guardrail is selected but no API key is stored")
    #
    # if not service.airs_profile_name:
    #     raise GuardrailError("the AIRS guardrail is selected but no profile name is set")
    #
    # settings = AirsConfig(
    #     api_key=config.airs_api_key,
    #     endpoint=cfg.AIRS_ENDPOINT,
    #     profile_name=service.airs_profile_name,
    #     timeout_sec=service.airs_timeout_sec,
    #     fail_closed=not service.airs_fail_open,
    # )
    #
    # try:
    #     return _gated(AirsGuardrail(AirsClient(settings)), service)
    # except ValueError as exc:
    #     raise GuardrailError(str(exc)) from exc


# -- the checkpoints --------------------------------------------------------------------
#
# Wrapping whichever guardrail was built so the points this service does not run answer
# NOT_INSPECTED. Off does not mean allow: a closed point reports that nothing looked, which is
# what lets a scan report tell a clean pass from a gap.
#
# def _gated(inner, service: "cfg.ServiceConfig"):
#     active = service.active_points()
#     _warn_about_switched_off(service, active)
#
#     return CheckpointGate(
#         inner,
#         prompt=cfg.POINT_PROMPT in active,
#         response=cfg.POINT_RESPONSE in active,
#         tool_call=cfg.POINT_TOOL_CALL in active,
#         tool_result=cfg.POINT_TOOL_RESULT in active,
#     )
#
#
# def _warn_about_switched_off(service: "cfg.ServiceConfig", active: tuple) -> None:
#     """Only what an operator turned off, never what this deployment does not have. Warning
#     about a point the guardrail cannot serve would fire on every correct deployment, which is
#     how a warning stops being read."""
#     switched_off = []
#     for point in service.available_points():
#         if point not in active:
#             switched_off.append(point)
#
#     if not switched_off:
#         return
#
#     log.warning("service %s: checkpoints switched off: %s",
#                 service.name, ", ".join(switched_off))
