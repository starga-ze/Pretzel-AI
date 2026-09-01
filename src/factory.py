"""Config in, ChatEngine out — the one place the deployment matrix is decided.

Two independent axes, not three routes:

    route.llm        who serves the completion    gateway | direct
    route.guardrail  who inspects                 gateway | airs | none

The guardrail values say who OWNS the decision, not how a verdict travels:

    gateway   the AI gateway's own configuration governs it. This appliance scans nothing and
              reports whatever came back — including "nothing was configured over there", which
              is a real answer and the one you want while the gateway is the thing under test.
    airs      this appliance calls the scan API itself and holds the enforcement point.
    none      nobody inspects. A deployment, written down rather than left as an absence.

Every combination is something someone runs, and each is a line of config rather than a branch:

    gateway + gateway   what this appliance shipped with, and how you test a gateway
    direct  + airs      the target: the appliance holds the enforcement point
    direct  + none      how customers run with no guardrail deployed at all
    gateway + airs      gateway for routing and observability, scanning done here
    gateway + none      routing only

Keeping them orthogonal is what makes the fourth row expressible. Treating them as one enum would
have made "use the gateway but do our own scanning" unrepresentable, and that is the row the
agent work needs — the gateway's inline hook cannot see a tool call, and moving the LLM leg is a
separate decision from moving the inspection.
"""

from __future__ import annotations

import logging
from typing import Any

from src.airs.client import AirsClient, AirsConfig
from src.airs.gateway import GatewayGuardrail
from src.airs.scan import AirsGuardrail
from src.chat.engine import ChatEngine, ToolRuntime
from src.guardrail import CheckpointGate, Guardrail, NullGuardrail
from src.llm.catalog import Catalog
from src.llm.direct import DirectTransport, Endpoint
from src.llm.portkey import PortkeyTransport
from src.llm.transport import LlmTransport

log = logging.getLogger("pretzel-ai")

LLM_LEGS = ("gateway", "direct")
GUARDRAILS = ("gateway", "airs", "none")


class ConfigError(ValueError):
    """The configuration cannot produce a working engine. Raised at startup, never mid-turn."""


def build_engine(config: dict[str, Any], credentials, *,
                 tools: ToolRuntime | None = None) -> ChatEngine:
    """Assemble the engine this appliance is configured to run."""
    gateway_cfg = config.get("gateway") or {}
    route = config.get("route") or {}

    catalog = Catalog(gateway_cfg.get("models") or [], gateway_cfg.get("default_model", ""))
    if not len(catalog):
        raise ConfigError("no models are configured")

    llm_leg = str(route.get("llm", "gateway")).lower()
    guardrail_kind = str(route.get("guardrail", "gateway")).lower()
    if llm_leg not in LLM_LEGS:
        raise ConfigError(f"route.llm must be one of {LLM_LEGS}, got '{llm_leg}'")
    if guardrail_kind not in GUARDRAILS:
        raise ConfigError(f"route.guardrail must be one of {GUARDRAILS}, got '{guardrail_kind}'")

    transport = _build_transport(llm_leg, gateway_cfg, config, credentials, catalog)
    guardrail = _build_guardrail(guardrail_kind, config, route, credentials)

    # Deployments that cannot inspect what they route. Not refused — both are real, and one of
    # them is how most customers run today — but never silent.
    if guardrail_kind == "none":
        log.warning("no guardrail is configured: turns on this appliance are not inspected")
    elif guardrail_kind == "gateway" and llm_leg == "direct":
        raise ConfigError("route.guardrail='gateway' needs route.llm='gateway' — there is no "
                          "gateway on this path to defer to")
    elif guardrail_kind == "gateway" and not route.get("require_guardrail", False):
        # Deferring is the point of this mode, so it is not refused — but an operator reading the
        # log should know that nothing here guarantees a guardrail ran.
        log.info("guardrail delegated to the gateway's own configuration; set "
                 "route.require_guardrail to fail turns it did not inspect")

    engine = ChatEngine(
        transport, guardrail, catalog,
        system_prompt=gateway_cfg.get("system_prompt", ""),
        max_tokens=int(gateway_cfg.get("max_tokens", 4096)),
        fail_open=bool((config.get("airs") or {}).get("fail_open", False)),
        tools=tools)
    log.info("chat engine: %s", engine.describes)
    return engine


def _build_transport(leg: str, gateway_cfg: dict[str, Any], config: dict[str, Any],
                     credentials, catalog: Catalog) -> LlmTransport:
    timeout = float(gateway_cfg.get("timeout_sec", 45))
    token_param = catalog.token_param

    if leg == "gateway":
        key = credentials.key("portkey")
        if not key:
            raise ConfigError("the AI gateway is selected but no gateway API key is stored")
        return PortkeyTransport(GATEWAY_BASE_URL, key, timeout_sec=timeout,
                                token_param_for=token_param)

    endpoints = {}
    for slug, raw in (config.get("providers") or {}).items():
        # The key comes from `credentials` and nowhere else. It used to be readable off the
        # provider entry too, back when that entry was a block someone hand-wrote in config.json;
        # a deployment document that carried it in two places was two places to look when the
        # wrong one was in use.
        key = credentials.key(slug)
        if not key:
            log.warning("provider '%s' has no key configured — models on it will fail", slug)
        endpoints[slug] = Endpoint(
            url=str(raw["url"]),
            api_key=key,
            auth_header=str(raw.get("auth_header", "Authorization")),
            auth_prefix=str(raw.get("auth_prefix", "Bearer ")),
            headers=dict(raw.get("headers") or {}))
    if not endpoints:
        raise ConfigError("route.llm='direct' but no `providers` are configured")

    def bare(model_id: str) -> str:
        entry = catalog.get(model_id)
        return entry.bare if entry else model_id.split("/", 1)[-1]

    return DirectTransport(endpoints, timeout_sec=timeout,
                           token_param_for=token_param, bare_model=bare)


def _build_guardrail(kind: str, config: dict[str, Any], route: dict[str, Any],
                     credentials) -> Guardrail:
    raw = config.get("airs") or {}
    inner = _guardrail_kind(kind, raw, route, credentials)

    # Nothing to gate. NullGuardrail already answers NOT_INSPECTED at all four, and wrapping it
    # would produce a second warning saying the same thing as the one build_engine already logs.
    if kind == "none":
        return inner

    # The four checkpoints, each its own switch. Applied to the gateway as well as to AIRS:
    # "gateway, but do not defer the response checkpoint to it" is as real a deployment as the
    # AIRS equivalent.
    points = raw.get("checkpoints") or {}
    gate = CheckpointGate(
        inner,
        prompt=bool(points.get("prompt", True)),
        response=bool(points.get("response", True)),
        tool_call=bool(points.get("tool_call", True)),
        tool_result=bool(points.get("tool_result", True)))

    # Only what an operator turned off, never what this deployment does not have. Chat has no tool
    # checkpoints and the gateway cannot see them; warning about those would fire on every correct
    # deployment, which is how a warning stops being read. `checkpoints_available` is set by
    # src/deployment.py, which is where the intersection is worked out.
    available = raw.get("checkpoints_available")
    if available is None:
        available = ("prompt", "response", "tool_call", "tool_result")
    off = [n for n in available if not bool(points.get(n, True))]
    if off:
        # Worth a line of its own: a checkpoint that is off produces no findings, and a report
        # that does not say which were live reads the same as one where nothing was found.
        log.warning("guardrail checkpoints switched off: %s — turns are not inspected at %s",
                    ", ".join(off), "those points" if len(off) > 1 else "that point")
    return gate


def _guardrail_kind(kind: str, raw: dict[str, Any], route: dict[str, Any],
                    credentials) -> Guardrail:
    if kind == "none":
        return NullGuardrail()
    if kind == "gateway":
        return GatewayGuardrail(
            require_guardrail=bool(route.get("require_guardrail", False)))

    airs = AirsConfig(
        # Same rule as a vendor key: it is resolved once, into `credentials`, and read from there.
        api_key=credentials.key("airs"),
        endpoint=str(raw.get("endpoint", "") or AirsConfig.endpoint),
        profile_name=str(raw.get("profile_name", "")),
        profile_id=str(raw.get("profile_id", "")),
        timeout_sec=float(raw.get("timeout_sec", 30)),
        fail_closed=not bool(raw.get("fail_open", False)))
    try:
        return AirsGuardrail(AirsClient(airs))
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc


# The hosted AI gateway, compiled in for the same reason the vendors' endpoints are: which URL it
# is, is a fact about the service rather than a setting, and a console field for it only ever bought
# the chance to point "the gateway" at something that is not it. The SDK owns the
# "/chat/completions" suffix and wants everything before it, which is why this stops at /v1.
#
# A self-hosted gateway would be a change here — it needs this transport to speak its dialect
# anyway, and it has never been a deployment this appliance shipped for.
GATEWAY_BASE_URL = "https://aigw.portkey.ai:443/v1"
