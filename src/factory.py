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
from src.guardrail import Guardrail, NullGuardrail
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
    guardrail = _build_guardrail(guardrail_kind, config, route)

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
        key = credentials.key(gateway_cfg.get("id", "portkey"))
        if not key:
            raise ConfigError("route.llm='gateway' but no gateway credential is configured")
        return PortkeyTransport(_base_url(gateway_cfg), key, timeout_sec=timeout,
                                token_param_for=token_param,
                                extra_headers=gateway_cfg.get("headers") or {})

    endpoints = {}
    for slug, raw in (config.get("providers") or {}).items():
        key = str(raw.get("api_key", "")) or credentials.key(slug)
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


def _build_guardrail(kind: str, config: dict[str, Any], route: dict[str, Any]) -> Guardrail:
    if kind == "none":
        return NullGuardrail()
    if kind == "gateway":
        return GatewayGuardrail(
            require_guardrail=bool(route.get("require_guardrail", False)))

    raw = config.get("airs") or {}
    airs = AirsConfig(
        api_key=str(raw.get("api_key", "")),
        endpoint=str(raw.get("endpoint", "") or AirsConfig.endpoint),
        profile_name=str(raw.get("profile_name", "")),
        profile_id=str(raw.get("profile_id", "")),
        timeout_sec=float(raw.get("timeout_sec", 30)),
        fail_closed=not bool(raw.get("fail_open", False)))
    try:
        return AirsGuardrail(AirsClient(airs))
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc


def _base_url(gateway_cfg: dict[str, Any]) -> str:
    """The gateway's base, with the SDK-owned path suffix removed.

    The config names a full completions path because that is what the operator pastes from the
    vendor's docs; the SDK owns "/chat/completions" and wants everything before it.
    """
    scheme = "https" if gateway_cfg.get("tls", True) else "http"
    host = gateway_cfg.get("host", "")
    port = gateway_cfg.get("port", 443)
    path = str(gateway_cfg.get("path", "/v1/chat/completions"))
    suffix = "/chat/completions"
    if path.endswith(suffix):
        path = path[: -len(suffix)]
    return f"{scheme}://{host}:{port}{path}"
