"""The engine that runs a turn, assembled from one service's configuration.

An engine is three things held together:

    catalog     which models may be asked for
    transport   who serves the completion - the vendor directly, or the AI gateway
    guardrail   who inspects it, and at which points

Each has its own builder and its own module - catalog.py, transport.py, guardrail.py - and
_build_route pairs them. Which pair a configuration means is read there and nowhere else.

The transport and the inspector arrive as two independent fields and are built by two functions
that read one field each, so every meaningful combination of them is expressible. What is not built
is either INSPECTOR: both guardrail builders refuse, so a configuration that named one is
refused and `guardrail` here is None only when the document said "none".

Two scopes, and they are not the same
-------------------------------------
The catalog is appliance-wide: which models exist follows from the accounts wired up behind
the providers, and both services see the same ones. Everything else is one service's, and
mgmtd sends it as that service's own document - which is why the two builders below take a
ServiceConfig each and read different fields out of it.

One builder per service, not one builder that asks which service it is
----------------------------------------------------------------------
Only chat is built today; agent is refused. Keeping them as two functions rather than one that
branches is what makes that difference a line an operator can read in a log - and it is where
an agent built on a real framework attaches, without chat being touched to make room.

Nothing downstream - not a handler, not the servicer - may ask which route this service
runs, because a second place that decided it would drift from this one.
"""

import logging

from src.deployment import config as cfg
from src.deployment import guardrail as guardrail_builder
from src.deployment import transport as transport_builder
from src.deployment.catalog import Catalog
from src.engine.chat import ChatEngine

log = logging.getLogger("pretzel-ai.deployment.engine")


class EngineError(Exception):
    """The configuration cannot produce a working engine. Raised at build time, never
    mid-turn."""


class ServiceNotBuilt(EngineError):
    """This appliance does not implement the service at all, whatever the document says.

    Apart from EngineError because the two are different answers to an operator. A configuration
    that names a guardrail with no key is WRONG and the push is refused so they fix it; a service
    this build simply does not have is not wrong, and refusing the document over it would take the
    services that DO work down with it - one console page saving an agent config would stop chat.

    A subclass so a caller that only cares "no engine came back" still catches EngineError.
    """


# -- one per service --------------------------------------------------------------------


def build_chat_engine(service: "cfg.ServiceConfig", config: "cfg.Config") -> ChatEngine:
    """One model call per turn. The only engine this appliance builds."""
    catalog = _build_catalog(service, config)
    transport, guardrail = _build_route(service, config, catalog)

    engine = ChatEngine(
        transport,
        guardrail,              # None when nothing inspects
        catalog,
        system_prompt=service.system_prompt,
        max_tokens=service.max_tokens,
        fail_open=service.airs_fail_open,
    )

    # The system prompt is reported as set/none and never printed: it is operator text, and the
    # rule that keeps it out of an INFO line keeps it out of a DEBUG one that runs on every build.
    log.debug("engine (version=%s, service=%s, class=%s, system_prompt=%s, max_tokens=%d, "
              "fail_open=%s)",
              config.version or "none", service.name, type(engine).__name__,
              "set" if service.system_prompt else "none",
              service.max_tokens, service.airs_fail_open)

    # The line that says this service is up is service.py's, not this module's. It used to be here
    # too, so every successful build wrote two - and the one over there is the only one that can
    # also speak for a service that did NOT build.
    return engine


def build_agent_engine(service: "cfg.ServiceConfig", config: "cfg.Config"):
    """Refused, not built. There is no agent engine.

    The hand-rolled loop that used to be here offered a model tools, scanned each call, ran them
    and fed the results back - and never ran one, because no tool runtime was ever wired up. It is
    gone rather than kept warm: an agent loop belongs on a framework that already has one, and
    half of an unused one is a thing to keep honest for no return.

    Refused rather than quietly served as a chat engine, on the same terms a configuration naming
    an unbuilt guardrail is refused: a service configured to loop must not come up as one that
    answers in a single call and says nothing about the difference.

    When it is built it takes the same route as chat - _build_route below - and differs only in
    what runs the turn.
    """
    raise ServiceNotBuilt("the agent service is not built on this appliance yet")

    # catalog = _build_catalog(service, config)
    # transport, guardrail = _build_route(service, config, catalog)
    # return AgentEngine(transport, guardrail, catalog, ...)


# -- the deployment matrix ----------------------------------------------------------------


def _build_route(service: "cfg.ServiceConfig", config: "cfg.Config", catalog: Catalog):
    """→ (transport, guardrail). The deployment matrix, and the only place it is read.

    TWO axes, arriving as two fields and answered on their own by the module that owns each. This
    function only pairs them:

        transport    direct | ai_gateway            -> deployment/transport.py
        guardrail    none | api_application         -> deployment/guardrail.py

    They multiply out cleanly - four pairs, all four meaningful - because neither constrains the
    other. Scanning is done HERE from the turn itself, so it reaches all four checkpoints on either
    transport; the gateway is a route and nothing more.

    `guardrail` is None when nothing inspects. A caller must not read that as permission: it means
    no verdict exists, which reaches the console as scan.present=false and is drawn there as
    "uninspected" rather than as a pass.

    Both builders' failures are the configuration's failures, so they are reported as this
    module's: the caller asked for an engine and did not get one, and which axis was missing is a
    detail of the message rather than of the exception type.
    """
    try:
        transport = _build_transport(service, config, catalog)
        guardrail = _build_guardrail(service, config)
    except (transport_builder.TransportError, guardrail_builder.GuardrailError) as exc:
        raise EngineError(str(exc)) from exc

    return transport, guardrail


def _build_transport(service: "cfg.ServiceConfig", config: "cfg.Config", catalog: Catalog):
    """Which transport carries the completion. Reads `service.transport` and nothing else.

    An unrecognised value is refused here rather than defaulted in config.py - see _read_route for
    why nothing on either axis is guessed.
    """
    if service.transport == cfg.TRANSPORT_DIRECT:
        return transport_builder.direct(config, catalog, service)

    if service.transport == cfg.TRANSPORT_AI_GATEWAY:
        return transport_builder.ai_gateway(service, config, catalog)

    raise EngineError("unknown transport: '%s' - expected one of %s"
                      % (service.transport, ", ".join(cfg.TRANSPORTS)))


def _build_guardrail(service: "cfg.ServiceConfig", config: "cfg.Config"):
    """Who inspects the turn. Reads `service.guardrail` and nothing else.

    → None when nothing does. The `none` row is logged here rather than in guardrail.py because
    that module has no builder for it: there is no object to construct, and a builder that
    returned None would exist only to have somewhere to put this line.
    """
    if service.guardrail == cfg.GUARDRAIL_NONE:
        log.debug("guardrail (version=%s, service=%s, kind=none, checkpoints=[], "
                  "note=nothing is asked, every turn reports NOT_INSPECTED)",
                  config.version or "none", service.name)
        return None

    if service.guardrail == cfg.GUARDRAIL_API_APPLICATION:
        return guardrail_builder.api_application(service, config)

    raise EngineError("unknown guardrail: '%s' - expected one of %s"
                      % (service.guardrail, ", ".join(cfg.GUARDRAILS)))


def _build_catalog(service: "cfg.ServiceConfig", config: "cfg.Config") -> Catalog:
    """Which models may be asked for, and which one a conversation opens on.

    Appliance-wide, and read from Config rather than from a ServiceConfig: the two services
    hold no separate accounts, so a per-service catalog would only be a way for them to
    disagree about what exists.

    An engine with no models cannot serve a turn, so this is where a configuration that
    named no vendors stops being usable.
    """
    models = config.qualified_models()

    if not models:
        raise EngineError("no models are configured")

    # The catalog opens on whatever it starts with. Which model a conversation uses is the
    # console's choice per conversation; this is only what it starts from.
    catalog = Catalog(models, default=models[0]["id"])

    providers = []
    for provider in config.providers:
        providers.append(provider.provider_id)

    log.debug("catalog (version=%s, service=%s, models=%d, default=%s, providers=[%s])",
              config.version or "none", service.name, len(catalog),
              catalog.default or "none", ",".join(providers) or "none")
    return catalog
