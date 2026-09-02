"""The engine that runs a turn, assembled from one service's configuration.

An engine is three things held together:

    catalog     which models may be asked for
    transport   who serves the completion - the vendor directly, or the AI gateway
    guardrail   who inspects it, and at which points

Each has its own builder and its own module - catalog.py, transport.py, guardrail.py - and
_build_route pairs them. Which pair a configuration means is read there and nowhere else.

Only the direct path is built today, so the guardrail half of that pair is None. What the
engine does with that is the engine's to say - guardrail.py refuses any configuration that
named an inspector, so None here can only ever mean "this deployment has none".

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
    catalog = _build_catalog(config)
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
    log.debug("[4/5] engine (class=%s, service=%s, system_prompt=%s, max_tokens=%d, "
              "fail_open=%s)",
              type(engine).__name__, service.name,
              "set" if service.system_prompt else "none",
              service.max_tokens, service.airs_fail_open)

    log.info("service %s ready: %s", service.name, engine.describes)
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

    # catalog = _build_catalog(config)
    # transport, guardrail = _build_route(service, config, catalog)
    # return AgentEngine(transport, guardrail, catalog, ...)


# -- the deployment matrix ----------------------------------------------------------------


def _build_route(service: "cfg.ServiceConfig", config: "cfg.Config", catalog: Catalog):
    """→ (transport, guardrail). The deployment matrix, and the only place it is read.

    TWO axes, written out as pairs rather than derived from each other. One console field picks
    the row today - `service.guardrail` - and that is a fact about the console, not about the
    appliance: the leg a turn goes out on and the thing that inspects it are separate questions
    with separate answers, built by separate modules.

        none              direct  + nothing        how a customer with no guardrail runs
        api_application   direct  + AIRS           the appliance holds the enforcement point
        ai_gateway        gateway + its verdict    what a gateway deployment looks like

    The row that is NOT here is the one this shape exists to keep reachable: gateway + AIRS - the
    gateway for its routing, the scanning done here. Adding it is one arm below, calling two
    builders that already exist, and nothing else moves.

    `guardrail` is None when nothing inspects. A caller must not read that as permission: it means
    no verdict exists, which reaches the console as scan.present=false and is drawn there as
    "uninspected" rather than as a pass.

    Both builders' failures are the configuration's failures, so they are reported as this
    module's: the caller asked for an engine and did not get one, and which axis was missing is a
    detail of the message rather than of the exception type.
    """
    kind = service.guardrail

    try:
        if kind == cfg.GUARDRAIL_NONE:
            transport = transport_builder.direct(config, catalog, service)
            log.debug("[3/5] guardrail (kind=none, checkpoints=[], "
                      "note=nothing is asked, every turn reports NOT_INSPECTED)")
            return transport, None

        if kind == cfg.GUARDRAIL_API_APPLICATION:
            return (transport_builder.direct(config, catalog, service),
                    guardrail_builder.api_application(service, config))

        if kind == cfg.GUARDRAIL_AI_GATEWAY:
            return (transport_builder.ai_gateway(service, config, catalog),
                    guardrail_builder.ai_gateway(service))

    except (transport_builder.TransportError, guardrail_builder.GuardrailError) as exc:
        raise EngineError(str(exc)) from exc

    raise EngineError("unknown guardrail: " + str(kind))


def _build_catalog(config: "cfg.Config") -> Catalog:
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

    log.debug("[1/5] catalog (models=%d, default=%s, providers=[%s])",
              len(catalog), catalog.default or "none", ",".join(providers) or "none")
    return catalog
