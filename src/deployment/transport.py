"""Who serves the completion, built from one service's configuration.

One axis of the deployment, and only one. Which transport a turn goes out on - straight to the
vendor, or through the AI gateway - is decided by the caller in engine.py and asked for here by
name; this module does not read `service.guardrail` and must not start, because a second place
deriving the transport from the inspector is a second place for the two to disagree.

That separation is the point. The gateway transport and the AIRS guardrail are two fields, not
one: a customer on the direct transport who buys a guardrail is a different argument at the call
site, not a different function here.

    direct       each vendor called at its own endpoint, with its own key
    ai_gateway   the gateway serves it and routes upstream

Both implementations live in transport/. This module is only the part that reads a configuration
and decides what to hand them.
"""

import logging

from src.deployment import config as cfg
from src.transport.ai_gateway import AiGatewayTransport
from src.transport.direct import DirectTransport, Endpoint

log = logging.getLogger("pretzel-ai.deployment.transport")


class TransportError(Exception):
    """The configuration cannot produce a working transport. Raised at build time, never
    mid-turn."""


def direct(config: "cfg.Config", catalog, service: "cfg.ServiceConfig"):
    """Each vendor called at its own endpoint, with its own key."""
    endpoints = {}

    for provider in config.providers:
        if not provider.is_known():
            log.warning("provider %s is not one this service knows - skipped",
                        provider.provider_id)
            continue

        if not provider.api_key:
            log.warning("provider %s has no key - models on it will fail",
                        provider.provider_id)

        endpoints[provider.provider_id] = Endpoint(
            url=provider.endpoint(),
            api_key=provider.api_key,
        )

    if not endpoints:
        raise TransportError("no providers are configured")

    log.debug("transport (version=%s, service=%s, kind=direct, endpoints=[%s], timeout=%.1fs)",
              config.version or "none", service.name,
              ",".join(sorted(endpoints)), service.gateway_timeout_sec)

    return DirectTransport(
        endpoints,
        timeout_sec=service.gateway_timeout_sec,
        token_param_for=catalog.token_param,
        bare_model=_bare_model_for(catalog),
    )


def ai_gateway(service: "cfg.ServiceConfig", config: "cfg.Config", catalog):
    """The AI gateway serves the completion and routes it upstream.

    The endpoint is compiled in rather than configured, for the reason the provider endpoints are:
    which URL the hosted gateway is, is a fact about the gateway, and a console field for it only
    ever bought the chance to point "gateway" at something that is not one.
    """
    if not config.gateway_api_key:
        raise TransportError("the AI gateway is selected but no gateway API key is stored")

    log.debug("transport (version=%s, service=%s, kind=ai_gateway, base_url=%s, timeout=%.1fs, "
              "key=stored)",
              config.version or "none", service.name,
              cfg.GATEWAY_BASE_URL, service.gateway_timeout_sec)

    return AiGatewayTransport(
        cfg.GATEWAY_BASE_URL,
        config.gateway_api_key,
        timeout_sec=service.gateway_timeout_sec,
        token_param_for=catalog.token_param,
    )


def _bare_model_for(catalog):
    """The model name with its routing slug removed - what a vendor's own API expects.

    Taken from the catalog rather than split here, because the catalog is what knows which
    spellings name the same model.
    """
    def bare(model_id: str) -> str:
        entry = catalog.get(model_id)
        if entry is not None:
            return entry.bare

        # Not in the catalog. Split rather than refused: the transport is about to fail on the
        # model anyway, and it should fail saying the provider rejected it rather than here.
        return model_id.split("/", 1)[-1]

    return bare
