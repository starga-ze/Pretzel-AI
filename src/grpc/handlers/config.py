"""ApplyConfig — the deployment, pushed from the appliance.

The one RPC in the contract that is not a question. mgmtd states what the assistant is configured
to be: which vendors it holds an account with, which of their models may be asked for, and the
keys it unsealed for the purpose. The reply is an acknowledgement.

It is a push rather than a pull because pretzel-ai must never read the appliance's database. The
running config is engined's, the sealed credentials are opened by mgmtd, and a second reader here
with its own idea of "current" is how a console and a service start disagreeing about what is
deployed. So the appliance says it, and this applies it.

What it does NOT carry: the guardrail (route.guardrail and the `airs` block stay in this service's
own config.json, so an appliance changing which models it serves cannot — by an edit in a console,
or by a bug in one — change whether the turns are inspected); the endpoints (a fact about each
vendor, compiled in here); and the turn shape (system prompt, token cap, timeout — how THIS service
shapes a turn, not a statement the appliance makes about the operator's vendor accounts).
"""

import logging

from src.factory import ConfigError
from src.grpc import pretzel_ai_pb2

log = logging.getLogger("pretzel-ai")


def _document(request):
    """The protobuf request as the plain dict src.deployment.Deployment merges.

    Written out field by field rather than through MessageToDict because the two are not the same
    document: an absent `token_param` has to survive as an absence, and the conversion helpers
    differ on whether a proto3 default is a value or a missing field.
    """
    return {
        "version": int(request.version),
        "providers": [
            {
                "id": p.id,
                "api_key": p.api_key,
                "models": [
                    {"id": m.id, "label": m.label, "token_param": m.token_param}
                    for m in p.models
                ],
            }
            for p in request.providers
        ],
    }


class ConfigHandlers:
    """ApplyConfig. A mixin; PretzelAiServicer composes it with the generated base."""

    def ApplyConfig(self, request, context):
        document = _document(request)

        provs = document["providers"]
        # Counted, never logged. Which vendors are configured is operational information; the keys
        # are not, and neither are their lengths.
        log.info("ApplyConfig: version=%s, providers=%d (keyed=%d), models=%d",
                 document["version"] or "unknown", len(provs),
                 sum(1 for p in provs if p["api_key"]),
                 sum(len(p["models"]) for p in provs))

        try:
            self._deployment.apply(document)
        except ConfigError as exc:
            # A document that cannot produce an engine. The service keeps serving the one it had —
            # Deployment.apply builds before it swaps — so this is a refusal, not an outage.
            log.error("ApplyConfig refused: %s", exc)
            return pretzel_ai_pb2.ApplyConfigResult(ok=False, error=str(exc),
                                                    version=request.version)
        except Exception as exc:                    # noqa: BLE001 - reported to the appliance
            log.exception("ApplyConfig failed")
            return pretzel_ai_pb2.ApplyConfigResult(ok=False, error=str(exc),
                                                    version=request.version)

        engine = self._deployment.engine
        log.info("deployment applied: %s, models=%d (default %s)", engine.describes,
                 len(engine.catalog), engine.catalog.default or "none")
        return pretzel_ai_pb2.ApplyConfigResult(ok=True, version=request.version)
