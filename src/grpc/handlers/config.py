"""ApplyConfig — the deployment, pushed from the appliance.

The one RPC in the contract that is not a question. mgmtd states what the assistant is configured
to be: which vendors it holds an account with, which of their models may be asked for, and the
keys it unsealed for the purpose. The reply is an acknowledgement.

It is a push rather than a pull because pretzel-ai must never read the appliance's database. The
running config is engined's, the sealed credentials are opened by mgmtd, and a second reader here
with its own idea of "current" is how a console and a service start disagreeing about what is
deployed. So the appliance says it, and this applies it.

It carries the guardrail now, and it did not use to. That block lived in this service's own
config.json on the argument that an appliance changing which models it serves must not be able to
change whether the turns are inspected. The file is gone: what that argument bought was a guardrail
nobody could reconfigure without editing a file on the appliance and restarting the service, and
what replaces it is that every change here is a committed, versioned running_config edit a reviewer
sees in the diff.

It carries one entry per engine — chat and agent — because the two are configured apart: agent has
two checkpoints chat does not have, and the AI gateway can see neither of them.

What it still does NOT carry: the endpoints. The vendors', the scan service's and the gateway's are
each a fact about the thing being called, and all three are compiled in here.
"""

import logging

from src.deployment.config import Config, ConfigRefused
from src.grpc import pretzel_ai_pb2

log = logging.getLogger("pretzel-ai")


def _service(entry):
    """One ServiceConfig as the plain dict src.deployment.Deployment merges."""
    cp = entry.checkpoints
    return {
        "service": entry.service,
        "transport": entry.transport,
        "guardrail": entry.guardrail,
        "checkpoints": {
            "prompt": cp.prompt,
            "response": cp.response,
            "tool_call": cp.tool_call,
            "tool_result": cp.tool_result,
        },
        "airs_profile_name": entry.airs_profile_name,
        "airs_timeout_sec": entry.airs_timeout_sec,
        "airs_fail_open": entry.airs_fail_open,
        "gateway_timeout_sec": entry.gateway_timeout_sec,
        "system_prompt": entry.system_prompt,
        "max_tokens": entry.max_tokens,
    }


def _document(request):
    """The protobuf request as the plain dict src.deployment.Deployment merges.

    Written out field by field rather than through MessageToDict because the two are not the same
    document: an absent `token_param` has to survive as an absence, and the conversion helpers
    differ on whether a proto3 default is a value or a missing field.

    Every field, always — mgmtd writes every field on every push for the same reason, and a dict
    built by picking out the non-defaults would reintroduce exactly the ambiguity the two sides
    agreed to avoid.
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
        "services": [_service(s) for s in request.services],
        "airs_api_key": request.airs_api_key,
        "gateway_api_key": request.gateway_api_key,
    }


def _shape(service: dict) -> str:
    """One service, as the ApplyConfig line reports it.

    Counted and named, never valued. Which vendors are configured, which transport they are called
    on and which checkpoints are live is operational information; the keys are not, and neither
    are their lengths.

    The transport is here because it is now its own field and a line naming only the guardrail
    could no longer say which path the turns take. The AIRS profile is here because it is the OTHER thing
    an api_application service refuses to build without - a document that named the guardrail and
    left the profile empty produced a refusal this line gave no way to see coming.
    """
    live = []
    for field, label in (("prompt", "prompt"), ("response", "response"),
                         ("tool_call", "tool-call"), ("tool_result", "tool-result")):
        if service["checkpoints"][field]:
            live.append(label)

    line = "%s=%s/%s(%s)" % (
        service["service"] or "?",
        service["transport"] or "unset",
        service["guardrail"] or "?",
        "+".join(live) or "none",
    )

    # Named only where it is read, so the line does not invite an operator to wonder why a
    # deployment that never scans here is reporting a profile.
    if service["guardrail"] == "api_application":
        line += " profile=%s" % (service["airs_profile_name"] or "UNSET")

    return line


class ConfigHandlers:
    """ApplyConfig. A mixin; PretzelAiServicer composes it with the generated base."""

    def ApplyConfig(self, request, context):
        document = _document(request)

        provs = document["providers"]
        shape = ", ".join(_shape(s) for s in document["services"])
        log.info("ApplyConfig: version=%s, providers=%d (keyed=%d), models=%d, services=[%s], "
                 "airs_key=%s, gateway_key=%s",
                 document["version"] or "unknown", len(provs),
                 sum(1 for p in provs if p["api_key"]),
                 sum(len(p["models"]) for p in provs),
                 shape or "none configured",
                 "stored" if document["airs_api_key"] else "none",
                 "stored" if document["gateway_api_key"] else "none")

        try:
            self.apply_config(Config.from_document(document))
        except ConfigRefused as exc:
            # A document that cannot produce engines. The service keeps serving the ones it had —
            # Core.apply_config builds before it swaps — so this is a refusal, not an outage.
            log.error("ApplyConfig refused: %s", exc)
            return pretzel_ai_pb2.ApplyConfigResult(ok=False, error=str(exc),
                                                    version=request.version)
        except Exception as exc:                    # noqa: BLE001 - reported to the appliance
            log.exception("ApplyConfig failed")
            return pretzel_ai_pb2.ApplyConfigResult(ok=False, error=str(exc),
                                                    version=request.version)

        # What became of each service is NOT reported here. Services.build writes one line per
        # service as it builds them - with the version on it, which this loop could not have had -
        # so repeating it after the fact only made every push say the same thing twice.
        return pretzel_ai_pb2.ApplyConfigResult(ok=True, version=request.version)
