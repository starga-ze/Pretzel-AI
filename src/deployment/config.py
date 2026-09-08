"""The configuration, as plain data.

The appliance decides what this daemon runs and pushes it over ApplyConfig. This module is
where that document stops being protobuf and becomes objects the rest of the code reads. It
builds nothing and calls nothing - engine.py and guardrail.py do that.

Three levels, and they are separate on purpose:

    Config          the whole document: providers, services, keys, version
    ServiceConfig   one engine's settings. There is one per service.
    ProviderConfig  one vendor: which models, and the key to call them with
"""

import enum
import json
import logging
import os
import tempfile
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger("pretzel-ai.deployment.config")


class ConfigRefused(Exception):
    """A pushed configuration that cannot serve.

    Lives here rather than in core.py because the handler that reports the refusal has to
    import it, and core.py imports the handlers - the other way round is a cycle. It is a
    fact about a configuration, so this is where it belongs anyway.
    """

# Where the last pushed document is cached, so a restart does not leave the daemon mute
# until the appliance pushes again. It holds keys in the clear, so it is 0600 and lives
# beside keys.env rather than in the repo.
CACHE_PATH = os.environ.get("PZ_PRETZEL_AI_STATE", "/etc/pretzel-ai/deployment.json")

# The services this daemon runs. Fixed: each is a different code path here, and a third
# name arriving in a document would configure nothing.
#
# An enum rather than two strings, because every caller that asks for an engine has to name
# one of these and a bare string lets a typo through as a quiet None. A `str` at heart so the
# pushed document's "chat" and ServiceType.CHAT are the same dictionary key - the wire stays
# strings and nothing has to translate at the boundary.
class ServiceType(str, enum.Enum):
    CHAT = "chat"
    AGENT = "agent"

    @classmethod
    def of(cls, name: str):
        """The member this name means, or the name itself when it means none of them.

        Returned rather than raised: this reads a document the appliance sent, and a service
        it invented is dropped by from_document's filter instead of failing the whole push.
        """
        try:
            return cls(name)
        except ValueError:
            return name

    def __str__(self) -> str:
        return self.value


CHAT = ServiceType.CHAT
AGENT = ServiceType.AGENT
SERVICES = tuple(ServiceType)

# Which transport serves the completion. One of the two axes of a deployment, and named for the
# thing that carries it: transport/ holds the implementations, deployment/transport.py builds one,
# and this is the field that says which. One word for one concept, all the way down.
TRANSPORT_DIRECT = "direct"
TRANSPORT_AI_GATEWAY = "ai_gateway"
TRANSPORTS = (TRANSPORT_DIRECT, TRANSPORT_AI_GATEWAY)

# Who inspects a turn. The other axis, and fully independent of the first: api_application runs on
# either transport, so the two multiply out with no unreachable pair between them.
GUARDRAIL_NONE = "none"
GUARDRAIL_API_APPLICATION = "api_application"
GUARDRAILS = (GUARDRAIL_NONE, GUARDRAIL_API_APPLICATION)

# The four points in a turn where something can be looked at.
POINT_PROMPT = "prompt"
POINT_RESPONSE = "response"
POINT_TOOL_CALL = "tool_call"
POINT_TOOL_RESULT = "tool_result"
POINTS = (POINT_PROMPT, POINT_RESPONSE, POINT_TOOL_CALL, POINT_TOOL_RESULT)

# What each service can be asked about at all. Chat has no tools, so two of the four points
# are not "off" for it - they do not exist.
SERVICE_POINTS = {
    CHAT: (POINT_PROMPT, POINT_RESPONSE),
    AGENT: (POINT_PROMPT, POINT_RESPONSE, POINT_TOOL_CALL, POINT_TOOL_RESULT),
}

# What each guardrail can serve. Keyed by the inspector alone and not by the transport, which is
# what makes the two axes orthogonal: scanning here reaches all four points whichever transport
# carries the completion, because the scan request is built HERE from the turn rather than by
# something reading a completion document after the fact.
#
# Which of the four a SERVICE then has is its own answer - see SERVICE_POINTS. Chat has no tools,
# so it reaches two of these however the guardrail is configured.
GUARDRAIL_POINTS = {
    GUARDRAIL_NONE: (),
    GUARDRAIL_API_APPLICATION: POINTS,
}

# Where each vendor answers. Compiled in rather than configured: which URL it is, is a fact
# about the vendor, and a console field for it only buys the chance to get it wrong.
PROVIDER_ENDPOINTS = {
    "openai": "https://api.openai.com/v1/chat/completions",
    "google": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
    "anthropic": "https://api.anthropic.com/v1/chat/completions",
}

# The scan service and the gateway, for the same reason.
AIRS_ENDPOINT = "https://service.api.aisecurity.paloaltonetworks.com"
GATEWAY_BASE_URL = "https://aigw.portkey.ai:443/v1"

DEFAULT_MAX_TOKENS = 4096
DEFAULT_AIRS_TIMEOUT_SEC = 30.0
DEFAULT_GATEWAY_TIMEOUT_SEC = 45.0


@dataclass
class ModelConfig:
    """One model a vendor may be asked for."""

    model_id: str = ""          # bare name, as the vendor knows it
    label: str = ""
    token_param: str = ""       # which name the output cap goes out under, when it differs


@dataclass
class ProviderConfig:
    """One vendor this appliance holds an account with."""

    provider_id: str = ""       # "openai" | "google" | "anthropic"
    api_key: str = ""
    models: list = field(default_factory=list)      # list[ModelConfig]

    def endpoint(self) -> str:
        return PROVIDER_ENDPOINTS.get(self.provider_id, "")

    def is_known(self) -> bool:
        return self.provider_id in PROVIDER_ENDPOINTS


@dataclass
class ServiceConfig:
    """One service's settings. There is one of these per entry in SERVICES.

    Everything here is per service and arrives as its own document: mgmtd sends a list, one
    entry per service, and the two are configured independently on the console. What is NOT
    here is the model catalog - which models exist is a fact about the appliance's accounts,
    lives on Config, and is the same for both services.
    """

    name: "ServiceType | str" = CHAT

    # The two axes, held apart. Read as a pair by deployment/engine.py and by nothing else.
    transport: str = TRANSPORT_DIRECT
    guardrail: str = GUARDRAIL_NONE

    # What the operator asked for. Not what will run - see active_points().
    points: dict = field(default_factory=dict)      # dict[str, bool]

    airs_profile_name: str = ""
    airs_timeout_sec: float = DEFAULT_AIRS_TIMEOUT_SEC
    airs_fail_open: bool = False

    gateway_timeout_sec: float = DEFAULT_GATEWAY_TIMEOUT_SEC

    system_prompt: str = ""
    max_tokens: int = DEFAULT_MAX_TOKENS

    def available_points(self) -> tuple:
        """The points this service and this guardrail can both serve."""
        by_service = SERVICE_POINTS.get(self.name, ())
        by_guardrail = GUARDRAIL_POINTS.get(self.guardrail, ())

        available = []
        for point in POINTS:
            if point in by_service and point in by_guardrail:
                available.append(point)
        return tuple(available)

    def active_points(self) -> tuple:
        """Where all three agree: the operator asked, the service has it, the guardrail
        can serve it.

        Intersected here rather than trusted from the console, because the console is not
        the only thing that can send an ApplyConfig - and a point the engine cannot honour
        must not be recorded as one it will.
        """
        active = []
        for point in self.available_points():
            if self.points.get(point, True):
                active.append(point)
        return tuple(active)

    def uses_gateway(self) -> bool:
        """Whether the completion goes through the AI gateway rather than to the vendor.

        Reads the transport. It used to read the guardrail, which was true only because one field
        said both things - and the reason a caller asks this is never "who inspects".
        """
        return self.transport == TRANSPORT_AI_GATEWAY


@dataclass
class Config:
    """Everything the appliance said, and the version it said it at."""

    version: int = 0
    providers: list = field(default_factory=list)   # list[ProviderConfig]
    services: dict = field(default_factory=dict)    # dict[str, ServiceConfig]

    # Appliance-wide, not per service: there is one AIRS account and one gateway account.
    airs_api_key: str = ""
    gateway_api_key: str = ""

    # -- questions the rest of the code asks ------------------------------------------

    def is_empty(self) -> bool:
        return self.version == 0 and not self.providers

    def service(self, service_type: "ServiceType") -> Optional[ServiceConfig]:
        return self.services.get(service_type)

    def keyed_providers(self) -> list:
        """The vendors that can actually serve a turn."""
        keyed = []
        for provider in self.providers:
            if provider.is_known() and provider.api_key:
                keyed.append(provider)
        return keyed

    def qualified_models(self) -> list:
        """Every model, as "<provider>/<model>". The provider half is what selects the
        endpoint; the vendor itself is sent the bare name."""
        models = []
        for provider in self.providers:
            if not provider.is_known():
                continue
            for model in provider.models:
                models.append({
                    "id": provider.provider_id + "/" + model.model_id,
                    "label": model.label or model.model_id,
                    "token_param": model.token_param,
                })
        return models

    # -- coming in from the appliance --------------------------------------------------

    @classmethod
    def from_document(cls, document: dict) -> "Config":
        """The pushed document as objects. Unknown fields are ignored; missing ones take
        their defaults."""
        config = cls()
        config.version = int(document.get("version") or 0)
        config.airs_api_key = document.get("airs_api_key") or ""
        config.gateway_api_key = document.get("gateway_api_key") or ""

        for raw in document.get("providers") or []:
            config.providers.append(_provider_from(raw))

        for raw in document.get("services") or []:
            service = _service_from(raw)
            if service.name in SERVICES:
                config.services[service.name] = service

        return config

    def to_document(self) -> dict:
        """The inverse, for the disk cache. Same shape the appliance sends."""
        providers = []
        for provider in self.providers:
            models = []
            for model in provider.models:
                models.append({
                    "id": model.model_id,
                    "label": model.label,
                    "token_param": model.token_param,
                })
            providers.append({
                "id": provider.provider_id,
                "api_key": provider.api_key,
                "models": models,
            })

        services = []
        for service in self.services.values():
            services.append({
                "service": service.name,
                "transport": service.transport,
                "guardrail": service.guardrail,
                "checkpoints": dict(service.points),
                "airs_profile_name": service.airs_profile_name,
                "airs_timeout_sec": service.airs_timeout_sec,
                "airs_fail_open": service.airs_fail_open,
                "gateway_timeout_sec": service.gateway_timeout_sec,
                "system_prompt": service.system_prompt,
                "max_tokens": service.max_tokens,
            })

        return {
            "version": self.version,
            "providers": providers,
            "services": services,
            "airs_api_key": self.airs_api_key,
            "gateway_api_key": self.gateway_api_key,
        }

    # -- the disk cache ----------------------------------------------------------------

    @classmethod
    def load_cached(cls) -> "Config":
        """The last pushed document, or an empty configuration."""
        try:
            with open(CACHE_PATH) as handle:
                document = json.load(handle)
        except FileNotFoundError:
            return cls()
        except (OSError, ValueError) as exc:
            log.warning("cached configuration at %s is unreadable (%s)", CACHE_PATH, exc)
            return cls()

        if not isinstance(document, dict):
            return cls()

        config = cls.from_document(document)
        log.info("restored the configuration pushed at version %s", config.version)
        return config

    def save_cached(self) -> None:
        """Write the cache, 0600, replaced atomically.

        Through a temporary file in the same directory, so a crash mid-write cannot leave a
        half-document behind - the next start would read that as the configuration.

        Not fatal on failure: the daemon is already running this configuration. What is
        lost is only the ability to come back on it after a restart.
        """
        directory = os.path.dirname(CACHE_PATH) or "."

        try:
            os.makedirs(directory, mode=0o700, exist_ok=True)
        except OSError as exc:
            log.warning("could not create %s (%s) - the configuration is live but will not "
                        "survive a restart", directory, exc)
            return

        # mkstemp is inside the try with everything else: a directory that exists but is not
        # writable fails HERE, and an exception escaping this method would make ApplyConfig
        # report a refusal for a configuration it had already applied.
        temporary_path = ""
        try:
            handle_fd, temporary_path = tempfile.mkstemp(dir=directory, prefix=".deployment-",
                                                         suffix=".json")
            os.fchmod(handle_fd, 0o600)
            with os.fdopen(handle_fd, "w") as handle:
                json.dump(self.to_document(), handle, indent=2)
            os.replace(temporary_path, CACHE_PATH)
        except OSError as exc:
            log.warning("could not cache the configuration to %s (%s) - it is live but will "
                        "not survive a restart", CACHE_PATH, exc)
            if temporary_path and os.path.exists(temporary_path):
                os.unlink(temporary_path)


# -- document -> objects ---------------------------------------------------------------
# Free functions rather than classmethods: they read one dict and return one object, and
# nothing about them belongs to the class.


def _provider_from(raw: dict) -> ProviderConfig:
    provider = ProviderConfig()
    provider.provider_id = raw.get("id") or ""
    provider.api_key = raw.get("api_key") or ""

    for raw_model in raw.get("models") or []:
        model = ModelConfig()
        model.model_id = raw_model.get("id") or ""
        model.label = raw_model.get("label") or ""
        model.token_param = raw_model.get("token_param") or ""
        if model.model_id:
            provider.models.append(model)

    return provider


def _read_route(service: ServiceConfig, raw: dict) -> None:
    """The two axes, as the document states them.

    Written through UNFILTERED, which is the opposite of what this module does everywhere else and
    is deliberate. A value neither axis recognises - a typo, or an empty field from a push that
    predates one of them - must not be quietly rounded to a default: the default on the guardrail
    axis is "none", so rounding would turn a service configured to be inspected into one that
    serves turns uninspected, which is the single failure this codebase is built to prevent.

    So the unknown value survives to deployment/engine.py, where _build_transport and
    _build_guardrail refuse it by name and the push is reported as refused. Loud and diagnosable
    beats silent and wrong; there is no reading of an unrecognised deployment that is safe to guess.
    """
    service.transport = raw.get("transport") or ""
    service.guardrail = raw.get("guardrail") or ""


def _service_from(raw: dict) -> ServiceConfig:
    service = ServiceConfig()
    service.name = ServiceType.of(raw.get("service") or CHAT)

    _read_route(service, raw)

    raw_points = raw.get("checkpoints") or {}
    for point in POINTS:
        service.points[point] = bool(raw_points.get(point, False))

    service.airs_profile_name = raw.get("airs_profile_name") or ""
    service.airs_timeout_sec = float(raw.get("airs_timeout_sec") or DEFAULT_AIRS_TIMEOUT_SEC)
    service.airs_fail_open = bool(raw.get("airs_fail_open", False))

    service.gateway_timeout_sec = float(
        raw.get("gateway_timeout_sec") or DEFAULT_GATEWAY_TIMEOUT_SEC)

    service.system_prompt = raw.get("system_prompt") or ""
    service.max_tokens = int(raw.get("max_tokens") or DEFAULT_MAX_TOKENS)

    return service
