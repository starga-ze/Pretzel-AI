"""The services this daemon runs, and the engines behind them.

Two of them, and they are separate because what answers a turn is a different thing in each:

    chat    one model call per turn. Built.
    agent   a loop over tools. Not built here - see engine.py - and refused rather than
            served as a chat engine, so a service configured to loop cannot come up quietly
            answering in a single call.

A Service is a name, the configuration for it, and the engine built from that. Services is
the pair, and the thing Core holds.

Nothing here runs a turn. It builds what does, and hands it out.
"""

import logging
from typing import Optional

from src.deployment import config as cfg
from src.deployment import engine as engine_builder

log = logging.getLogger("pretzel-ai.deployment.service")


class Service:
    """One service. `engine` is None when the configuration could not produce one, which is
    a state a turn is refused in rather than a failure to start."""

    def __init__(self, service_type: "cfg.ServiceType"):
        self.name = service_type
        self.config: Optional["cfg.ServiceConfig"] = None
        self.engine = None
        self.error = ""             # why there is no engine, for the caller to report

        # This build does not implement the service at all. Distinct from `error`: that is a
        # document to fix, this is a feature that is not here, and only the first refuses a push.
        self.unimplemented = False

    def is_ready(self) -> bool:
        return self.engine is not None

    def describe(self) -> str:
        if self.engine is None:
            return self.error or "not configured"
        return self.engine.describes


class Services:
    """Every service, built together.

    Built as a set rather than one at a time: an ApplyConfig either produces a daemon that
    works or one that does not, and a half-applied document would leave chat on the new
    configuration and agent on the old with nothing saying so.
    """

    def __init__(self):
        self._services = {}
        for service_type in cfg.SERVICES:
            self._services[service_type] = Service(service_type)

    # -- building ------------------------------------------------------------------------

    @classmethod
    def build(cls, config: "cfg.Config") -> "Services":
        """Every service, from one configuration.

        A service the document does not mention is left unconfigured rather than defaulted.
        The appliance decides which services exist; a daemon that invented one would be
        serving something nobody asked for.

        Never raises. A service that cannot be built carries its reason instead, because
        one unusable service must not stop the other from running.
        """
        services = cls()

        for service_type in cfg.SERVICES:
            service = services._services[service_type]
            service.config = config.service(service_type)

            if service.config is None:
                service.error = "not in the pushed configuration"
                log.debug("[5/5] service (name=%s, state=skipped, "
                          "reason=not in the pushed configuration)", service_type)
                continue

            try:
                service.engine = _build_engine(service_type, service.config, config)
                service.error = ""
                log.debug("[5/5] service (name=%s, state=ready, guardrail=%s, "
                          "checkpoints=[%s])",
                          service_type, service.config.guardrail,
                          ",".join(service.config.active_points()))
            except engine_builder.ServiceNotBuilt as exc:
                # Caught before EngineError, which it subclasses. INFO rather than WARNING: the
                # appliance is answering "I do not have that", which is a fact about this build
                # and not a fault in the document.
                service.engine = None
                service.error = str(exc)
                service.unimplemented = True
                log.info("service %s: %s", service_type, exc)
                log.debug("[5/5] service (name=%s, state=unimplemented, reason=%s)",
                          service_type, exc)
            except engine_builder.EngineError as exc:
                service.engine = None
                service.error = str(exc)
                log.warning("service %s cannot serve: %s", service_type, exc)
                log.debug("[5/5] service (name=%s, state=failed, reason=%s)",
                          service_type, exc)

        return services

    # -- what Core and the handlers ask -------------------------------------------------

    def get_service(self, service_type: "cfg.ServiceType") -> Optional[Service]:
        """One service, ready or not. Named apart from get_engine because a caller that wants
        the reason a service cannot serve wants this one."""
        return self._services.get(service_type)

    def get_engine(self, service_type: "cfg.ServiceType"):
        """The engine that serves this service's turns, or None.

        Read per turn, never captured: ApplyConfig replaces the engines while the daemon
        runs, and a handler that held one would keep serving the configuration it started
        with.
        """
        service = self._services.get(service_type)
        if service is None:
            return None
        return service.engine

    def all(self) -> list:
        """Every service, in a fixed order, so a log line reads the same every time."""
        ordered = []
        for service_type in cfg.SERVICES:
            ordered.append(self._services[service_type])
        return ordered

    def any_ready(self) -> bool:
        """Whether this daemon can serve anything at all."""
        for service in self.all():
            if service.is_ready():
                return True
        return False

    def failures(self) -> list:
        """The services the document named and that could not be built.

        A service the document does not mention is not in here: the appliance decides which
        services exist, and one it did not configure is absent rather than broken. Neither is a
        service this build does not implement - refusing a whole document over one of those would
        take the services that DO work down with it.
        """
        broken = []
        for service in self.all():
            if service.config is None or service.unimplemented:
                continue
            if service.engine is None:
                broken.append(service)
        return broken


def _build_engine(service_type: "cfg.ServiceType", service: "cfg.ServiceConfig",
                  config: "cfg.Config"):
    """Which builder runs, decided by which service this is.

    Two services, two functions. The difference between them is what the model may ask this
    appliance to run, and naming it here means neither builder has to ask which service it
    was called for - see engine.py.
    """
    if service_type is cfg.ServiceType.CHAT:
        return engine_builder.build_chat_engine(service, config)

    if service_type is cfg.ServiceType.AGENT:
        return engine_builder.build_agent_engine(service, config)

    # Unreachable through cfg.SERVICES, and raised rather than asserted so a third member
    # added to ServiceType but not to this function is reported as the service's own failure
    # instead of stopping the daemon.
    raise engine_builder.EngineError("no engine builder for service " + str(service_type))
