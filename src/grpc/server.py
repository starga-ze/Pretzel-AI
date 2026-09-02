"""The service mgmtd calls in place of the old inferd IPC path.

This file is composition and nothing else. Every RPC lives in src/grpc/handlers/, one module per
domain, and each is imported from the module that defines it — there is no package re-export to
look through; the transport that binds the port is next door in serve.py, and the process entry point is
src/main.py.

The servicer is assembled from mixins rather than written out here because the four domains have
nothing to say to each other: a benchtest RPC and a chat RPC share the object only because grpc
dispatches both off one servicer instance. Splitting them means a proto change touches one file,
and the file it touches is named after the thing that changed.
"""

import logging

from src.grpc import pretzel_ai_pb2_grpc
from src.grpc.handlers.benchmark import BenchmarkHandlers
from src.grpc.handlers.benchtest import BenchtestHandlers
from src.grpc.handlers.chat import ChatHandlers
from src.grpc.handlers.config import ConfigHandlers
from src.grpc.handlers.corpus import CorpusHandlers

log = logging.getLogger("pretzel-ai")


class PretzelAiServicer(
    ChatHandlers,
    ConfigHandlers,
    CorpusHandlers,
    BenchmarkHandlers,
    BenchtestHandlers,
    pretzel_ai_pb2_grpc.PretzelAiServicer,
):
    """Every RPC in the contract, gathered from the four handler mixins.

    The generated base comes last: its methods are `raise NotImplementedError` stubs, so it has to
    lose the MRO to the mixins. It stays in the bases because grpc's service registration checks
    the type, and because an RPC added to the proto but not yet to a handler should fail as
    UNIMPLEMENTED rather than AttributeError.
    """

    def __init__(self, core):
        # The servicer holds Core, not an engine. ApplyConfig replaces the engines while the
        # daemon runs, so a handler that captured one would keep serving the configuration it
        # started with. Every handler asks per call.
        #
        # Core rather than Services for the same reason one level up: applying a configuration
        # replaces the whole Services object, and a servicer holding the old one would hand out
        # old engines. A turn already in flight keeps the engine it started on.
        #
        # The engine holds the transport and the guardrail that configuration selected. Handlers
        # take it as given: none of them may ask which route this appliance is running, because a
        # handler that branched on it would be a second place the matrix is decided.
        self._core = core

    def get_engine(self, service_type):
        """The engine that serves this service's turns, or None when it has none.

        None is a state, not a failure: a fresh install has no configuration until the appliance
        pushes one, and a handler answers with the reason rather than crashing. Read per call,
        never cached.

        There is no `current_engine` any more, and the name is why: with chat and agent configured
        apart there is no single current one, so the caller names the service it is serving -
        ServiceType.CHAT or ServiceType.AGENT, never a bare string a typo could slip through.
        """
        services = self._core.services
        if services is None:
            return None
        return services.get_engine(service_type)

    def apply_config(self, config) -> None:
        """Adopt a pushed configuration. Raises when it cannot produce engines."""
        self._core.apply_config(config)

    def describe_service(self, service_type) -> str:
        """One line for the log, whether or not the service is ready."""
        services = self._core.services
        if services is None:
            return "not configured"

        service = services.get_service(service_type)
        if service is None:
            return "unknown service"
        return service.describe()
