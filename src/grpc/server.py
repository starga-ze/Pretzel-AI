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
from src.grpc.handlers.corpus import CorpusHandlers

log = logging.getLogger("pretzel-ai")


class PretzelAiServicer(
    ChatHandlers,
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

    def __init__(self, gateway):
        # Only the chat handlers need it; it lives here because construction is this file's job.
        self._gateway = gateway
