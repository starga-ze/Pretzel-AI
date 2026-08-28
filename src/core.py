"""The service: configuration in, a running daemon out.

The composition root. It is the one module that knows both halves of the appliance — the domain
(factory.build_engine decides which transport and which guardrail this deployment runs) and the
transport that exposes it (a gRPC server on the mgmtd edge) — and it exists so that nothing else
has to. src/main.py above it handles only the command line; src/grpc/ below it holds only the
contract and its handlers.

Promoted out of src/grpc/ once it started calling the factory. Building the engine is not a gRPC
concern, and a module that assembles the domain has no business living inside the package named
after one way of reaching it. When the agent service arrives it will assemble a different engine —
one holding a ToolRuntime — and hand it to the same kind of server; the seam that makes that
possible is this file being the only place the two are joined.
"""

import logging
from concurrent import futures

import grpc

from src import config as pa_config
from src.benchmark import store as benchmark_store
from src.factory import build_engine
from src.grpc import pretzel_ai_pb2_grpc
from src.grpc.server import PretzelAiServicer

log = logging.getLogger("pretzel-ai")

# mgmtd calls one at a time per operator, but a benchtest run and a corpus refresh are both long
# streams that hold a worker for their whole duration. Eight leaves room for those plus the chat
# turns that must not queue behind them.
MAX_WORKERS = 8


def build(config_path):
    """→ (server, engine). Bound and populated, not yet started.

    The whole deployment matrix is decided in one call here: build_engine reads `route.llm` and
    `route.guardrail` and hands back an engine already holding the transport and the guardrail it
    chose. Nothing downstream of this line — not the servicer, not a handler — can tell which
    combination it got, which is the point of the indirection and the reason moving inspection
    to or from a gateway is a config edit.
    """
    config, credentials = pa_config.load(config_path)
    engine = build_engine(config, credentials)

    # An upload carries a whole .jsonl in one message and the store accepts up to 32 MB, which is
    # past gRPC's 4 MB default — without this the large-file case fails at the transport with a
    # RESOURCE_EXHAUSTED that never reaches the store's own size check and its clearer message.
    limit = benchmark_store.MAX_UPLOAD_BYTES + (1 << 20)

    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=MAX_WORKERS),
        options=[("grpc.max_receive_message_length", limit),
                 ("grpc.max_send_message_length", limit)])

    servicer = PretzelAiServicer(engine)
    pretzel_ai_pb2_grpc.add_PretzelAiServicer_to_server(servicer, server)
    return server, engine


def serve(address, config_path):
    """Start on `address` and block until the process is told to stop."""
    server, engine = build(config_path)

    # Loopback, no TLS — this is the mgmtd↔pretzel-ai edge, not the gateway edge.
    server.add_insecure_port(address)
    server.start()

    log.info("pretzel-ai listening on %s", address)
    # Where turns go and who inspects them, on one line, because those two facts decide how every
    # verdict in the log below should be read.
    log.info("route: %s", engine.describes)
    log.info("models: %d (default %s)", len(engine.catalog), engine.catalog.default or "none")

    server.wait_for_termination()
