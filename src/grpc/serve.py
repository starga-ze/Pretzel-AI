"""The gRPC transport: build the server, register the servicer, hold the port.

Split out of server.py so that file is handlers and nothing else. The two concerns move for
different reasons — a handler changes when the contract does, this changes when the transport
does (message limits, worker count, TLS if the mgmtd edge ever leaves loopback) — and keeping
them in one file meant every proto change touched the same file as every tuning change.

Nothing here decides anything about a turn. It reads config, wires the object graph and blocks.
"""

import logging
from concurrent import futures

import grpc

from src import config as pa_config
from src.benchmark import store as benchmark_store
from src.gateway import GatewayService
from src.grpc import pretzel_ai_pb2_grpc
from src.grpc.server import PretzelAiServicer

log = logging.getLogger("pretzel-ai")

# mgmtd calls one at a time per operator, but a benchtest run and a corpus refresh are both long
# streams that hold a worker for their whole duration. Eight leaves room for those plus the chat
# turns that must not queue behind them.
MAX_WORKERS = 8


def build(config_path):
    """→ (server, gateway_config, credentials). Bound and populated, not yet started."""
    gw, credentials = pa_config.load(config_path)
    if not isinstance(gw, dict) or "host" not in gw:
        raise ValueError(f"{config_path}: missing or invalid 'gateway' object")

    # An upload carries a whole .jsonl in one message and the store accepts up to 32 MB, which is
    # past gRPC's 4 MB default — without this the large-file case fails at the transport with a
    # RESOURCE_EXHAUSTED that never reaches the store's own size check and its clearer message.
    limit = benchmark_store.MAX_UPLOAD_BYTES + (1 << 20)

    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=MAX_WORKERS),
        options=[("grpc.max_receive_message_length", limit),
                 ("grpc.max_send_message_length", limit)])

    servicer = PretzelAiServicer(GatewayService(gw, credentials))
    pretzel_ai_pb2_grpc.add_PretzelAiServicer_to_server(servicer, server)
    return server, gw, credentials


def serve(address, config_path):
    """Start on `address` and block until the process is told to stop."""
    server, gw, credentials = build(config_path)

    # Loopback, no TLS — this is the mgmtd↔pretzel-ai edge, not the gateway edge.
    server.add_insecure_port(address)
    server.start()

    scheme = "https" if gw.get("tls", True) else "http"
    log.info("pretzel-ai listening on %s", address)
    log.info("AIRS gateway → %s://%s:%s%s (key=%s)",
             scheme, gw.get("host", "?"), gw.get("port", "?"), gw.get("path", ""),
             "set" if credentials.key() else "MISSING")

    server.wait_for_termination()
