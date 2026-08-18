"""pretzel-ai inference server — the gRPC service mgmtd calls in place of the old inferd IPC path.

Chat() runs one turn through the AIRS gateway (see gateway.py, ported from inferd) and streams the
reply back to mgmtd. The reply text is re-streamed word by word so the console can render it as it
arrives; the final chunk carries the complete turn document (reply, the AIRS scan verdict, usage,
ok/code) as JSON, which mgmtd files verbatim.

Why re-stream a completed answer rather than stream tokens from the model: the gateway call is
non-streaming on purpose. The AIRS response-side guardrail has to see the whole answer to rule on
it, so streaming raw tokens straight through would either skip that scan or buffer for it anyway.
Scanning the finished answer and then re-streaming it to the console is the honest compromise.
"""

import argparse
import json
import logging
import os
import time
from concurrent import futures

import grpc

from src import config as pa_config
from src import inference_pb2, inference_pb2_grpc, log as pa_log
from src.gateway import GatewayService

log = logging.getLogger("pretzel-ai")

# How the completed reply is sliced into deltas for the console. Whitespace-preserving so the
# reassembled text is byte-identical to result_json["reply"].
def _chunks(text):
    token = ""
    for ch in text:
        token += ch
        if ch.isspace():
            yield token
            token = ""
    if token:
        yield token


class InferenceServicer(inference_pb2_grpc.InferenceServicer):
    def __init__(self, gateway):
        self._gateway = gateway

    def Chat(self, request, context):
        log.info(
            "Chat turn from %s: model=%s system_prompt=%s message_chars=%d",
            context.peer(),
            request.model or "(default)",
            "set" if request.system_prompt else "none",
            len(request.message),
        )

        result = self._gateway.complete_turn(
            request.model, request.message, request.system_prompt or None)

        # Stream the reply text (only present on a successful turn) so the console fills in as it
        # arrives; a failed turn streams nothing and carries its reason on the final chunk.
        if result.get("ok") and isinstance(result.get("reply"), str):
            for piece in _chunks(result["reply"]):
                yield inference_pb2.ChatChunk(delta=piece, done=False)

        yield inference_pb2.ChatChunk(
            done=True,
            error="" if result.get("ok") else result.get("error", ""),
            result_json=json.dumps(result, ensure_ascii=False),
        )


def serve(address, config_path):
    gw, credentials = pa_config.load(config_path)
    if not isinstance(gw, dict) or "host" not in gw:
        raise ValueError(f"{config_path}: missing or invalid 'gateway' object")

    gateway = GatewayService(gw, credentials)

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    inference_pb2_grpc.add_InferenceServicer_to_server(InferenceServicer(gateway), server)
    # Loopback, no TLS — this is the mgmtd↔pretzel-ai edge, not the gateway edge.
    server.add_insecure_port(address)
    server.start()

    scheme = "https" if gw.get("tls", True) else "http"
    log.info("pretzel-ai listening on %s", address)
    log.info("AIRS gateway → %s://%s:%s%s (key=%s)",
             scheme, gw.get("host", "?"), gw.get("port", "?"), gw.get("path", ""),
             "set" if credentials.key() else "MISSING")
    server.wait_for_termination()


def _default_config():
    return os.environ.get("PZ_PRETZEL_AI_CONFIG", "") or os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "prisma-airs", "config.json")


def main():
    ap = argparse.ArgumentParser(description="pretzel-ai gRPC inference server")
    ap.add_argument("--listen", default="127.0.0.1:50051",
                    help="host:port to bind (default 127.0.0.1:50051)")
    ap.add_argument("--config", default=_default_config(),
                    help="path to the gateway config json (default: prisma-airs/config.json)")
    args = ap.parse_args()

    pa_log.setup()
    serve(args.listen, args.config)


if __name__ == "__main__":
    main()
