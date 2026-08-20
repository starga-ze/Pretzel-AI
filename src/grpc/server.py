"""pretzel-ai gRPC server — the service mgmtd calls in place of the old inferd IPC path.

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
import threading
import time
from concurrent import futures

import grpc

from src import config as pa_config
from src import log as pa_log
from src.crawler import pipeline as corpus_pipeline, store as corpus_store
from src.gateway import GatewayService
from src.grpc import pretzel_ai_pb2, pretzel_ai_pb2_grpc

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


# One refresh at a time. The crawl saturates the network worker pool and writes the whole techdoc
# schema; two of them interleaved would double-fetch every page and race each other's writes for
# no gain. A second caller is refused rather than queued, because the console's card is a
# synchronous window and a request that silently waited would look like one that had hung.
_refresh_lock = threading.Lock()


class PretzelAiServicer(pretzel_ai_pb2_grpc.PretzelAiServicer):
    def __init__(self, gateway):
        self._gateway = gateway

    def Chat(self, request, context):
        log.info(
            "Chat turn from %s: model=%s system_prompt=%s message_chars=%d history=%d session=%s",
            context.peer(),
            request.model or "(default)",
            "set" if request.system_prompt else "none",
            len(request.message),
            len(request.history),
            request.session_id or "(none)",
        )

        history = [{"role": t.role, "content": t.content} for t in request.history]
        result = self._gateway.complete_turn(
            request.model, request.message, request.system_prompt or None,
            history, request.session_id)

        # Stream the reply text (only present on a successful turn) so the console fills in as it
        # arrives; a failed turn streams nothing and carries its reason on the final chunk.
        if result.get("ok") and isinstance(result.get("reply"), str):
            for piece in _chunks(result["reply"]):
                yield pretzel_ai_pb2.ChatChunk(delta=piece, done=False)

        yield pretzel_ai_pb2.ChatChunk(
            done=True,
            error="" if result.get("ok") else result.get("error", ""),
            result_json=json.dumps(result, ensure_ascii=False),
        )

    # --- The tech-doc knowledge base ------------------------------------------------------

    def RefreshCorpus(self, request, context):
        scope = request.scope or None
        log.info("RefreshCorpus from %s: scope=%s", context.peer(), scope or "(all)")

        if not _refresh_lock.acquire(blocking=False):
            yield pretzel_ai_pb2.RefreshProgress(
                stage="failed", final=True,
                error="a refresh is already running on this appliance")
            return

        try:
            with corpus_store.connect() as conn:
                # Also checked in the database: the CLI is a separate process writing the same
                # schema, and a console refresh started on top of it would fetch everything twice.
                in_flight = corpus_store.running_run(conn)
                if in_flight:
                    yield pretzel_ai_pb2.RefreshProgress(
                        stage="failed", final=True,
                        error=(f"crawl #{in_flight[0]} is already running "
                               f"(started {in_flight[1]:%Y-%m-%d %H:%M})"))
                    return

                for update in corpus_pipeline.crawl(conn, scope=scope):
                    # The console closing its window cancels the crawl. Documented behaviour of
                    # this card, not a failure: the operator was told to keep the window open, and
                    # whatever was written stays written.
                    if not context.is_active():
                        log.info("RefreshCorpus cancelled by client")
                        return
                    yield _progress_message(update)
        except Exception as exc:                    # noqa: BLE001 - reported to the console
            log.exception("RefreshCorpus failed")
            yield pretzel_ai_pb2.RefreshProgress(stage="failed", final=True, error=str(exc))
        finally:
            _refresh_lock.release()

    def GetCorpusStatus(self, request, context):
        try:
            with corpus_store.connect() as conn:
                snapshot = corpus_store.status(conn)
                tree = corpus_store.product_tree(conn)
        except Exception as exc:                    # noqa: BLE001 - reported to the console
            log.exception("GetCorpusStatus failed")
            return pretzel_ai_pb2.CorpusStatus(error=str(exc))
        return pretzel_ai_pb2.CorpusStatus(
            **snapshot,
            products=[pretzel_ai_pb2.ProductStat(**row) for row in tree])

    def ListDocuments(self, request, context):
        try:
            rows = _list_documents(self, request, context)
        except Exception as exc:                    # noqa: BLE001 - reported to the console
            log.exception("ListDocuments failed")
            return pretzel_ai_pb2.DocumentList(error=str(exc))
        return pretzel_ai_pb2.DocumentList(
            documents=[pretzel_ai_pb2.DocumentSummary(**row) for row in rows])


def _list_documents(servicer, request, context):
    """Shared by the RPC below; kept apart so the error shape is written once."""
    with corpus_store.connect() as conn:
        return corpus_store.documents(conn, request.product, request.docset)


def _progress_message(update):
    """pipeline.crawl's dict -> the wire message. Counts are absent on the earliest stages."""
    counts = update.get("counts") or {}
    survey = update.get("survey") or {}
    return pretzel_ai_pb2.RefreshProgress(
        stage=update.get("stage", ""),
        done=update.get("done", 0),
        total=update.get("total", 0),
        listed=counts.get("listed", 0),
        stored=counts.get("stored", 0),
        rejected=counts.get("rejected", 0),
        survey_ok=survey.get("ok", 0),
        survey_redirect=survey.get("redirect", 0),
        survey_missing=survey.get("missing", 0),
        final=bool(update.get("final")),
        error=update.get("error", "") or "",
        run_id=update.get("run_id", 0) or 0,
    )


def serve(address, config_path):
    gw, credentials = pa_config.load(config_path)
    if not isinstance(gw, dict) or "host" not in gw:
        raise ValueError(f"{config_path}: missing or invalid 'gateway' object")

    gateway = GatewayService(gw, credentials)

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    pretzel_ai_pb2_grpc.add_PretzelAiServicer_to_server(PretzelAiServicer(gateway), server)
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
    # src/grpc/server.py -> src/grpc -> src -> the repo root.
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.environ.get("PZ_PRETZEL_AI_CONFIG", "") or os.path.join(
        root, "prisma-airs", "config.json")


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
