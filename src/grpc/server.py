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


# The console lists a sample of the pending changes, not all of them. A refresh can legitimately
# have five figures of work in it on a first build, and neither the wire nor the operator is
# served by carrying every URL — the counts alongside are the complete answer.
CHANGE_SAMPLE = 200

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
                yield pretzel_ai_pb2.ChatChunk(delta=piece, done=False)

        yield pretzel_ai_pb2.ChatChunk(
            done=True,
            error="" if result.get("ok") else result.get("error", ""),
            result_json=json.dumps(result, ensure_ascii=False),
        )

    # --- The tech-doc knowledge base ------------------------------------------------------

    def CheckCorpus(self, request, context):
        scope = request.scope or None
        log.info("CheckCorpus from %s: scope=%s", context.peer(), scope or "(all)")
        try:
            with corpus_store.connect() as conn:
                changes, total = corpus_pipeline.check(conn, scope=scope)
        except Exception as exc:                    # noqa: BLE001 - reported to the console
            log.exception("CheckCorpus failed")
            return pretzel_ai_pb2.CorpusCheck(error=str(exc))

        counts = {"added": 0, "changed": 0, "removed": 0, "retry": 0}
        # Folded onto (product, version, docset) — the tree the URLs imply and the sitemap does
        # not. Complete, unlike the change sample below it: the operator judges the shape of a
        # refresh from this, not from the first 200 URLs.
        groups = {}
        for change in changes:
            counts[change.kind] += 1
            key = (change.product or "", change.version or "", change.docset or "")
            bucket = groups.setdefault(
                key, {"added": 0, "changed": 0, "removed": 0, "retry": 0})
            bucket[change.kind] += 1

        return pretzel_ai_pb2.CorpusCheck(
            total_in_scope=total,
            added=counts["added"], changed=counts["changed"], removed=counts["removed"],
            retry=counts["retry"],
            truncated=len(changes) > CHANGE_SAMPLE,
            groups=[
                pretzel_ai_pb2.ChangeGroup(
                    product=product, version=version, docset=docset,
                    added=b["added"], changed=b["changed"], removed=b["removed"],
                    retry=b["retry"])
                for (product, version, docset), b in sorted(
                    groups.items(),
                    key=lambda kv: -sum(kv[1].values()))
            ],
            changes=[
                pretzel_ai_pb2.DocChange(
                    url=c.url, kind=c.kind, product=c.product or "",
                    version=c.version or "", docset=c.docset or "",
                    lastmod=c.lastmod.isoformat() if c.lastmod else "",
                    previous_lastmod=(c.previous_lastmod.isoformat()
                                      if c.previous_lastmod else ""),
                    title=c.title or "",
                )
                for c in changes[:CHANGE_SAMPLE]
            ],
        )

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
                # Also checked in the database, not just in this process: the CLI used for the
                # first full build is a separate process writing the same schema, and a console
                # refresh started on top of it would fetch every page twice.
                in_flight = corpus_store.running_run(conn)
                if in_flight:
                    yield pretzel_ai_pb2.RefreshProgress(
                        stage="failed", final=True,
                        error=(f"crawl #{in_flight[0]} is already running "
                               f"(started {in_flight[1]:%Y-%m-%d %H:%M})"))
                    return

                changes, _total = corpus_pipeline.check(conn, scope=scope)
                if not changes:
                    yield pretzel_ai_pb2.RefreshProgress(stage="done", final=True)
                    return

                for update in corpus_pipeline.refresh(conn, changes, scope=scope):
                    # The console closing its window cancels the crawl. That is the documented
                    # behaviour of this card, not a failure: the operator was told to keep the
                    # window open, and a half-applied refresh is resumable — every page already
                    # written keeps its content hash, so the next run skips it.
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


def _progress_message(update):
    """pipeline.refresh's dict -> the wire message. Counts are absent on the earliest stages."""
    counts = update.get("counts") or {}
    return pretzel_ai_pb2.RefreshProgress(
        stage=update.get("stage", ""),
        done=update.get("done", 0),
        total=update.get("total", 0),
        fetched=counts.get("fetched", 0),
        added=counts.get("added", 0),
        changed=counts.get("changed", 0),
        removed=counts.get("removed", update.get("removed", 0)),
        skipped_304=counts.get("skipped_304", 0),
        skipped_same_sha=counts.get("skipped_same_sha", 0),
        skipped_alias=counts.get("skipped_alias", 0),
        failed=counts.get("failed", 0),
        final=bool(update.get("done_flag")),
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
