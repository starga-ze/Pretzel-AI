"""The tech-doc knowledge base: crawl, status, and the document browser."""

import logging
import threading

import grpc

from src.crawler import pipeline as corpus_pipeline, store as corpus_store
from src.grpc import pretzel_ai_pb2

log = logging.getLogger("pretzel-ai")


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

class CorpusHandlers:
    """RefreshCorpus + GetCorpusStatus + ListDocuments.

    A mixin: PretzelAiServicer composes it with the generated base. Kept out of the
    servicer because these methods change when this domain's contract does, and
    nothing else in the service has a reason to move with them.
    """

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
