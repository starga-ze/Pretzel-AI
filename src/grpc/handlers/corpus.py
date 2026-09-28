"""The tech-doc knowledge base: crawl, status, and the document browser."""

import logging
import threading

import grpc

from src.crawler import pipeline as corpus_pipeline, store as corpus_store
from src.grpc import pretzel_ai_pb2

log = logging.getLogger("pretzel-ai")

# One refresh at a time. The crawl saturates the network worker pool and writes the whole
# techdoc schema; two interleaved would double-fetch every page and race each other's writes
# for no gain. A second caller is refused rather than queued, because the console's card is a
# synchronous window and a request that silently waited would look like one that had hung.
_refresh_lock = threading.Lock()


def _list_documents(servicer, request, context):
    """→ (rows, total). Shared by the RPC below; kept apart so the error shape is written once.

    Two questions through one call, told apart by `query`: browsing a book returns all of it and
    `total` is just its length, while a search is capped and `total` is what it matched before
    the cap.
    """
    with corpus_store.connect() as conn:
        if request.query:
            return corpus_store.search(conn, request.query)
        rows = corpus_store.documents(conn, request.product, request.docset)
        return rows, len(rows)

def _progress_message(update):
    """pipeline.crawl's dict -> the wire message. Counts are absent on the earliest stages."""
    counts = update.get("counts") or {}
    survey = update.get("survey") or {}
    # `listed` is the one field both halves of a run report, and it is carried in a different
    # dict in each: the survey has not built `counts` yet, so reading it from there alone drew
    # "68 gone of 0 listed" on the card for the whole survey.
    return pretzel_ai_pb2.RefreshProgress(
        stage=update.get("stage", ""),
        done=update.get("done", 0),
        total=update.get("total", 0),
        listed=counts.get("listed") or survey.get("listed", 0),
        stored=counts.get("stored", 0),
        rejected=counts.get("rejected", 0),
        survey_ok=survey.get("ok", 0),
        survey_redirect=survey.get("redirect", 0),
        survey_missing=survey.get("missing", 0),
        survey_unknown=survey.get("unknown", 0),
        current_url=update.get("current_url", "") or "",
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

                # Held in a name so it can be closed EXPLICITLY, which is the whole point.
                # Returning out of the loop instead only drops the last reference: the `with`
                # above closes the connection as this frame unwinds, and the generator's
                # GeneratorExit handler - the one that marks the run cancelled - then runs
                # against a closed connection and fails. Crawl #5 sat 'running' for ever that
                # way, and a stuck row refuses every later crawl on the appliance.
                progress = corpus_pipeline.crawl(conn, scope=scope)
                try:
                    for update in progress:
                        # Cancel, or mgmtd going away. Not a failure either way, and whatever
                        # was written stays written. The browser has no part in it: mgmtd holds
                        # this stream and keeps the progress in a slot the console polls, so
                        # closing that window leaves the crawl running. The call goes inactive
                        # when mgmtd TryCancels it, which is what the card's Cancel asks for.
                        if not context.is_active():
                            log.info("RefreshCorpus cancelled by client")
                            return
                        yield _progress_message(update)
                finally:
                    # Covers the cancel above and any error thrown into this generator from
                    # outside. Closing while `conn` is still open is what lets the run close out.
                    progress.close()
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
            rows, total = _list_documents(self, request, context)
        except Exception as exc:                    # noqa: BLE001 - reported to the console
            log.exception("ListDocuments failed")
            return pretzel_ai_pb2.DocumentList(error=str(exc))
        return pretzel_ai_pb2.DocumentList(
            documents=[pretzel_ai_pb2.DocumentSummary(**row) for row in rows],
            total=total)
