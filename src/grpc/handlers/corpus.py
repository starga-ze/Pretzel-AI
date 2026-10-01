"""Corpus lifecycle and paginated document browsing."""
import logging
import re
import threading
from src.crawler import pipeline, store
from src.crawler.fetch import Cancelled
from src.grpc import pretzel_ai_pb2 as pb

log = logging.getLogger(__name__)


def _progress_message(update):
    counts = update.get('counts', {})
    return pb.RefreshProgress(stage=update.get('stage',''),done=update.get('done',0),total=update.get('total',0),
        listed=counts.get('listed',0),collected=counts.get('collected',0),excluded=counts.get('excluded',0),
        unknown=counts.get('unknown',0),dry_run=counts.get('dry_run',False),
        current_url=update.get('current_url',''),final=update.get('final',False),error=update.get('error',''),run_id=update.get('run_id',0))


class CorpusHandlers:
    def RefreshCorpus(self, request, context):
        cancel = threading.Event()
        if not context.add_callback(cancel.set):
            cancel.set()
        try:
            if request.scope and not re.fullmatch(r'[a-z0-9-]{1,64}', request.scope):
                raise ValueError('Invalid product scope')
            with store.connect() as conn:
                progress = pipeline.crawl(conn,scope=request.scope or None,dry_run=request.dry_run,cancel=cancel)
                try:
                    for update in progress:
                        if not context.is_active():
                            cancel.set()
                            return
                        yield _progress_message(update)
                finally:
                    progress.close()
        except Cancelled:
            return
        except Exception as exc:
            log.exception('Corpus refresh failed')
            yield pb.RefreshProgress(stage='failed',final=True,error=str(exc))

    def GetCorpusStatus(self, request, context):
        try:
            with store.connect() as conn:
                snapshot = store.status(conn)
                tree = store.product_tree(conn)
            return pb.CorpusStatus(**snapshot,products=[pb.ProductStat(**row) for row in tree])
        except Exception as exc:
            log.exception('Corpus status failed')
            return pb.CorpusStatus(error=str(exc))

    def ListDocuments(self, request, context):
        try:
            if len(request.query) > 256 or request.offset < 0 or request.offset > 1000000:
                raise ValueError('Invalid document query')
            with store.connect() as conn:
                rows,total = store.documents(conn,request.product,request.docset,request.query,
                    request.version if request.HasField('version') else None,request.offset,request.limit)
            return pb.DocumentList(documents=[pb.DocumentSummary(**row) for row in rows],total=total)
        except Exception as exc:
            log.exception('Corpus browse failed')
            return pb.DocumentList(error=str(exc))

    def ListCorpusExceptions(self, request, context):
        try:
            if request.offset < 0 or request.offset > 1000000 or len(request.reason) > 64:
                raise ValueError('Invalid exception query')
            with store.connect() as conn:
                rows,total,tally,run_id = store.exceptions(
                    conn,request.run_id,request.reason,request.offset,request.limit)
            return pb.ExceptionList(exceptions=[pb.CorpusException(**row) for row in rows],
                tally=[pb.ReasonTally(**row) for row in tally],run_id=run_id,total=total)
        except Exception as exc:
            log.exception('Corpus exception listing failed')
            return pb.ExceptionList(error=str(exc))
