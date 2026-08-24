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
from src.benchmark import runner as benchmark_runner, store as benchmark_store
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


    # --- Benchmark sets -------------------------------------------------------------------
    #
    # Unary reads and one unary write, straight against pretzel_knowledge. Every handler answers
    # with a message carrying an `error` field rather than raising: the console has to be able to
    # tell "the set is empty" from "the read failed", and a gRPC status code collapses both into a
    # red box with no sentence in it.

    def ListBenchmarkDatasets(self, request, context):
        try:
            with benchmark_store.connect() as conn:
                found = benchmark_store.datasets(conn, request.search)
        except Exception as exc:                    # noqa: BLE001 - reported to the console
            log.exception("ListBenchmarkDatasets failed")
            return pretzel_ai_pb2.BenchmarkDatasetList(error=str(exc))
        return pretzel_ai_pb2.BenchmarkDatasetList(
            datasets=[_dataset_msg(d) for d in found])

    def UploadBenchmarkDataset(self, request, context):
        try:
            with benchmark_store.connect() as conn:
                stored = benchmark_store.create(
                    conn, request.content, request.filename,
                    name=request.name, note=request.note, uploaded_by=request.uploaded_by)
        except benchmark_store.DuplicateUpload as dup:
            # Not an error. The bytes are already a set, and the console should open it.
            return pretzel_ai_pb2.UploadBenchmarkDatasetResult(
                dataset=_dataset_msg(dup.dataset), duplicate=True)
        except benchmark_store.UploadError as bad:
            log.info("benchmark upload rejected: %s", bad.message)
            return pretzel_ai_pb2.UploadBenchmarkDatasetResult(
                error=bad.message, problems=list(bad.problems))
        except Exception as exc:                    # noqa: BLE001 - reported to the console
            log.exception("UploadBenchmarkDataset failed")
            return pretzel_ai_pb2.UploadBenchmarkDatasetResult(error=str(exc))
        return pretzel_ai_pb2.UploadBenchmarkDatasetResult(dataset=_dataset_msg(stored))

    def RenameBenchmarkDataset(self, request, context):
        try:
            with benchmark_store.connect() as conn:
                got = benchmark_store.rename(
                    conn, request.dataset_id, request.name,
                    note=request.note if request.note else None)
        except Exception as exc:                    # noqa: BLE001 - reported to the console
            log.exception("RenameBenchmarkDataset failed")
            return pretzel_ai_pb2.BenchmarkDatasetResult(error=str(exc))
        if not got:
            return pretzel_ai_pb2.BenchmarkDatasetResult(error="no such benchmark set")
        return pretzel_ai_pb2.BenchmarkDatasetResult(dataset=_dataset_msg(got))

    def DeleteBenchmarkDataset(self, request, context):
        try:
            with benchmark_store.connect() as conn:
                gone = benchmark_store.delete(conn, request.dataset_id)
        except Exception as exc:                    # noqa: BLE001 - reported to the console
            log.exception("DeleteBenchmarkDataset failed")
            return pretzel_ai_pb2.DeleteBenchmarkDatasetResult(error=str(exc))
        return pretzel_ai_pb2.DeleteBenchmarkDatasetResult(deleted=gone)

    def GetBenchmarkSummary(self, request, context):
        try:
            with benchmark_store.connect() as conn:
                got = benchmark_store.summary(conn, request.dataset_id)
        except Exception as exc:                    # noqa: BLE001 - reported to the console
            log.exception("GetBenchmarkSummary failed")
            return pretzel_ai_pb2.BenchmarkSummary(error=str(exc))
        if not got:
            return pretzel_ai_pb2.BenchmarkSummary(error="no such benchmark set")
        return pretzel_ai_pb2.BenchmarkSummary(
            dataset=_dataset_msg(got),
            by_category=[pretzel_ai_pb2.BenchmarkBucket(**b) for b in got["by_category"]],
            by_verdict=[pretzel_ai_pb2.BenchmarkBucket(**b) for b in got["by_verdict"]],
            by_language=[pretzel_ai_pb2.BenchmarkBucket(**b) for b in got["by_language"]],
            techniques=[pretzel_ai_pb2.BenchmarkTechnique(**t) for t in got["techniques"]])

    def ListBenchmark(self, request, context):
        try:
            with benchmark_store.connect() as conn:
                page = benchmark_store.rows(
                    conn, request.dataset_id,
                    filters={"category": request.category, "verdict": request.verdict,
                             "language": request.language, "technique": request.technique},
                    search=request.search,
                    offset=request.offset,
                    limit=request.limit or benchmark_store.DEFAULT_LIMIT,
                    order_by=request.order_by, descending=request.descending)
        except Exception as exc:                    # noqa: BLE001 - reported to the console
            log.exception("ListBenchmark failed")
            return pretzel_ai_pb2.BenchmarkPage(error=str(exc))
        return pretzel_ai_pb2.BenchmarkPage(
            total=page["total"], offset=page["offset"], limit=page["limit"],
            rows=[_benchmark_row_msg(r) for r in page["rows"]])


    # --- Benchtest runs -------------------------------------------------------------------

    def RunBenchtest(self, request, context):
        """Stream a run. The generator is closed when the client goes away, which is what marks
        the run cancelled — a run left 'running' would block every later one through the schema's
        single-active constraint."""
        conn = None
        generator = None
        try:
            conn = benchmark_store.connect()
            generator = benchmark_runner.run(
                conn, request.dataset_id,
                filters={"category": request.category, "verdict": request.verdict,
                         "language": request.language, "technique": request.technique},
                search=request.search, workers=request.workers, label=request.label,
                note=request.note)
            for update in generator:
                if not context.is_active():
                    break
                yield _run_progress(update)
        except Exception as exc:                    # noqa: BLE001 - reported to the console
            log.exception("RunBenchtest failed")
            yield pretzel_ai_pb2.RunProgress(stage="failed", final=True, status="failed",
                                             error=str(exc))
        finally:
            # close() raises GeneratorExit inside the runner, which is where it finishes the run.
            if generator is not None:
                generator.close()
            if conn is not None:
                conn.close()

    def ListBenchtestRuns(self, request, context):
        try:
            with benchmark_store.connect() as conn:
                found = benchmark_runner.runs(conn, request.dataset_id, request.limit or 50)
        except Exception as exc:                    # noqa: BLE001 - reported to the console
            log.exception("ListBenchtestRuns failed")
            return pretzel_ai_pb2.BenchtestRunList(error=str(exc))
        return pretzel_ai_pb2.BenchtestRunList(runs=[_run_msg(r) for r in found])

    def GetBenchtestRun(self, request, context):
        try:
            with benchmark_store.connect() as conn:
                got = benchmark_runner.run_summary(
                    conn, request.run_id,
                    filters={"category": request.category, "verdict": request.verdict,
                             "language": request.language, "technique": request.technique},
                    search=request.search)
        except Exception as exc:                    # noqa: BLE001 - reported to the console
            log.exception("GetBenchtestRun failed")
            return pretzel_ai_pb2.BenchtestRunSummary(error=str(exc))
        if not got:
            return pretzel_ai_pb2.BenchtestRunSummary(error="no such run")
        return pretzel_ai_pb2.BenchtestRunSummary(
            run=_run_msg(got),
            tally=[pretzel_ai_pb2.RunTally(**t) for t in got["tally"]],
            by_category=[pretzel_ai_pb2.BenchmarkBucket(**b) for b in got.get("by_category", [])],
            by_verdict=[pretzel_ai_pb2.BenchmarkBucket(**b) for b in got.get("by_verdict", [])],
            by_language=[pretzel_ai_pb2.BenchmarkBucket(**b) for b in got.get("by_language", [])],
            techniques=[pretzel_ai_pb2.BenchmarkTechnique(
                category="", technique=t["key"], count=t["count"])
                for t in got.get("by_technique", [])],
            detected=got["detected"], ruled=got["ruled"], refused=got["refused"])

    def ListBenchtestCases(self, request, context):
        try:
            with benchmark_store.connect() as conn:
                page = benchmark_runner.cases(
                    conn, request.run_id, request.cause,
                    filters={"category": request.category, "verdict": request.verdict,
                             "language": request.language, "technique": request.technique},
                    search=request.search, offset=request.offset, limit=request.limit,
                    order_by=request.order_by, descending=request.descending)
        except Exception as exc:                    # noqa: BLE001 - reported to the console
            log.exception("ListBenchtestCases failed")
            return pretzel_ai_pb2.BenchtestCaseList(error=str(exc))
        return pretzel_ai_pb2.BenchtestCaseList(
            total=page["total"], offset=page["offset"], limit=page["limit"],
            cases=[_stored_case_msg(c) for c in page["cases"]])

    def GetBenchtestCase(self, request, context):
        try:
            with benchmark_store.connect() as conn:
                got = benchmark_runner.case_detail(conn, request.run_id, request.seq)
        except Exception as exc:                    # noqa: BLE001 - reported to the console
            log.exception("GetBenchtestCase failed")
            return pretzel_ai_pb2.BenchtestCaseDetail(error=str(exc))
        if not got:
            return pretzel_ai_pb2.BenchtestCaseDetail(error="no such case")
        return pretzel_ai_pb2.BenchtestCaseDetail(
            summary=_stored_case_msg(got), scan_id=got["scan_id"], caught=got["caught"],
            http_status=got["http_status"] or 0, prompt=got.get("prompt", ""),
            response=got["response"], raw_request=got["raw_request"],
            raw_response=got["raw_response"], tool_calls=got["tool_calls"])

    def ExportBenchmarkDataset(self, request, context):
        try:
            with benchmark_store.connect() as conn:
                got = benchmark_store.export_jsonl(conn, request.dataset_id)
        except Exception as exc:                    # noqa: BLE001 - reported to the console
            log.exception("ExportBenchmarkDataset failed")
            return pretzel_ai_pb2.ExportBenchmarkDatasetResult(error=str(exc))
        if not got:
            return pretzel_ai_pb2.ExportBenchmarkDatasetResult(error="no such benchmark set")
        return pretzel_ai_pb2.ExportBenchmarkDatasetResult(
            content=got["content"], filename=got["filename"], row_count=got["row_count"])


def _run_msg(r):
    return pretzel_ai_pb2.BenchtestRun(
        id=r["id"], dataset_id=r["dataset_id"], f_category=r["f_category"],
        f_verdict=r["f_verdict"], f_language=r["f_language"], f_technique=r["f_technique"],
        f_search=r["f_search"], selected=r["selected"], status=r["status"], error=r["error"],
        model=r["model"], started_at=r["started_at"], ended_at=r["ended_at"],
        label=r.get("label", ""), note=r.get("note", ""))


def _live_case_msg(c):
    """A case as the runner just produced it. `excluded` carries what a bool cannot: ok is None
    for an uninspected turn or a failed call, and sending that as false would score it as a miss."""
    return pretzel_ai_pb2.RunCase(
        seq=c["seq"], prompt_id=c["prompt_id"], category=c["category"], technique=c["technique"],
        language=c["language"], expected=c["expected"], verdict=c["verdict"],
        detectors=list(c["detectors"] or []), cause=c["cause"], ok=bool(c["ok"]),
        excluded=c["ok"] is None, latency_ms=c["latency_ms"])


def _stored_case_msg(c):
    """The same message, read back from the database, where the row carries fewer of the set's
    columns — the listing joins nothing, so category/technique/language are not on it."""
    return pretzel_ai_pb2.RunCase(
        seq=c["seq"], prompt_id=c["prompt_id"], category=c.get("category") or "",
        technique=c.get("technique") or "", language=c.get("language") or "",
        expected=c["expected"], verdict=c["verdict"], detectors=list(c["detectors"] or []),
        cause=c["cause"], ok=bool(c["ok"]), excluded=c["ok"] is None,
        latency_ms=c["latency_ms"] or 0, prompt=c.get("prompt") or "")


def _run_progress(update):
    msg = pretzel_ai_pb2.RunProgress(
        stage=update.get("stage", ""), run_id=update.get("run_id", 0) or 0,
        done=update.get("done", 0), total=update.get("total", 0),
        final=bool(update.get("final")), status=update.get("status", "") or "",
        error=update.get("error", "") or "")
    if update.get("case"):
        msg.last_case.CopyFrom(_live_case_msg(update["case"]))
    for key, count in (update.get("tally") or {}).items():
        msg.tally.append(pretzel_ai_pb2.RunTally(key=key, count=count))
    return msg


def _dataset_msg(d):
    return pretzel_ai_pb2.BenchmarkDataset(
        id=d["id"], name=d["name"], filename=d["filename"], content_sha=d["content_sha"],
        byte_size=d["byte_size"], row_count=d["row_count"], note=d["note"],
        uploaded_by=d["uploaded_by"], uploaded_at=d["uploaded_at"])


def _benchmark_row_msg(r):
    # `extra` travels as JSON text rather than as a struct: it is passed through to the console
    # untouched, and a proto Struct would rewrite number types on the way.
    return pretzel_ai_pb2.BenchmarkRow(
        row_no=r["row_no"], prompt_id=r["prompt_id"], category=r["category"],
        category_ko=r["category_ko"], category_en=r["category_en"], verdict=r["verdict"],
        expected=r["expected"], scan_target=r["scan_target"], language=r["language"],
        technique=r["technique"], expected_labels=list(r["expected_labels"] or []),
        severity=r["severity"], origin=r["origin"], prompt=r["prompt"],
        extra_json=json.dumps(r["extra"], ensure_ascii=False) if r["extra"] else "")


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

    # An upload carries a whole .jsonl in one message and the store accepts up to 32 MB, which is
    # past gRPC's 4 MB default — without this the large-file case fails at the transport with a
    # RESOURCE_EXHAUSTED that never reaches the store's own size check and its clearer message.
    limit = benchmark_store.MAX_UPLOAD_BYTES + (1 << 20)
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=8),
        options=[("grpc.max_receive_message_length", limit),
                 ("grpc.max_send_message_length", limit)])
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
