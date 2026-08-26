"""Benchmark sets: the uploaded .jsonl files and the prompts inside them."""

import logging

import grpc

from src.benchmark import store as benchmark_store
from src.grpc import pretzel_ai_pb2

log = logging.getLogger("pretzel-ai")


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

class BenchmarkHandlers:
    """The benchmark.dataset / benchmark.row operations.

    A mixin: PretzelAiServicer composes it with the generated base. Kept out of the
    servicer because these methods change when this domain's contract does, and
    nothing else in the service has a reason to move with them.
    """

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
