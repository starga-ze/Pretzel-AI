"""Benchtest runs: executing a set against the guardrail, and reading the results back."""

import logging
import time

import grpc

from src.benchmark import runner as benchmark_runner, store as benchmark_store
from src.grpc import pretzel_ai_pb2

log = logging.getLogger("pretzel-ai")


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
        language=c["language"], expected_action=c["expected_action"],
        observed_action=c["observed_action"],
        observed_detector=list(c.get("observed_detector") or []),
        expected_detector=list(c.get("expected_detector") or []),
        checkpoint=c.get("checkpoint") or "", outcome=c.get("outcome") or "",
        threats=list(c.get("threats") or []),
        cause=c["cause"], ok=bool(c["ok"]),
        excluded=c["ok"] is None, latency_ms=c["latency_ms"])

def _stored_case_msg(c):
    """The same message, read back from the database, where the row carries fewer of the set's
    columns — the listing joins nothing, so category/technique/language are not on it."""
    return pretzel_ai_pb2.RunCase(
        seq=c["seq"], prompt_id=c["prompt_id"], category=c.get("category") or "",
        technique=c.get("technique") or "", language=c.get("language") or "",
        expected_action=c["expected_action"], observed_action=c["observed_action"],
        observed_detector=list(c.get("observed_detector") or []),
        expected_detector=list(c.get("expected_detector") or []),
        checkpoint=c.get("checkpoint") or "", outcome=c.get("outcome") or "",
        threats=list(c.get("threats") or []), note=c.get("note") or "",
        cause=c["cause"], ok=bool(c["ok"]), excluded=c["ok"] is None,
        latency_ms=c["latency_ms"] or 0)

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

class BenchtestHandlers:
    """The benchmark.run / benchmark.run_case operations.

    A mixin: PretzelAiServicer composes it with the generated base. Kept out of the
    servicer because these methods change when this domain's contract does, and
    nothing else in the service has a reason to move with them.
    """

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
                             "language": request.language, "technique": request.technique,
                             "checkpoint": request.checkpoint},
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
            by_checkpoint=[pretzel_ai_pb2.BenchmarkBucket(**b)
                           for b in got.get("by_checkpoint", [])],
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
                             "language": request.language, "technique": request.technique,
                             "checkpoint": request.checkpoint},
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
            http_status=got["http_status"] or 0,
            contents_json=got.get("contents_json", ""),
            response=got["response"], raw_request=got["raw_request"],
            raw_response=got["raw_response"], tool_calls=got["tool_calls"])
