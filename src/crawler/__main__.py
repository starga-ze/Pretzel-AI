"""python -m src.crawler — the operator-side entry point.

    python -m src.crawler check   [--scope ngfw]
    python -m src.crawler refresh [--scope ngfw] [--yes]
    python -m src.crawler status

The console card drives the same two operations over gRPC. This CLI exists for the one case the
card is wrong for: the very first build, where every page in the sitemap is "added" and the fetch
runs for half an hour. That is a job to start from a terminal and leave running, not one to hold a
browser window open for.
"""

import argparse
import logging
import sys

from src import log as pa_log
from src.crawler import pipeline, sitemap, store


def _print_changes(changes, total, limit=20):
    kinds = {}
    for change in changes:
        kinds[change.kind] = kinds.get(change.kind, 0) + 1
    print(f"\n{total} pages in scope, {len(changes)} changes")
    for kind in ("added", "changed", "removed"):
        if kinds.get(kind):
            print(f"  {kind:8s} {kinds[kind]}")
    if not changes:
        return
    print()
    for change in changes[:limit]:
        stamp = change.lastmod.date().isoformat() if change.lastmod else "-"
        print(f"  [{change.kind:7s}] {stamp}  {change.url}")
    if len(changes) > limit:
        print(f"  ... and {len(changes) - limit} more")


def cmd_check(args):
    with store.connect() as conn:
        changes, total = pipeline.check(conn, scope=args.scope)
    _print_changes(changes, total)
    return 0


def cmd_refresh(args):
    with store.connect() as conn:
        changes, total = pipeline.check(conn, scope=args.scope)
        _print_changes(changes, total)
        if not changes:
            print("\nNothing to do.")
            return 0
        if not args.yes:
            print("\nThis operation is not performed asynchronously.")
            if input("Proceed? [y/N] ").strip().lower() not in ("y", "yes"):
                print("Aborted.")
                return 1

        print()
        for progress in pipeline.refresh(conn, changes, scope=args.scope):
            if progress["stage"] == "fetch":
                counts = progress["counts"]
                print(f"\r  {progress['done']}/{progress['total']}  "
                      f"fetched={counts['fetched']} 304={counts['skipped_304']} "
                      f"same-sha={counts['skipped_same_sha']} "
                      f"alias={counts['skipped_alias']} failed={counts['failed']}",
                      end="", flush=True)
            elif progress["done_flag"]:
                print()
                if progress["stage"] == "failed":
                    print(f"[ERROR] {progress['error']}")
                    return 1
                counts = progress["counts"]
                print("\nDone.")
                for key in ("added", "changed", "removed", "skipped_304",
                            "skipped_same_sha", "skipped_alias", "failed"):
                    print(f"  {key:16s} {counts[key]}")
    return 0


def cmd_status(args):
    with store.connect() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT count(*) FILTER (WHERE deleted_at IS NULL),
                   count(*) FILTER (WHERE deleted_at IS NOT NULL),
                   count(DISTINCT content_sha)
              FROM techdoc.document
        """)
        live, gone, bodies = cur.fetchone()
        cur.execute("SELECT count(*), coalesce(sum(char_count), 0) FROM techdoc.content")
        rows, chars = cur.fetchone()
        print(f"documents   {live} live, {gone} tombstoned")
        print(f"content     {rows} bodies ({chars:,} chars)")
        print(f"dedup       {live} documents -> {bodies} distinct bodies")
        cur.execute("""
            SELECT id, started_at, finished_at, status, checked, fetched, failed
              FROM techdoc.crawl_run ORDER BY id DESC LIMIT 5
        """)
        runs = cur.fetchall()
        if runs:
            print("\nrecent runs")
            for run in runs:
                print(f"  #{run[0]} {run[1]:%Y-%m-%d %H:%M} {run[3]:9s} "
                      f"checked={run[4]} fetched={run[5]} failed={run[6]}")
    return 0


def main():
    parser = argparse.ArgumentParser(prog="python -m src.crawler",
                                     description="pretzel-ai tech-doc crawler")
    sub = parser.add_subparsers(dest="command", required=True)

    for name, handler, needs_yes in (("check", cmd_check, False),
                                     ("refresh", cmd_refresh, True),
                                     ("status", cmd_status, False)):
        sp = sub.add_parser(name)
        sp.set_defaults(handler=handler)
        if name != "status":
            sp.add_argument("--scope", default=None,
                            help="limit to one product (e.g. ngfw); default is the whole sitemap")
        if needs_yes:
            sp.add_argument("--yes", action="store_true", help="skip the confirmation prompt")

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    sys.exit(args.handler(args))


if __name__ == "__main__":
    main()
