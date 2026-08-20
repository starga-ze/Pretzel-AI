"""python -m src.crawler — the operator-side entry point.

    python -m src.crawler crawl  [--scope ngfw] [--yes]
    python -m src.crawler status

One operation: re-fetch everything the sitemap lists and keep what is a document. The console
drives the same thing from System Management ▸ Operation ▸ Tech Documentation; this exists for
running it from a terminal, where a forty-minute job does not need a browser window held open.
"""

import argparse
import logging
import sys

from src.crawler import pipeline, store


def cmd_crawl(args):
    with store.connect() as conn:
        in_flight = store.running_run(conn)
        if in_flight:
            print(f"[*] crawl #{in_flight[0]} is already running "
                  f"(started {in_flight[1]:%Y-%m-%d %H:%M}).")
            return 1

        if not args.yes:
            print("This re-fetches every page in the sitemap and replaces the corpus.")
            if input("Proceed? [y/N] ").strip().lower() not in ("y", "yes"):
                print("Aborted.")
                return 1

        for progress in pipeline.crawl(conn, scope=args.scope):
            if progress["stage"] == "survey":
                print(f"  surveying {progress['total']:,} URLs (HEAD)…", flush=True)
            elif progress["stage"] == "start":
                sv = progress.get("survey") or {}
                print(f"  survey: {sv.get('ok',0):,} pages, {sv.get('redirect',0):,} redirect, "
                      f"{sv.get('missing',0):,} missing → {progress['total']:,} to fetch")
            elif progress["stage"] == "fetch":
                c = progress["counts"]
                print(f"\r  {progress['done']}/{progress['total']}  "
                      f"stored={c['stored']} rejected={c['rejected']}", end="", flush=True)
            elif progress["final"]:
                print()
                if progress["stage"] == "failed":
                    print(f"[ERROR] {progress['error']}")
                    return 1
                c = progress["counts"]
                print(f"\nDone. listed={c['listed']} stored={c['stored']} rejected={c['rejected']}")
    return 0


def cmd_status(args):
    with store.connect() as conn:
        snapshot = store.status(conn)
        tree = store.product_tree(conn)
    print(f"documents   {snapshot['documents']:,}")
    print(f"bodies      {snapshot['bodies']:,} distinct ({snapshot['chars']:,} chars)")
    print(f"last crawl  {snapshot['last_run_at'][:19].replace('T', ' ')} "
          f"{snapshot['last_run_status']}")
    print(f"\nproducts    {len({r['product'] for r in tree})}")
    for row in tree[:10]:
        label = f"{row['product']}/{row['docset']}" if row["docset"] else row["product"]
        print(f"  {label[:48]:50s} {row['documents']:6,}")
    return 0


def main():
    parser = argparse.ArgumentParser(prog="python -m src.crawler",
                                     description="pretzel-ai tech-doc crawler")
    sub = parser.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("crawl")
    sp.set_defaults(handler=cmd_crawl)
    sp.add_argument("--scope", default=None, help="limit to one product (e.g. ngfw)")
    sp.add_argument("--yes", action="store_true", help="skip the confirmation prompt")

    sp = sub.add_parser("status")
    sp.set_defaults(handler=cmd_status)

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    sys.exit(args.handler(args))


if __name__ == "__main__":
    main()
