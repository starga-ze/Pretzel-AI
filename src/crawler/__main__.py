"""Operator commands for migration, corpus rebuild and audit."""
import argparse
import json
import logging
import threading
from src.crawler import pipeline, store
from src.crawler.fetch import Cancelled


def main():
    parser = argparse.ArgumentParser(prog='python -m src.crawler')
    sub = parser.add_subparsers(dest='command',required=True)
    crawl = sub.add_parser('crawl')
    crawl.add_argument('--scope',default='')
    crawl.add_argument('--dry-run',action='store_true',help='Record decisions without changing the active corpus')
    crawl.add_argument('--yes',action='store_true')
    sub.add_parser('status')
    sub.add_parser('migrate')
    audit = sub.add_parser('audit')
    audit.add_argument('run_id',type=int)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    with store.connect() as conn:
        if args.command == 'migrate':
            store.migrate(conn)
            print('Corpus migration applied.')
        elif args.command == 'status':
            print(json.dumps(store.status(conn),indent=2))
        elif args.command == 'audit':
            for row in conn.execute('SELECT url,final_url,decision,reason,http_status,detail FROM techdoc.crawl_observation WHERE run_id=%s ORDER BY decision,url',(args.run_id,)):
                print(json.dumps(dict(zip(('url','final_url','decision','reason','http_status','detail'),row))))
        else:
            if not args.yes and input('Refresh technical documentation? [y/N] ').lower() != 'y':
                return 0
            cancel = threading.Event()
            progress = pipeline.crawl(conn,scope=args.scope or None,dry_run=args.dry_run,cancel=cancel)
            try:
                for update in progress:
                    print(json.dumps(update),flush=True)
                    if update['final'] and update.get('error'):
                        return 1
            except (KeyboardInterrupt,Cancelled):
                cancel.set()
                return 130
            finally:
                progress.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
