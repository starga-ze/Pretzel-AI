"""Cancellable corpus refresh: discover, classify, keep what is documentation.

A run REBUILDS the corpus rather than reconciling with it. Whatever the newest completed run
collected is the whole of techdoc.document; anything it excluded or could not read is simply not
there. That is the whole model, and it is the reason there is no archive, no deletion candidate
and no removal count to reconcile - a page is in the corpus because this run put it there.

Written as a swap rather than as "empty the table, then fill it": every row carries the run that
wrote it, and the rows belonging to older runs are dropped in one statement once the fetch has
finished. A crawl that dies halfway therefore leaves the previous corpus standing, which an
hour and a half of fetching makes worth insisting on.
"""
import logging
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED

from src.crawler import sitemap, store
from src.crawler.fetch import fetch, Result, Cancelled, check
from src.crawler.extract import COLLECTED, EXCLUDED, UNKNOWN

log = logging.getLogger(__name__)
FETCH_WORKERS = 4

# The one thing a rebuild cannot survive: a sitemap that answers with a fraction of what it holds.
# Reconciliation used to absorb that - a page missing from the sitemap was refetched and kept on
# its own evidence - but a rebuild takes the sitemap at its word, so a truncated one silently
# becomes a truncated corpus. Refused outright rather than warned about, because the run that
# would follow the warning is the one that does the damage.
MIN_COVERAGE = .7


def crawl(conn, scope=None, dry_run=False, cancel=None):
    cancel = cancel or threading.Event()
    run_id = store.claim(conn, scope, dry_run)
    # The three outcomes carry the same names here as on the decision column and on screen. Only
    # `collected` reaches the corpus; the other two are recorded so an operator can review the
    # URLs afterwards, and are otherwise the run saying what it left out.
    counts = dict(listed=0, processed=0, collected=0, excluded=0, unknown=0,
                  redirects=0, dry_run=dry_run)
    pool = None
    finished = False
    try:
        yield dict(stage='discover', run_id=run_id, counts=dict(counts), final=False)
        check(cancel)
        previous = store.previous_listed(conn, scope)
        pages = sitemap.fetch(max_age=0, cancel=cancel)
        listed = sorted(u for u in pages
                        if sitemap.eligible(u) and (not scope or pages[u]['product'] == scope))
        if not listed:
            raise ValueError('No documentation candidates in sitemap for requested scope')
        if previous and len(listed) < previous * MIN_COVERAGE:
            raise ValueError(f'Sitemap lists {len(listed)} pages against {previous} last time; '
                             'refusing to rebuild the corpus from it')
        total = counts['listed'] = counts['total'] = len(listed)
        urls = iter(listed)
        reasons = Counter()
        pool = ThreadPoolExecutor(max_workers=FETCH_WORKERS)
        pending = {}

        def submit():
            url = next(urls, None)
            if url is not None:
                pending[pool.submit(fetch, url, cancel)] = url

        for _ in range(FETCH_WORKERS):
            submit()
        last_heartbeat = 0
        current_url = ''
        while pending:
            check(cancel)
            ready, _ = wait(pending, timeout=.5, return_when=FIRST_COMPLETED)
            for future in ready:
                original = pending.pop(future)
                result = future.result()
                check(cancel)
                final = result.final_url or original
                current_url = final
                if result.status == 200 and not sitemap.eligible(final):
                    result.decision, result.reason = EXCLUDED, 'excluded_destination'
                if result.decision == COLLECTED and scope and sitemap.classify(final)['product'] != scope:
                    result.decision, result.reason = UNKNOWN, 'redirect_outside_scope'
                counts['processed'] += 1
                counts['redirects'] += int(final != original)
                reasons[result.reason] += 1
                with conn.cursor() as cur:
                    store.observe(cur, run_id, result)
                    if result.decision == COLLECTED:
                        if not dry_run:
                            store.put(cur, run_id, final, result.title, result.text,
                                      pages.get(final, pages.get(original, {})).get('lastmod'),
                                      result.metadata)
                        counts['collected'] += 1
                    elif result.decision == EXCLUDED:
                        counts['excluded'] += 1
                    else:
                        counts['unknown'] += 1
                submit()
            if time.monotonic() - last_heartbeat >= 1 or not pending:
                counts['reasons'] = dict(reasons)
                store.heartbeat(conn, run_id, counts)
                last_heartbeat = time.monotonic()
                yield dict(stage='fetch', done=counts['processed'], total=total,
                           current_url=current_url, run_id=run_id, counts=dict(counts), final=False)
        pool.shutdown(wait=True)
        pool = None
        yield dict(stage='reconcile', done=total, total=total, run_id=run_id,
                   counts=dict(counts), final=False)
        check(cancel)
        # The swap. Everything this run did not write belongs to a corpus that no longer exists,
        # and it goes in one statement so the table is never half of each.
        if not dry_run:
            with conn.cursor() as cur:
                store.retain_only(cur, run_id, scope)
        check(cancel)
        store.finish_run(conn, run_id, 'ok', counts)
        finished = True
        yield dict(stage='done', done=total, total=total, run_id=run_id,
                   counts=dict(counts), final=True)
    except (GeneratorExit, Cancelled):
        cancel.set()
        conn.rollback()
        if not finished:
            store.finish_run(conn, run_id, 'cancelled', counts)
        # gRPC cancellation may close the generator; never yield from GeneratorExit handling.
        raise
    except Exception as exc:
        cancel.set()
        conn.rollback()
        store.finish_run(conn, run_id, 'failed', counts, str(exc))
        log.exception('Corpus refresh failed')
        yield dict(stage='failed', error=str(exc), run_id=run_id, counts=dict(counts), final=True)
    finally:
        cancel.set()
        if pool:
            pool.shutdown(wait=True, cancel_futures=True)
        store.release(conn)
