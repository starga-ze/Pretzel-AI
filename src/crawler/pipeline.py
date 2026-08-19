"""check() and refresh(): the two operations the console card drives.

check() is cheap — one sitemap fetch and one query — and answers "what would a refresh do".
The console shows that answer to the operator before anything is downloaded, so a refresh is
never a blind 21,768-page fetch.

refresh() is the expensive half, and is written as a generator that yields progress rather than
returning at the end. That shape is what lets the gRPC layer stream RefreshProgress to the
console while the work runs, and it is also what makes the operation interruptible: the caller
stops consuming and the crawl stops.

The three gates, in the order they cost money:

  1. sitemap lastmod   — free (already fetched). Says a page *might* have moved.
  2. If-Modified-Since — one request, no body on a 304. Says whether the server agrees.
  3. sha256 of text    — the only one that decides. lastmod moves in wholesale republishes
                         (two dozen pages sharing a timestamp to the second), so without this
                         gate a refresh re-derives everything downstream for pages whose text
                         is byte-identical to what is already stored.

Ahead of all three sits redirect collapsing. Whole subtrees of this site 301 onto a single page —
110 URLs under one custom-signature-contexts branch land on the same Advanced Threat Prevention
document — and once a previous crawl has recorded where an alias ends, refetching it is downloading
a page this run already has. Aliases are resolved from their target's result instead.
"""

import logging
from concurrent.futures import ThreadPoolExecutor

from src.crawler import sitemap, store
from src.crawler.fetch import Result, fetch

log = logging.getLogger("pretzel-ai.crawler.pipeline")

# Network-bound, so more workers than cores — but lower than it was. Eight sustained workers drew
# rate-limiting from docs.paloaltonetworks.com on a full crawl (155 pages came back 403 and were
# serving normally on a later request), and the retry backoff only cleans that up after the fact.
# The crawl is never the priority here: it runs on an appliance beside a live assistant, and half
# an hour versus forty minutes is not worth being throttled for.
FETCH_WORKERS = 5


class Change:
    """One pending unit of work, as shown to the operator before they confirm."""

    __slots__ = ("url", "kind", "product", "version", "docset", "section_path",
                 "lastmod", "previous_lastmod", "unconditional", "title")

    def __init__(self, url, kind, facets, lastmod, previous_lastmod=None,
                 unconditional=False, title=None):
        self.url = url
        # Set when this page is being refetched because what is stored is unusable rather than
        # because the sitemap moved. Such a fetch must not be conditional: the server would answer
        # 304 — correctly, nothing changed — and the unusable copy would survive the retry that
        # existed to replace it.
        self.unconditional = unconditional
        # added | changed | retry | removed. `retry` is deliberately not `changed`: the page did
        # not change, we failed to read it. Reporting 220 unreadable pages as 220 edits tells the
        # operator the documentation moved under them when what actually happened is that a crawl
        # got throttled.
        self.kind = kind
        self.product = facets["product"]
        self.version = facets["version"]
        self.docset = facets["docset"]
        self.section_path = facets["section_path"]
        self.lastmod = lastmod
        self.previous_lastmod = previous_lastmod
        # Only known for a page seen before: the sitemap carries no titles, so a newly added URL
        # has nothing to show but its path until it has been fetched once.
        self.title = title

    def as_dict(self):
        return {"url": self.url, "kind": self.kind, "product": self.product,
                "version": self.version, "docset": self.docset, "title": self.title,
                "lastmod": self.lastmod.isoformat() if self.lastmod else None,
                "previous_lastmod": (self.previous_lastmod.isoformat()
                                     if self.previous_lastmod else None)}


def check(conn, scope=None, pages=None):
    """→ (changes, total_in_scope). Nothing is fetched beyond the sitemap itself.

    `scope` filters by product ('ngfw'); None means the whole sitemap. `pages` lets a caller
    that already holds a parsed sitemap reuse it instead of downloading it twice.
    """
    pages = sitemap.fetch() if pages is None else pages
    if scope:
        pages = {u: f for u, f in pages.items() if f["product"] == scope}

    known = store.load_documents(conn)
    changes = []

    for url, facets in pages.items():
        previous = known.get(url)
        if previous is None:
            changes.append(Change(url, "added", facets, facets["lastmod"]))
            continue
        # A tombstoned URL that reappears in the sitemap is a restoration, not an edit.
        if previous["deleted_at"] is not None:
            changes.append(Change(url, "added", facets, facets["lastmod"],
                                  previous["lastmod"]))
            continue
        # A page that did not come back usable last time is always a candidate, whatever its
        # lastmod says. Nothing about a failed fetch changes the sitemap, so a lastmod-only rule
        # would freeze the failure permanently — and the failures that matter most are transient.
        # A full crawl recorded 155 throttled 403s that were all serving normally minutes later.
        #
        # An empty stored body counts as unusable even though the fetch reported success: pages
        # crawled before the extractor learned to reject those are sitting on zero-character
        # content rows with no error to find them by.
        # Never verified for redirects. Such a row may be holding a body that belongs to a page it
        # silently 301'd to, which reads as a clean fetch and no error-based rule can find.
        if not previous.get("redirect_checked"):
            changes.append(Change(url, "retry", facets, facets["lastmod"],
                                  previous["lastmod"], unconditional=True,
                                  title=previous.get("title")))
            continue

        if (previous.get("fetch_error")
                or previous["content_sha"] is None
                or not previous.get("char_count")):
            changes.append(Change(url, "retry", facets, facets["lastmod"],
                                  previous["lastmod"], unconditional=True,
                                  title=previous.get("title")))
            continue

        stored = previous["lastmod"]
        if facets["lastmod"] and (stored is None or facets["lastmod"] > stored):
            changes.append(Change(url, "changed", facets, facets["lastmod"], stored,
                                  title=previous.get("title")))

    # Gone from the sitemap: tombstone candidates. Restricted to the scope under examination so
    # a per-product refresh cannot tombstone pages it never looked at.
    for url, previous in known.items():
        if url in pages or previous["deleted_at"] is not None:
            continue
        facets = sitemap.classify(url)
        if scope and facets["product"] != scope:
            continue
        changes.append(Change(url, "removed", facets, None, previous["lastmod"],
                              title=previous.get("title")))

    log.info("check: %d pages in scope, %d changes (%s)", len(pages), len(changes),
             ", ".join(f"{k}={sum(1 for c in changes if c.kind == k)}"
                       for k in ("added", "changed", "retry", "removed")))
    return changes, len(pages)


def refresh(conn, changes, scope=None):
    """Apply `changes`. Yields progress dicts; the final one carries done=True and the counts.

    Committed in batches rather than in one transaction: a 21,768-page crawl held open as a
    single transaction would keep an hours-long snapshot on a database that is also serving
    retrieval, and would lose every page if it failed on the last one.
    """
    counts = {"checked": len(changes), "fetched": 0, "changed": 0, "added": 0,
              "removed": 0, "skipped_304": 0, "skipped_same_sha": 0, "skipped_alias": 0,
              "failed": 0}
    run_id = store.start_run(conn, scope)
    known = store.load_documents(conn)

    removals = [c for c in changes if c.kind == "removed"]
    work = [c for c in changes if c.kind != "removed"]

    # Known aliases, from what previous crawls recorded. Their targets are fetched first so an
    # alias can be answered out of the target's result rather than out of a second download.
    alias_target = {
        url: entry["canonical_url"]
        for url, entry in known.items()
        if entry.get("canonical_url") and entry["canonical_url"] != url
    }
    primary = [c for c in work if c.url not in alias_target]
    aliases = [c for c in work if c.url in alias_target]

    yield {"stage": "start", "done": 0, "total": len(work), "run_id": run_id, "done_flag": False}

    try:
        with conn.cursor() as cur:
            if removals:
                counts["removed"] = store.mark_deleted(cur, [c.url for c in removals])
                conn.commit()
                yield {"stage": "tombstone", "done": 0, "total": len(work),
                       "removed": counts["removed"], "done_flag": False}

            def job(change):
                previous = known.get(change.url) or {}
                since = None if change.unconditional else previous.get("last_modified")
                return change, fetch(change.url, last_modified=since)

            completed = 0
            # Keyed by both the URL asked for and the URL the fetch ended on, so an alias finds
            # its target's body whichever of the two it was recorded under.
            fetched_sha = {}

            with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as pool:
                for change, result in pool.map(job, primary):
                    completed += 1

                    if result.not_modified:
                        counts["skipped_304"] += 1
                        store.touch_seen(cur, change.url, change.lastmod)
                    elif result.error:
                        counts["failed"] += 1
                        store.put_document(cur, change.url,
                                           {"product": change.product, "version": change.version,
                                            "docset": change.docset,
                                            "section_path": change.section_path},
                                           change.lastmod, result, None)
                    else:
                        counts["fetched"] += 1
                        digest = store.sha256(result.text)
                        unchanged = (known.get(change.url) or {}).get("content_sha") == digest
                        if unchanged:
                            counts["skipped_same_sha"] += 1
                        else:
                            store.put_content(cur, result.text)
                            counts["added" if change.kind == "added" else "changed"] += 1
                        fetched_sha[change.url] = digest
                        fetched_sha[result.final_url] = digest
                        store.put_document(cur, change.url,
                                           {"product": change.product, "version": change.version,
                                            "docset": change.docset,
                                            "section_path": change.section_path},
                                           change.lastmod, result, digest)

                    if completed % 50 == 0:
                        conn.commit()
                        yield {"stage": "fetch", "done": completed, "total": len(work),
                               "counts": dict(counts), "done_flag": False}

                # Aliases second, now that every target this run touched has a body.
                for change in aliases:
                    completed += 1
                    facets = {"product": change.product, "version": change.version,
                              "docset": change.docset, "section_path": change.section_path}
                    digest = fetched_sha.get(alias_target[change.url])

                    if digest is not None:
                        counts["skipped_alias"] += 1
                        # A synthetic result: the fetch that produced this body already happened,
                        # under the target's URL. Recorded as the redirect it is, not as a 200 this
                        # alias served.
                        alias_result = Result(change.url, status=301,
                                              final_url=alias_target[change.url])
                        store.put_document(cur, change.url, facets, change.lastmod,
                                           alias_result, digest)
                        continue

                    # The target was not part of this run — fetch normally and let the redirect be
                    # followed, which is also how the alias got recorded in the first place.
                    since = (None if change.unconditional
                             else (known.get(change.url) or {}).get("last_modified"))
                    result = fetch(change.url, last_modified=since)
                    if result.not_modified:
                        counts["skipped_304"] += 1
                        store.touch_seen(cur, change.url, change.lastmod)
                    elif result.error:
                        counts["failed"] += 1
                        store.put_document(cur, change.url, facets, change.lastmod, result, None)
                    else:
                        counts["fetched"] += 1
                        digest = store.sha256(result.text)
                        if (known.get(change.url) or {}).get("content_sha") == digest:
                            counts["skipped_same_sha"] += 1
                        else:
                            store.put_content(cur, result.text)
                            counts["added" if change.kind == "added" else "changed"] += 1
                        store.put_document(cur, change.url, facets, change.lastmod, result, digest)

                    if completed % 50 == 0:
                        conn.commit()
                        yield {"stage": "fetch", "done": completed, "total": len(work),
                               "counts": dict(counts), "done_flag": False}

                # Bodies the run has just orphaned — a page that changed leaves its previous
                # text behind with nothing pointing at it.
                pruned = store.prune_orphan_content(cur)
                if pruned:
                    log.info("pruned %d orphaned content rows", pruned)

            conn.commit()
    except Exception as exc:                     # noqa: BLE001 - reported, not swallowed
        conn.rollback()
        store.finish_run(conn, run_id, "failed", counts, str(exc))
        log.exception("refresh failed after %d/%d", counts["fetched"], len(work))
        yield {"stage": "failed", "error": str(exc), "counts": counts, "done_flag": True}
        return

    store.finish_run(conn, run_id, "ok", counts)
    log.info("refresh complete: %s", counts)
    yield {"stage": "done", "done": len(work), "total": len(work),
           "counts": counts, "run_id": run_id, "done_flag": True}
