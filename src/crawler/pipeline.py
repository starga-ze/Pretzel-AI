"""The crawl: fetch every page the sitemap lists, keep the ones that are documents.

Why the crawler lives in pretzel-ai rather than in one of the C++ daemons:
Why this lives in pretzel-ai rather than in one of the C++ daemons: fetch, extract, hash and
(later) embed are one pipeline, not four steps that happen to run in sequence. The decision to
re-embed a page is made by comparing the hash of its *extracted* text against the stored one, so
splitting extraction away from embedding would put a process and a language boundary through the
middle of the only gate that keeps the embedding cost down. Two further facts settle it: the IPC
fabric caps a frame at 1 MiB (shared/ipc/IpcProtocol.h) while the largest observed page body is
1.3 MiB, and the extractor is DITA-shaped HTML work that has no reason to be rewritten in C++17.

There is one operation and no incremental path. Every run re-reads the sitemap and re-fetches
everything on it, which is slower than comparing timestamps and very much simpler: nothing is
remembered between runs, so nothing between runs can be wrong. The staleness gates that used to
live here were correct and still cost a schema of their own — lastmod, ETag, content hashes,
redirect markers — and each one was a place the store could disagree with the site.

What survives a crawl is what a reader can use: a URL with a title, a body, and a date. Everything
else is dropped at the point it is recognised rather than stored with a flag:

  404 / unreachable   the sitemap lists pages Palo Alto has removed
  redirect            whole URL subtrees 301 onto one page; the target is what gets stored, once
  no usable body      the content root is missing or renders to nothing (JS-built landing pages)
  no title            nothing was served to read one from
  nothing but its own headings  a section landing page: matches every query about its product,
                                answers none
  a top-level path    /dns-security, /hardware, /traps and forty-odd others are product landing
                      pages — marketing copy and a table of contents. /sitemap is on that list
                      too, and had put 939,897 characters of sitemap XML into the corpus.

Progress is yielded rather than returned so the gRPC layer can stream it, and so the caller can
stop consuming to cancel.
"""

import logging
from concurrent.futures import ThreadPoolExecutor

from src.crawler import sitemap, store
from src.crawler.extract import residual
from src.crawler.fetch import fetch, probe

BASE = "https://docs.paloaltonetworks.com"

log = logging.getLogger("pretzel-ai.crawler.pipeline")

# Network-bound, so more workers than cores — but low enough not to draw rate limiting. Eight
# sustained workers had docs.paloaltonetworks.com answering 403 to 155 pages that were serving
# normally minutes later. The crawl is never the priority: it runs beside a live assistant.
FETCH_WORKERS = 5

# The survey uses the same restraint but moves ~3x faster: HEAD carries no body.
PROBE_WORKERS = 5

# How often progress is reported and work committed.
BATCH = 50


def _is_landing(url):
    """True for the product landing pages, which are indexes rather than documentation.

    Judged by path depth because that is what separates them: /dns-security is a product's front
    page, /dns-security/administration/… is a page of its manual. Everything Palo Alto publishes as
    documentation sits at least two segments deep.
    """
    path = url[len(BASE):] if url.startswith(BASE) else url
    return len([segment for segment in path.split("/") if segment]) <= 1


def _document(url, result):
    """→ (title, text) when this fetch produced a document, else None with the reason logged."""
    if result.error or not result.text:
        return None
    title = (result.title or "").strip()
    if not title:
        return None
    # A page whose body is only its own headings and the template's boilerplate is a section
    # landing page. Structural rather than a length cutoff: the corpus holds a 5.1 MB CLI command
    # hierarchy with no sentence in it, which any prose-shaped rule would have discarded.
    if not residual(result.text):
        return None
    return title, result.text


def survey(urls):
    """HEAD every URL to find out what is really there. → (targets, stats)

    The sitemap lists more than it has. A fifth of its URLs 301 onto a page it also lists, and a
    few hundred are gone entirely, so a crawl told to fetch 21,916 pages ends with 17,300 documents
    and a progress bar that never reaches its own end. This pass resolves that before any of it is
    downloaded: redirects collapse onto their targets, missing pages drop out, and what remains is
    the number worth showing an operator.

    HEAD rather than GET because it answers the same question without the body — 20 pages/second
    against 6.
    """
    stats = {"listed": len(urls), "ok": 0, "redirect": 0, "missing": 0, "unknown": 0}
    targets = set()

    def resolve(url):
        status, location = probe(url)
        return url, status, location

    with ThreadPoolExecutor(max_workers=PROBE_WORKERS) as pool:
        for url, status, location in pool.map(resolve, urls):
            if status in (301, 302, 307, 308) and location:
                stats["redirect"] += 1
                targets.add(sitemap.canonical(location))
            elif status in (404, 410):
                stats["missing"] += 1
            elif status == 0:
                # Unreachable during the survey says nothing about the page; let the crawl decide.
                stats["unknown"] += 1
                targets.add(url)
            else:
                stats["ok"] += 1
                targets.add(url)

    return sorted(targets), stats


def crawl(conn, scope=None):
    """Re-fetch the whole sitemap. Yields progress; the last message has final=True.

    `scope` limits the run to one product (the first path segment), which is how a single product
    is refreshed without re-reading the rest.
    """
    pages = sitemap.fetch(max_age=0)
    if scope:
        pages = {u: f for u, f in pages.items() if f["product"] == scope}

    # Dropped before the fetch, not after: there is nothing to gain from downloading a landing
    # page to then discard it.
    listed = sorted(u for u in pages if not _is_landing(u))

    # The run is claimed after the survey, not before it. start_run writes a row that only this
    # generator will ever close, so claiming it before the first yield means a process killed in
    # between leaves a row marked running for ever — and the guard that reads it then refuses
    # every later crawl. The survey writes nothing, so there is nothing to record until it ends.
    yield {"stage": "survey", "done": 0, "total": len(listed), "final": False}
    urls, survey_stats = survey(listed)
    run_id = store.start_run(conn)
    log.info("survey: %s -> %d to fetch", survey_stats, len(urls))

    counts = {"listed": survey_stats["listed"], "stored": 0, "rejected": 0}
    kept = []

    yield {"stage": "start", "done": 0, "total": len(urls), "run_id": run_id,
           "survey": survey_stats, "final": False}

    try:
        with conn.cursor() as cur:
            done = 0
            with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as pool:
                for url, result in pool.map(lambda u: (u, fetch(u)), urls):
                    done += 1
                    doc = _document(url, result)
                    if doc is None:
                        counts["rejected"] += 1
                    else:
                        title, text = doc
                        # Stored under the URL the fetch ended on: a redirected page belongs to its
                        # target, and several aliases landing there collapse onto one row.
                        final_url = result.final_url or url
                        # Both lookups are misses waiting to happen. The survey replaces a
                        # redirecting URL with its target, and a target need not itself be listed
                        # in the sitemap — `pages[url]` on such a URL raised KeyError and took the
                        # whole crawl down 1,273 pages in. A page with no sitemap entry simply has
                        # no vendor timestamp, which is a missing field and not a failure.
                        lastmod = (pages.get(final_url, {}).get("lastmod")
                                   or pages.get(url, {}).get("lastmod"))
                        store.put(cur, final_url, title, text, lastmod)
                        kept.append(final_url)
                        counts["stored"] += 1

                    if done % BATCH == 0:
                        conn.commit()
                        yield {"stage": "fetch", "done": done, "total": len(urls),
                               "counts": dict(counts), "survey": survey_stats, "final": False}

            # A full crawl is the whole truth about what exists; anything not seen is gone. Only
            # when the run covered everything — a scoped run knows nothing about other products.
            if not scope and kept:
                removed = store.drop_missing(cur, kept)
                if removed:
                    log.info("dropped %d documents no longer listed", removed)
            conn.commit()
    except GeneratorExit:
        # The caller stopped consuming — the console cancelled, or its stream died. Not a failure:
        # everything committed so far stays, and the run has to be closed out here because nothing
        # else will. GeneratorExit descends from BaseException, not Exception, so the handler below
        # never sees it; without this branch the run stayed 'running' for ever and every later
        # update was refused as "a crawl is already running".
        conn.commit()
        store.finish_run(conn, run_id, "cancelled", counts)
        log.info("crawl cancelled after %d/%d", counts["stored"], len(urls))
        raise
    except Exception as exc:                     # noqa: BLE001 - reported, not swallowed
        conn.rollback()
        store.finish_run(conn, run_id, "failed", counts, str(exc))
        log.exception("crawl failed after %d/%d", counts["stored"], len(urls))
        yield {"stage": "failed", "error": str(exc), "counts": counts, "final": True}
        return

    store.finish_run(conn, run_id, "ok", counts)
    log.info("crawl complete: %s", counts)
    yield {"stage": "done", "done": len(urls), "total": len(urls),
           "counts": counts, "survey": survey_stats, "run_id": run_id, "final": True}
