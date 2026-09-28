"""The crawl: fetch every page the sitemap lists, keep the ones that are documents.

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
import time
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

# How often work is committed. Not how often progress is reported - the two were one number
# and that is why the card looked frozen: a commit every fifty pages is right, an update every
# fifty pages is one redraw every eight seconds.
BATCH = 50

# The floor between two progress messages. A page takes ~170ms, so without this the stream
# carries ~40,000 updates in a run and mgmtd re-renders the card faster than anyone can read a
# URL. Slow enough to read, fast enough that the line is always visibly moving.
PROGRESS_INTERVAL_SEC = 0.25

# Path roots that are never documentation, whatever they hold.
#
#   translated  the localised trees - /translated/ko-kr, /translated/ja-jp and eleven more. Each
#               is one locale index page, not a translated manual, so there is no Korean corpus
#               here to keep; and were there one, thirteen near-identical copies of the English
#               text is exactly what an embedding index must not hold.
EXCLUDED_ROOTS = frozenset({"translated"})

# A cover page is recognised by where its H1 sits, not by how long it is.
#
# Every page opens with the same masthead - "Updated on ...", the product, the book, the title -
# and a real topic then starts its own H1 within a few lines of the top. A book's cover page has
# no topic to start: what follows its masthead is the version picker, so the first H1 (if there
# is one at all) is pushed well down the page and there is almost nothing under it.
#
# Both halves are needed, and both were arrived at by measuring the corpus rather than by taste:
#
#   * Length alone is wrong. Pages of 160-190 residual characters include the PAN-OS addressed-
#     issues lists ("PAN-272809 | A fix was made to address CVE-2024-0012") and the Prisma Access
#     alert-code pages - short by nature and exactly what a support assistant is asked about.
#     Their H1 is at the top, so the position test keeps them.
#   * H1 position alone is wrong. best-practices topics carry a version picker too, which pushes
#     their H1 to line 9-15; they survive on having 1,000-1,500 characters under it.
#
# A third candidate, DITA's <shortdesc>, was measured and discarded: ngfw/help, network-security,
# panorama, prisma-sd-wan/ion-cli-reference and saas-security do not emit it at all, so it would
# have dropped whole products - 37% of a stratified sample, including a 3,146-character SAML
# procedure. The numbers here are deliberately far from the decision boundary: raising the
# residual floor from 500 to 2,000 changes the verdict on 16 of 17,307 pages.
MASTHEAD_LINES = 6
COVER_RESIDUAL_MAX = 500

# A path root holding fewer documents than this is not a manual. See store.prune_small_products
# for what these actually are and why the rule counts rather than names them.
MIN_PRODUCT_DOCS = 20


def _is_landing(url):
    """True for the product landing pages, which are indexes rather than documentation.

    Judged by path depth because that is what separates them: /dns-security is a product's front
    page, /dns-security/administration/… is a page of its manual. Everything Palo Alto publishes as
    documentation sits at least two segments deep.
    """
    path = url[len(BASE):] if url.startswith(BASE) else url
    return len([segment for segment in path.split("/") if segment]) <= 1


def _excluded_root(url):
    """True for a URL under a path root that is never documentation."""
    path = url[len(BASE):] if url.startswith(BASE) else url
    segments = [segment for segment in path.split("/") if segment]
    return bool(segments) and segments[0] in EXCLUDED_ROOTS


def _is_document_url(url):
    """Both URL-shaped rules, asked together.

    Applied twice on purpose: once to the sitemap's list, to not fetch what will be discarded,
    and once to the URL a fetch ENDED on. The second is not redundant - a page that 301s onto
    the site root was stored under the root, because the first check only ever saw the listed
    URL and the redirect target is by definition not the URL that was checked.
    """
    return not _is_landing(url) and not _excluded_root(url)


def _is_cover_page(text, body):
    """True for a book's cover page: a masthead, a version picker, and no topic under them.

    `body` is the already-computed residual, passed in rather than recomputed because the caller
    needs it too and it walks the whole document.
    """
    lines = [line for line in text.split("\n") if line.strip()]
    # The renderer emits a bare "#" where a topic has no title of its own, so an H1 is not
    # always "# " - the IoT integration pages are titled that way and are real documents.
    first_h1 = next((i for i, line in enumerate(lines)
                     if line.rstrip() == "#" or line.startswith("# ")), None)
    return ((first_h1 is None or first_h1 > MASTHEAD_LINES)
            and len(body) < COVER_RESIDUAL_MAX)


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
    body = residual(result.text)
    if not body:
        return None
    if _is_cover_page(result.text, body):
        return None
    return title, result.text


def survey(urls):
    """HEAD every URL to find out what is really there. Yields progress; RETURNS (targets, stats).

    Two passes, and the second is what makes the run's numbers legible. A redirect resolves onto
    a page the sitemap need not list itself, and those destinations used to join the fetch list
    without ever being probed - so Ok counted the pages that answered 200 while the fetch counted
    something larger, and the gap (21,644 surveyed, 18,062 to fetch) had no explanation on screen.
    Pass two probes exactly those destinations and files each under Ok or Not found like any other
    URL, which leaves one invariant worth having:

        Ok + Redirect + Not found + Unreachable  =  URLs surveyed
        Ok + Unreachable                         =  pages the fetch will visit

    It costs almost nothing: 3,211 redirects produced 125 destinations worth a second look, the
    rest being pages this pass was already resolving anyway.

    A generator rather than a plain function because it is the longest silent stretch of a run:
    21,644 HEADs at five workers is about eighteen minutes during which the old version reported
    nothing, so the console drew a full-width placeholder bar and the operator had no way to tell
    a working survey from a hung one. The caller collects the return value with `yield from`.

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

    seen = set(urls)        # what pass one already has an answer for
    pending = set()         # redirect destinations the sitemap never listed
    done, last_emit, total = 0, 0.0, len(urls)

    with ThreadPoolExecutor(max_workers=PROBE_WORKERS) as pool:
        for url, status, location in pool.map(resolve, urls):
            done += 1
            if status in (301, 302, 307, 308) and location:
                stats["redirect"] += 1
                destination = sitemap.canonical(location)
                # Held back rather than counted as a target. Almost all of them are pages this
                # pass is already resolving on their own account - a product's whole version
                # history points at one current page - and those need no second look.
                if destination not in seen:
                    pending.add(destination)
            elif status in (404, 410):
                stats["missing"] += 1
            elif status == 0:
                # Unreachable during the survey says nothing about the page; let the crawl decide.
                stats["unknown"] += 1
                targets.add(url)
            else:
                stats["ok"] += 1
                targets.add(url)

            now = time.monotonic()
            if now - last_emit >= PROGRESS_INTERVAL_SEC or done == total:
                last_emit = now
                yield {"stage": "survey", "done": done, "total": total,
                       "current_url": url, "survey": dict(stats), "final": False}

        # Pass two: the destinations nothing has an answer for yet, resolved the same way the
        # sitemap's own URLs were. Without it those pages entered the fetch list unexamined and
        # the card could not be made to add up - Ok counted one thing and the fetch another.
        # Now every URL the crawl will visit has been probed, so Ok IS the fetch list.
        if pending:
            extra = sorted(pending)
            total += len(extra)
            stats["listed"] += len(extra)
            for url, status, location in pool.map(resolve, extra):
                done += 1
                if status == 0:
                    stats["unknown"] += 1
                    targets.add(url)
                elif 200 <= status < 300:
                    stats["ok"] += 1
                    targets.add(url)
                else:
                    # Gone, or redirecting again. A second hop is not chased: its destination is
                    # either a page this survey already resolved - in which case it is in the
                    # list already - or one Palo Alto publishes nowhere, which is not a document
                    # this corpus is missing.
                    stats["missing"] += 1

                now = time.monotonic()
                if now - last_emit >= PROGRESS_INTERVAL_SEC or done == total:
                    last_emit = now
                    yield {"stage": "survey", "done": done, "total": total,
                           "current_url": url, "survey": dict(stats), "final": False}

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
    listed = sorted(u for u in pages if _is_document_url(u))

    # The run is claimed after the survey, not before it. start_run writes a row that only this
    # generator will ever close, so claiming it before the first yield means a process killed in
    # between leaves a row marked running for ever — and the guard that reads it then refuses
    # every later crawl. The survey writes nothing, so there is nothing to record until it ends.
    yield {"stage": "survey", "done": 0, "total": len(listed), "final": False}
    # yield from: the survey's own progress messages go straight to the caller and its return
    # value lands here. The generator is what makes those eighteen minutes visible.
    urls, survey_stats = yield from survey(listed)
    run_id = store.start_run(conn)
    log.info("survey: %s -> %d to fetch", survey_stats, len(urls))

    counts = {"listed": survey_stats["listed"], "stored": 0, "rejected": 0}
    kept = []          # written this run
    unread = []        # attempted and not judged - protected from drop_missing, not stored

    try:
        # Inside the try, and that is load-bearing. start_run has just written a row that only
        # this generator will ever close, so every suspension point from here on must sit where
        # GeneratorExit can be caught. This yield used to sit above the try: a console cancelled
        # at exactly this moment - the instant the survey ends, which is where an operator tired
        # of waiting clicks - left the row 'running' for ever, and a stuck row refuses every
        # later crawl on the appliance. Run #5 died that way on 2026-09-21.
        yield {"stage": "start", "done": 0, "total": len(urls), "run_id": run_id,
               "survey": survey_stats, "final": False}

        with conn.cursor() as cur:
            done, last_emit = 0, 0.0
            with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as pool:
                for url, result in pool.map(lambda u: (u, fetch(u)), urls):
                    done += 1
                    doc = _document(url, result)
                    # Stored under the URL the fetch ended on: a redirected page belongs to its
                    # target, and several aliases landing there collapse onto one row.
                    final_url = result.final_url or url
                    # The URL rule again, on where the fetch LANDED rather than where it was
                    # aimed. This is what keeps a redirect onto the site root out. Asked here
                    # rather than mid-branch so that neither outcome can skip the commit and
                    # progress tail below - an early `continue` did exactly that.
                    if doc is None or not _is_document_url(final_url):
                        counts["rejected"] += 1
                        # Two different answers, and only one of them is about the page. A
                        # fetch that ERRORED - 403 under rate limiting, a timeout, a shell
                        # response that never resolved - judged nothing: this run simply did
                        # not get to read it. Recorded so drop_missing leaves whatever is
                        # already stored alone. A page rejected on its CONTENT was read and
                        # found not to be a document, and that is a real answer, so it stays
                        # out of both lists and the existing row goes.
                        if result.error:
                            unread.append(final_url)
                            if url != final_url:
                                unread.append(url)
                    else:
                        title, text = doc
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

                    # Committing and reporting are on separate clocks now: work is durable
                    # every BATCH pages, the card moves several times a second.
                    if done % BATCH == 0:
                        conn.commit()

                    now = time.monotonic()
                    if now - last_emit >= PROGRESS_INTERVAL_SEC or done == len(urls):
                        last_emit = now
                        yield {"stage": "fetch", "done": done, "total": len(urls),
                               "current_url": result.final_url or url,
                               "counts": dict(counts), "survey": survey_stats, "final": False}

            # A full crawl is the whole truth about what exists; anything not seen is gone. Only
            # when the run covered everything — a scoped run knows nothing about other products.
            if not scope and kept:
                # kept + unread, not kept. A full crawl is the whole truth about what EXISTS,
                # but only about the pages it managed to read: a 403 says the appliance was
                # rate-limited, not that Palo Alto withdrew the page, and deleting on that
                # basis loses a good document to a transient failure. Sixteen hardware pages
                # went that way on 2026-09-21 when the crawl ran beside another HEAD load.
                removed = store.drop_missing(cur, kept + unread)
                if removed:
                    log.info("dropped %d documents no longer listed", removed)
                if unread:
                    # Said separately because the two are not the same event and an operator
                    # reading one line of "dropped N" cannot tell them apart.
                    log.warning("kept %d documents whose fetch failed this run; they are "
                                "protected from the sweep, not refreshed", len(set(unread)))

                # After drop_missing, not before: a product sitting on the line would be
                # measured with pages in it that this crawl has just established are gone.
                pruned = store.prune_small_products(cur, MIN_PRODUCT_DOCS)
                if pruned:
                    counts["stored"] -= pruned
                    log.info("pruned %d documents under products with fewer than %d",
                             pruned, MIN_PRODUCT_DOCS)
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
