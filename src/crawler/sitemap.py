"""The sitemap: the whole crawl's worklist, and the first staleness gate.

docs.paloaltonetworks.com publishes one flat sitemap.xml (~4.4 MB, ~22.5k <url> entries) with a
<lastmod> on every entry. That single fetch is what makes "check for updates" cheap: the crawler
compares each lastmod against the one stored on techdoc.document and only the pages that moved
are candidates for a re-fetch.

Two things the caller must know about that signal:

  - Fragment URLs. The sitemap lists the same page once per in-page anchor, so 22,518 <loc>
    entries collapse to 21,768 real pages. Canonicalising away the fragment is not a tidy-up, it
    is what stops the crawler fetching some pages a dozen times.

  - lastmod moves in batches. Entries share a timestamp to the second (24 pages on one, 20 on
    another), which is a documentation set being republished wholesale rather than 24 pages being
    edited. So lastmod means "republished", never "the text changed" — it is a cheap filter that
    over-reports, and the content hash downstream is what actually decides.
"""

import logging
import random
import re
import time
import urllib.error
import urllib.request
from datetime import datetime

log = logging.getLogger("pretzel-ai.crawler.sitemap")

SITEMAP_URL = "https://docs.paloaltonetworks.com/sitemap.xml"
BASE = "https://docs.paloaltonetworks.com/"
USER_AGENT = "pz-pretzel-ai/1.0 (+tech-doc indexer)"

# The sitemap is 4.4 MB and is fetched by every check. The console's card lets an operator press
# Check as often as they like, and each press was a fresh download — which is how this request
# started drawing the same 403 rate-limiting the page crawl did. Cached for a few minutes because
# nothing it reports can change faster than that: lastmod moves when Palo Alto republishes, not
# between two clicks.
CACHE_TTL_SEC = 300
_cache = {"at": 0.0, "pages": None}

# Same policy as fetch.py, for the same reason: this request goes to the same host and is refused
# by the same limiter. A bare urlopen here meant a check failed outright where a page fetch would
# have waited and succeeded.
MAX_ATTEMPTS = 3
THROTTLE_STATUSES = frozenset({403, 429, 503})
BACKOFF_BASE = 1.5
THROTTLE_BACKOFF_BASE = 4.0

_URL_BLOCK = re.compile(
    r"<url>\s*<loc>([^<]*)</loc>\s*(?:<lastmod>([^<]*)</lastmod>)?", re.I)
# Palo Alto's version segment is always <major>-<minor>: 10-2, 11-1, 12-2.
_VERSION = re.compile(r"^\d+-\d+$")


def _parse_lastmod(raw):
    """'2026-08-17T22:29:45.123Z' -> datetime, or None when the entry carries no usable date."""
    if not raw:
        return None
    text = raw.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        log.debug("unparseable lastmod: %r", raw)
        return None


def classify(url):
    """Split a doc URL into the facets retrieval filters and cites on.

        .../pan-os/10-2/pan-os-admin/monitoring/view-reports
             product  version  docset      section_path

    The version segment is optional and is detected by shape rather than by position, because a
    product without versioned docs (prisma-access/activation-and-onboarding) puts its docset
    exactly where a versioned one puts its version.
    """
    path = url[len(BASE):] if url.startswith(BASE) else url
    segments = [s for s in path.split("/") if s]
    if not segments:
        return {"product": "", "version": None, "docset": None, "section_path": None}

    product, rest = segments[0], segments[1:]
    version = None
    if rest and _VERSION.match(rest[0]):
        version, rest = rest[0], rest[1:]

    return {
        "product": product,
        "version": version,
        "docset": rest[0] if rest else None,
        "section_path": "/".join(rest[1:]) or None,
    }


def canonical(url):
    """The URL as it is stored: fragment removed, trailing slash removed, repeated slashes collapsed.

    The slash collapsing is for redirect targets, not for the sitemap. This site answers some 301s
    with a Location carrying an empty path segment — ngfw/networking//session-settings-and-timeouts
    — and urllib resolves that verbatim, so the recorded target does not match the document that
    actually holds the page. Normalising both ends of the comparison is what makes an alias
    resolvable: of 19 targets that matched nothing, 13 matched once the slashes were collapsed.
    """
    trimmed = url.split("#", 1)[0].rstrip("/")
    scheme, sep, rest = trimmed.partition("://")
    if not sep:
        return re.sub(r"/{2,}", "/", trimmed)
    return scheme + sep + re.sub(r"/{2,}", "/", rest)


def _download(url, timeout):
    """The sitemap body, retried on throttling. Raises the last error if every attempt failed."""
    last = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            last = e
            throttled = e.code in THROTTLE_STATUSES
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            last = e
            throttled = False
        if attempt < MAX_ATTEMPTS:
            base = THROTTLE_BACKOFF_BASE if throttled else BACKOFF_BASE
            wait = base ** attempt + random.uniform(0, 0.4)
            log.warning("sitemap attempt %d failed (%s); retrying in %.1fs", attempt, last, wait)
            time.sleep(wait)
    raise last


def fetch(url=SITEMAP_URL, timeout=60, max_age=CACHE_TTL_SEC):
    """→ {canonical_url: {'lastmod': datetime|None, 'product', 'version', 'docset',
    'section_path'}}

    Deduplicated by canonical URL. Where several fragment entries collapse onto one page their
    lastmod values are identical in practice; the newest is kept regardless, so a page is never
    reported as older than the sitemap claims it is.

    Served from a short-lived cache unless `max_age` is 0, which a refresh passes to make sure it
    acts on a sitemap it read itself rather than on one a check left behind.
    """
    if max_age and _cache["pages"] is not None and time.monotonic() - _cache["at"] < max_age:
        log.debug("sitemap: served from cache (%d pages)", len(_cache["pages"]))
        return dict(_cache["pages"])

    xml = _download(url, timeout)

    pages = {}
    raw_entries = 0
    for loc, lastmod in _URL_BLOCK.findall(xml):
        raw_entries += 1
        key = canonical(loc)
        if not key:
            continue
        moment = _parse_lastmod(lastmod)
        existing = pages.get(key)
        if existing is None:
            entry = classify(key)
            entry["lastmod"] = moment
            pages[key] = entry
        elif moment and (existing["lastmod"] is None or moment > existing["lastmod"]):
            existing["lastmod"] = moment

    log.info("sitemap: %d entries -> %d canonical pages", raw_entries, len(pages))
    _cache.update({"at": time.monotonic(), "pages": pages})
    return dict(pages)
