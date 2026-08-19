"""Fetching a page, and knowing when not to.

Every request is conditional on Last-Modified: the value recorded by the previous crawl goes back
out as If-Modified-Since, so an unchanged page costs a 304 and no body. That is the second
staleness gate — the sitemap's lastmod says a page *might* have moved, and this says whether the
server agrees.

Deliberately not ETag. docs.paloaltonetworks.com serves a different ETag for the same unchanged
page on consecutive requests ("79701-6595c05d4a65a-gzip" then "796fb-6595c068dcd05-gzip" seconds
apart), so If-None-Match never matches and every request would come back 200 with a full body.
The header is still recorded on the document row for diagnostics, but sending it back would cost
the entire saving this gate exists for.

The retry policy exists for one specific failure. A page can answer 200 with the site chrome
intact and the content root missing; the same URL fetched again returns the real body. Because it
is a 200 nothing about the HTTP layer looks wrong, so without an explicit content check the shell
is stored and then dropped downstream as an empty document, silently. Here a missing content root
is a retryable failure like a 503, and a page that fails it on every attempt is recorded with an
error rather than written as empty.
"""

import logging
import random
import time
import urllib.error
import urllib.request

from src.crawler.extract import NoContentRoot, extract, title_of
from src.crawler.sitemap import canonical

log = logging.getLogger("pretzel-ai.crawler.fetch")

USER_AGENT = "pz-pretzel-ai/1.0 (+tech-doc indexer)"
MAX_ATTEMPTS = 3
BACKOFF_BASE = 1.5

# Statuses that mean "you are going too fast", not "this page is unavailable".
#
# 403 belongs here, which is not obvious and was got wrong once: a full crawl recorded 155 of them,
# concentrated in end-of-life PAN-OS versions, which reads exactly like a vendor locking retired
# documentation. Re-requesting a sample of those URLs afterwards returned 200 or 301 for every one
# of them — the concentration was an artifact of crawl order, and the site was rate-limiting eight
# concurrent workers. Treating 403 as settled would have permanently dropped pages that are simply
# behind a throttle.
THROTTLE_STATUSES = frozenset({403, 429, 503})

# Throttling is answered by waiting longer, not by trying sooner. Separate from BACKOFF_BASE so a
# transient network error still retries quickly.
THROTTLE_BACKOFF_BASE = 4.0


class Result:
    """One fetch outcome. `status` is the HTTP code; 0 means the request never completed.

    not_modified and text are mutually exclusive: a 304 carries no body, which is the point.
    """

    __slots__ = ("url", "final_url", "status", "not_modified", "text", "title", "root",
                 "etag", "last_modified", "error")

    def __init__(self, url, status=0, not_modified=False, text=None, title=None,
                 root=None, etag=None, last_modified=None, error=None, final_url=None):
        self.url = url
        # Where the request actually ended. Whole subtrees of this site 301 onto one page, and
        # urllib follows without saying so; without this the store records a body under a URL that
        # never served it.
        self.final_url = final_url or url
        self.status = status
        self.not_modified = not_modified
        self.text = text
        self.title = title
        self.root = root
        self.etag = etag
        self.last_modified = last_modified
        self.error = error

    @property
    def ok(self):
        return self.error is None and (self.not_modified or self.text is not None)

    def __repr__(self):
        state = ("304" if self.not_modified
                 else f"{self.status} {len(self.text)}c" if self.text is not None
                 else f"ERR {self.error}")
        return f"<Result {self.url} {state}>"


def _request(url, last_modified, timeout):
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"}
    if last_modified:
        headers["If-Modified-Since"] = last_modified

    request = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read().decode("utf-8", "replace")
        return response.status, body, response.headers, response.geturl()


def fetch(url, last_modified=None, timeout=30):
    """→ Result. Retries transient failures and shell responses; never raises for a bad page."""
    last_error = None
    status = 0

    for attempt in range(1, MAX_ATTEMPTS + 1):
        throttled = False
        try:
            status, body, headers, final_url = _request(url, last_modified, timeout)
        except urllib.error.HTTPError as e:
            if e.code == 304:
                return Result(url, status=304, not_modified=True)
            # 404/410 are settled answers: the page is gone and retrying cannot change that.
            if e.code in (404, 410):
                return Result(url, status=e.code, error=f"HTTP {e.code}")
            last_error = f"HTTP {e.code}"
            status = e.code
            if e.code in THROTTLE_STATUSES:
                throttled = True
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            last_error = str(getattr(e, "reason", e)) or e.__class__.__name__
        else:
            try:
                root, text = extract(body)
            except NoContentRoot as e:
                # The shell response. Retryable precisely because it is indistinguishable from
                # success at the HTTP layer.
                last_error = f"no usable body ({e})"
                log.debug("no usable body on attempt %d: %s (%s)", attempt, url, e)
            else:
                return Result(url, status=status, text=text, title=title_of(body), root=root,
                              etag=headers.get("ETag"),
                              last_modified=headers.get("Last-Modified"),
                              # Normalised so it can be compared against a stored URL; the raw
                              # value can carry an empty path segment the redirect introduced.
                              final_url=canonical(final_url))

        if attempt < MAX_ATTEMPTS:
            # Jittered so a documentation set that fails together does not retry in lockstep.
            base = THROTTLE_BACKOFF_BASE if throttled else BACKOFF_BASE
            time.sleep(base ** attempt + random.uniform(0, 0.4))

    log.warning("giving up on %s after %d attempts: %s", url, MAX_ATTEMPTS, last_error)
    return Result(url, status=status, error=last_error)
