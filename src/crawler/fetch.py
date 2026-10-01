"""Bounded GETs, same-host redirects, cooperative cancellation and shared throttling."""
import random
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urljoin

from src.crawler.extract import analyze, EXCLUDED, UNKNOWN
from src.crawler.sitemap import canonical

# The publisher having removed a page is the one exclusion that needs corroborating before it may
# delete anything: a 404 can be a deploy halfway through. Every other exclusion was read and
# judged, and that reading is the evidence. Named here because these are the reasons this module
# produces, and read by the pipeline when it decides what a run may remove.
MISSING_REASONS = frozenset({'http_404', 'http_410'})

USER_AGENT = 'pz-pretzel-ai/2.0 (+tech-doc indexer)'
MAX_ATTEMPTS = 3
MAX_BYTES = 16 * 1024 * 1024
_lock = threading.Lock()
_next_request = 0.0


class Cancelled(Exception):
    pass


class FetchError(Exception):
    def __init__(self, message, status=0):
        super().__init__(message)
        self.status = status


class _Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Check BEFORE issuing a redirected request, not after downloading an arbitrary host.
        newurl = canonical(urljoin(req.full_url, newurl))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@dataclass
class Result:
    url: str
    final_url: str = ''
    status: int = 0
    decision: str = UNKNOWN
    reason: str = ''
    title: str = ''
    text: str = ''
    metadata: dict = field(default_factory=dict)
    error: str = ''


def check(cancel):
    if cancel and cancel.is_set():
        raise Cancelled()


def pause(seconds, cancel):
    if cancel:
        if cancel.wait(seconds):
            raise Cancelled()
    else:
        time.sleep(seconds)


def throttle(cancel):
    global _next_request
    while True:
        check(cancel)
        with _lock:
            delay = _next_request - time.monotonic()
            if delay <= 0:
                _next_request = time.monotonic() + 0.2
                return
        pause(min(delay, 1), cancel)


def retry_after(value):
    try:
        return min(120, max(0, float(value)))
    except (TypeError, ValueError):
        try:
            return min(120, max(0, (parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds()))
        except (TypeError, ValueError, OverflowError):
            return 0


def download(url, timeout=20, cancel=None, xml=False):
    global _next_request
    url = canonical(url)
    opener = urllib.request.build_opener(_Redirect)
    for attempt in range(MAX_ATTEMPTS):
        throttle(cancel)
        retry = 0
        try:
            req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT,
                'Accept': 'application/xml,text/xml' if xml else 'text/html,application/xhtml+xml'})
            with opener.open(req, timeout=timeout) as response:
                status = response.status
                final = canonical(response.geturl())
                if status != 200:
                    raise FetchError('unexpected HTTP ' + str(status), status)
                mime = response.headers.get_content_type()
                if not xml and mime not in ('text/html', 'application/xhtml+xml'):
                    raise FetchError('unsupported content type: ' + mime)
                chunks, size = [], 0
                deadline = time.monotonic() + 60
                while True:
                    check(cancel)
                    if time.monotonic() > deadline:
                        raise FetchError('response body deadline exceeded')
                    chunk = response.read(65536)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > MAX_BYTES:
                        raise FetchError('response exceeds size limit')
                    chunks.append(chunk)
                return status, b''.join(chunks).decode(response.headers.get_content_charset() or 'utf-8', 'replace'), final
        except urllib.error.HTTPError as exc:
            if exc.code in (404, 410):
                return exc.code, '', canonical(exc.geturl())
            if exc.code not in (403, 408, 429, 500, 502, 503, 504):
                raise FetchError('HTTP ' + str(exc.code), exc.code) from exc
            retry = max(retry_after(exc.headers.get('Retry-After')), 2 ** (attempt + 1))
            with _lock:
                _next_request = max(_next_request, time.monotonic() + retry)
            error = 'HTTP ' + str(exc.code)
            error_status = exc.code
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            error = str(exc)
            error_status = 0
        if attempt == MAX_ATTEMPTS - 1:
            raise FetchError(error, error_status)
        pause(max(retry, 2 ** attempt) + random.uniform(0, .3), cancel)


def fetch(url, cancel=None):
    result = Result(url=url, final_url=url)
    try:
        for attempt in range(2):
            result.status, markup, result.final_url = download(url, cancel=cancel)
            if result.status in (404, 410):
                result.decision, result.reason = EXCLUDED, 'http_' + str(result.status)
                return result
            doc = analyze(markup, result.final_url)
            result.decision, result.reason = doc.decision, doc.reason
            result.title, result.text, result.metadata = doc.title, doc.text, doc.metadata
            if doc.reason != 'content_root_missing' or attempt:
                return result
            pause(2, cancel)
    except Cancelled:
        raise
    except (FetchError, ValueError, urllib.error.URLError, OSError, TimeoutError) as exc:
        result.decision, result.reason, result.error = UNKNOWN, 'fetch_failed', str(exc)
        result.status = getattr(exc, 'status', result.status)
    return result
