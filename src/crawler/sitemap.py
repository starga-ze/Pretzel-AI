"""Validated sitemap discovery. Absence from a sitemap is never deletion evidence."""
import re
import time
from datetime import datetime
from urllib.parse import urlsplit, urlunsplit, urljoin
from xml.etree import ElementTree as ET

HOST = 'docs.paloaltonetworks.com'
BASE = 'https://' + HOST
SITEMAP_URL = BASE + '/sitemap.xml'
_VERSION = re.compile(r'^\d+-\d+(?:-\d+)?$')
_cache = {}


def canonical(url):
    parts = urlsplit(url)
    if parts.scheme.lower() not in ('http', 'https') or parts.hostname != HOST:
        raise ValueError('URL outside documentation host')
    if parts.username or parts.password or parts.port not in (None, 80, 443):
        raise ValueError('unsupported URL authority')
    path = re.sub(r'/+', '/', parts.path).rstrip('/')
    # Tracking/query parameters are not part of published topic identities.
    return urlunsplit(('https', HOST, path, '', ''))


def classify(url):
    parts = [p for p in urlsplit(url).path.split('/') if p]
    product = parts.pop(0) if parts else ''
    version = None
    if parts and _VERSION.fullmatch(parts[0]):
        version = parts.pop(0)
    docset = parts.pop(0) if parts else ''
    if parts and _VERSION.fullmatch(parts[0]) and version is None:
        version = parts.pop(0)
    return dict(product=product, version=version, docset=docset, section_path='/'.join(parts))


# Path roots the publisher serves from this host that are not product documentation. Two kinds,
# kept in one set because the rule is the same — never fetch, never keep:
#
#   site plumbing      translated, search, sitemap, content, etc, apps
#   published but not  resources      indexes, infographics, licensing pages. Also the 896k-char
#   documentation      oss-listings   EDL list and per-release open-source licence texts: long,
#                                     DITA-shaped, and answering no question about the product.
#
# A name list rots when the publisher reorganises; that is accepted here because the alternative -
# judging topic by subject matter - is a far larger and less predictable thing to get wrong.
EXCLUDED_ROOTS = {'translated', 'search', 'sitemap', 'content', 'etc', 'apps',
                  'resources', 'oss-listings'}
EXCLUDED_SUFFIXES = ('.pdf', '.xml', '.zip', '.json')


def eligible(url):
    """True when the URL's shape alone says it can be product documentation.

    Shape only: this runs before any fetch, so it can answer from the path and nothing else. A
    page that passes here still has to prove itself to the extractor.
    """
    try:
        url = canonical(url)
    except ValueError:
        return False
    parts = [p for p in urlsplit(url).path.split('/') if p]
    if len(parts) < 2:                      # a product's front page, not a page of its manual
        return False
    if parts[0] in EXCLUDED_ROOTS:
        return False
    return not parts[-1].lower().endswith(EXCLUDED_SUFFIXES)


def _parse_lastmod(raw):
    try:
        value = datetime.fromisoformat(raw.strip().replace('Z', '+00:00'))
        # A date-only lastmod is valid sitemap data.
        from datetime import timezone
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None


def fetch(url=SITEMAP_URL, timeout=30, max_age=300, cancel=None):
    if max_age and url in _cache and time.monotonic() - _cache[url][0] < max_age:
        return dict(_cache[url][1])
    from src.crawler.fetch import download
    pages, visited = {}, set()

    def read(location, depth=0):
        location = canonical(location)
        if location in visited:
            return
        if depth > 4 or len(visited) >= 100:
            raise ValueError('sitemap index exceeds safety limit')
        visited.add(location)
        status, body, final_url = download(location, timeout=timeout, cancel=cancel, xml=True)
        if status != 200:
            raise ValueError('sitemap HTTP ' + str(status))
        root = ET.fromstring(body)
        kind = root.tag.rsplit('}', 1)[-1]
        if kind not in ('urlset', 'sitemapindex'):
            raise ValueError('not a sitemap XML document')
        for item in root:
            values = {e.tag.rsplit('}', 1)[-1]: e.text for e in item}
            if not values.get('loc'):
                raise ValueError('sitemap entry has no location')
            key = canonical(urljoin(final_url, values['loc'].strip()))
            if kind == 'sitemapindex':
                read(key, depth + 1)
            else:
                moment = _parse_lastmod(values.get('lastmod'))
                old = pages.get(key)
                if old is None or (moment and (not old['lastmod'] or moment > old['lastmod'])):
                    pages[key] = dict(classify(key), lastmod=moment)
    read(url)
    if not pages:
        raise ValueError('empty sitemap; existing corpus retained')
    _cache[url] = (time.monotonic(), pages)
    return pages
