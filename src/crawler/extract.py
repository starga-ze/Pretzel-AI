"""Site-specific DOM classification and structure-preserving corpus extraction."""
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup, NavigableString, Tag, Comment

# The three outcomes a page can reach, named once and used unchanged by the counters, the
# decision column and the console's buckets. One vocabulary end to end, so a number on screen can
# be traced to a row in techdoc.crawl_observation without a translation table in between.
#
#   COLLECTED  read, and it is documentation
#   EXCLUDED   read, and it is not - or the publisher has removed it. Correctly absent either way
#   UNKNOWN    not read. A failure on our side, so nothing about the stored copy may change
#
# Why the publisher's 404s sit under EXCLUDED rather than a fourth name: to an operator both mean
# "this page is not in the corpus, and that is right". What separates them is how much evidence is
# needed before deleting, and that is a property of the REASON (http_404), not of the outcome.
COLLECTED = 'collected'
EXCLUDED = 'excluded'
UNKNOWN = 'unknown'

# Every reason a run can record, and the outcome it belongs to. Gathered here - including the five
# raised in fetch and pipeline rather than in this module - so there is one list to read and one to
# keep current. The console shows the whole vocabulary rather than only what occurred, because a
# reason sitting at zero is itself worth seeing: `fetch_failed` at nought says the throttle held
# for 22,000 requests, and that is not visible if the row is simply absent.
REASONS = {
    'technical_topic':        COLLECTED,
    'navigation_only':        EXCLUDED,
    'excluded_destination':   EXCLUDED,   # pipeline: the fetch landed somewhere ineligible
    'excluded_url':           EXCLUDED,   # pipeline: policy, judged without fetching
    'http_404':               EXCLUDED,   # fetch
    'http_410':               EXCLUDED,   # fetch
    'unsupported_template':   UNKNOWN,
    'content_root_missing':   UNKNOWN,
    'title_missing':          UNKNOWN,
    'image_only_topic':       UNKNOWN,
    'empty_topic':            UNKNOWN,
    'fetch_failed':           UNKNOWN,    # fetch
    'redirect_outside_scope': UNKNOWN,    # pipeline
}

PARSER_VERSION = 'pan-dom-v1'
CONTENT_ROOTS = ('book-pdf-content', 'td-body__content', 'oneColumnPlain')
NAV = '.consolidated-toc, .toc-scrollarea, .aside-right-content, .dita-pagination, [data-outputclass="nav"], nav, aside'
INTRO = re.compile(r'^(the following (topics|sections)|this (section|chapter) (provides|contains)|in this (section|chapter))\b', re.I)


class NoContentRoot(Exception):
    pass


@dataclass
class Document:
    decision: str
    reason: str
    title: str = ''
    text: str = ''
    root: str = ''
    metadata: dict = field(default_factory=dict)


def plain(node):
    return re.sub(r'\s+', ' ', node.get_text(' ', strip=True)).strip()


def render(node, base=''):
    if isinstance(node, Comment):
        return ''
    if isinstance(node, NavigableString):
        return re.sub(r'\s+', ' ', str(node))
    if not isinstance(node, Tag):
        return ''
    tag = node.name
    if tag == 'pre':
        return '\n\n```\n' + node.get_text().strip('\n') + '\n```\n\n'
    if tag == 'table':
        # Some vendor tables put div wrappers between tr and td; direct-child lookup loses them.
        rows = []
        for row in node.find_all('tr'):
            if row.find_parent('table') is not node:
                continue
            cells = [re.sub(r'\s+', ' ', render(c, base)).strip().replace('|', '\\|')
                     for c in row.find_all(['td', 'th']) if c.find_parent('tr') is row]
            if cells:
                rows.append(cells)
        if not rows:
            return '\n\n' + plain(node) + '\n\n'
        width = max(map(len, rows))
        lines = ['| ' + ' | '.join(r + [''] * (width - len(r))) + ' |' for r in rows]
        lines.insert(1, '| ' + ' | '.join(['---'] * width) + ' |')
        return '\n\n' + '\n'.join(lines) + '\n\n'
    if 'menucascade' in node.get('class', []):
        return ' → '.join(plain(c) for c in node.find_all(recursive=False))
    children = ''.join(render(c, base) for c in node.children)
    if re.fullmatch(r'h[1-6]', tag):
        return '\n\n' + '#' * int(tag[1]) + ' ' + plain(node) + '\n\n'
    if tag == 'li':
        prefix = '1. ' if node.parent.name == 'ol' else '- '
        return '\n' + prefix + children.strip() + '\n'
    if tag == 'a':
        href = urljoin(base, node.get('href', ''))
        if children.strip() and urlsplit(href).scheme in ('https', 'http'):
            return '[' + children.strip() + '](' + href.replace(' ', '%20').replace(')', '%29') + ')'
    if tag == 'img':
        alt = node.get('alt', '').strip()
        return (' [Image: ' + alt + '] ') if alt else ''
    if tag == 'br':
        return '\n'
    if tag == 'code':
        return '`' + children.strip() + '`'
    if tag in ('p', 'div', 'section', 'article', 'ul', 'ol', 'dl', 'dt', 'dd', 'blockquote'):
        return '\n\n' + children.strip() + '\n\n'
    return children


def analyze(markup, url=''):
    soup = BeautifulSoup(markup, 'html.parser')
    metadata = {m.get('name', '').lower(): m.get('content', '').strip('[] ')
                for m in soup.find_all('meta') if m.get('name')}
    for node in soup.select('script, style, noscript, svg, template'):
        node.decompose()
    root = None
    root_name = ''
    for cls in CONTENT_ROOTS:
        root = soup.select_one('.' + cls)
        if root is not None:
            root_name = cls
            break
    if root is None:
        return Document(UNKNOWN, 'content_root_missing', metadata=metadata)
    had_navigation = bool(root.select(NAV))
    for node in root.select(NAV):
        if node.parent is not None:
            node.decompose()
    topics = root.select('.topic.concept, .topic.task, .topic.reference, .topic[id], article')
    if not topics:
        # Published feature notes use a separate, server-rendered template.
        topics = root.select('.new-features-entry .coveo-results-card')
        for node in root.select('.coveo-results-tag-list'):
            node.decompose()
    # An outer topic already contains its nested topics; render each only once.
    topics = [n for n in topics if not any(p in topics for p in n.parents)]
    if not topics:
        return Document(UNKNOWN, 'unsupported_template', root=root_name, metadata=metadata)
    title_node = topics[0].find(re.compile(r'^h[1-6]$')) or soup.title
    title = plain(title_node) if title_node else ''
    title = re.sub(r'\s*[|–]\s*Palo Alto Networks.*$', '', title).strip()
    if not title:
        return Document(UNKNOWN, 'title_missing', root=root_name, metadata=metadata)
    meaningful = []
    for topic in topics:
        for block in topic.select('p, .p, pre, table, li, dd'):
            text = plain(block)
            if not text or INTRO.match(text):
                continue
            # A list of links is navigation; links inside explanatory sentences are retained.
            links = ' '.join(plain(a) for a in block.find_all('a'))
            if links and re.sub(r'\W', '', text) == re.sub(r'\W', '', links):
                continue
            meaningful.append(block)
    if not meaningful:
        if any(t.find('img') for t in topics):
            return Document(UNKNOWN, 'image_only_topic', title=title, root=root_name, metadata=metadata)
        if had_navigation or any(t.find('a') for t in topics):
            return Document(EXCLUDED, 'navigation_only', title=title, root=root_name, metadata=metadata)
        return Document(UNKNOWN, 'empty_topic', title=title, root=root_name, metadata=metadata)
    text = '\n\n'.join(render(t, url).strip() for t in topics)
    # Preserve indentation and blank lines inside fenced command examples.
    chunks = text.split('```')
    for i in range(0, len(chunks), 2):
        chunks[i] = re.sub(r'\n[ \t]+', '\n', chunks[i])
        chunks[i] = re.sub(r'\n{3,}', '\n\n', chunks[i])
    text = '```'.join(chunks).strip()
    return Document(COLLECTED, 'technical_topic', title, text, root_name, metadata)


def extract(markup):
    result = analyze(markup)
    if result.decision != COLLECTED:
        raise NoContentRoot(result.reason)
    return result.root, result.text


def title_of(markup):
    soup = BeautifulSoup(markup, 'html.parser')
    return plain(soup.title) if soup.title else None
