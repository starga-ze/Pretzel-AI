"""HTML -> the text that actually gets indexed.

Palo Alto's tech docs are DITA rendered into a Coveo-backed site: ~340 KB of HTML wrapping ~10 KB
of prose, the rest being the navigation tree, the version picker and the search chrome. Indexing
the page as a whole would fill the corpus with table-of-contents fragments that match every query
about the product and answer none of them, so extraction is scoped to the content root and
everything outside it is dropped.

Two failures found the hard way are handled here rather than left to the caller:

  - The empty 200. A page can return HTTP 200 with the chrome present and the content root
    missing entirely; refetching the same URL then yields the real body. Left alone it is written
    to the store and silently discarded downstream as an empty document — silently, because 200
    is a success and nothing retries it. `extract` reports the missing root as a distinct outcome
    so the fetcher can treat it as the failure it is.

  - DITA hard newlines. The renderer breaks lines mid-sentence ("supports the following\\n
    functionalities:"). Chunking on those boundaries splits sentences across chunks and strands
    the two halves in different embeddings, so a line that does not end on sentence punctuation
    is joined to the next one.
"""

import html
import logging
import re

log = logging.getLogger("pretzel-ai.crawler.extract")

# Tightest container first. The order is load-bearing, not cosmetic: on templates that carry
# several of these, oneColumnPlain is an outer wrapper that encloses the navigation tree as well
# as the prose, so matching it ahead of td-body__content pulls the whole table of contents into
# the body. That is the defect that filled the previous corpus with sidebar text.
CONTENT_ROOTS = ("book-pdf-content", "td-body__content", "oneColumnPlain")

# Navigation containers that live *inside* some content roots. Removed before the root is chosen
# so the choice is made on prose, not on chrome.
# Deliberately narrow. Broader candidates (scrollbar-outer, coveo-results-content) also enclose
# the prose on some templates, so removing them costs the whole body — verified against live
# pages, not assumed from the class name.
_NAV_CLASSES = ("consolidated-toc", "toc-scrollarea", "aside-right-content")

# Chrome that survives inside the content root on some templates: widget labels, not prose.
_CHROME_LINES = frozenset({
    "Focus", "Clear", "Home", "Filter", "Expand all | Collapse all",
    "Expand All | Collapse All", "Next", "Previous", "Table of Contents",
    "Download PDF", "Print", "Feedback", "Was this helpful?",
})

_DROP_TAGS = re.compile(r"(?is)<(script|style|noscript|svg)[^>]*>.*?</\1>")
_HEADING = re.compile(r"(?i)<h([1-6])[^>]*>")
_BLOCK_END = re.compile(r"(?i)</(p|li|div|h[1-6]|tr|td|th|pre|blockquote)>")
_TAG = re.compile(r"(?s)<[^>]+>")
_SENTENCE_END = re.compile(r"[.:;!?)\]]$")
_TITLE = re.compile(r"(?is)<title[^>]*>(.*?)</title>")

# Labels the template prints on every page. Not content, and their presence must not make a page
# that carries nothing else look like it carries something.
_LABELS = re.compile(
    r"^(Where Can I Use This\?|What Do I Need\?|Updated on .{5,60}|Release Date:.*|"
    r"Last Updated:.*|Learn More|View Now|Version|Focus|Home|Clear)$", re.I)


class NoContentRoot(Exception):
    """The page did not yield a usable body — a shell response, not an empty document.

    Two shapes, one meaning. Either the content root was absent, or it was present and extracted to
    nothing: docs.paloaltonetworks.com/develop answers 200 with the root in place and the body
    rendered by JavaScript, so a crawler that only checked for the root's presence stored it as a
    zero-character document. Both are "the server said 200 and gave us no text", and neither should
    reach the store as an empty body that later reads as a page with nothing on it."""


def _strip_containers(markup, classes):
    """Delete whole elements whose class matches, brace-matched so nested children go with them."""
    for cls in classes:
        while True:
            opener = re.search(
                r'<(div|nav|aside)[^>]*class="[^"]*\b%s\b[^"]*"[^>]*>' % re.escape(cls), markup)
            if not opener:
                break
            tag, start = opener.group(1), opener.end()
            depth, end = 1, len(markup)
            for token in re.finditer(r"</?%s\b[^>]*>" % tag, markup[start:]):
                depth += -1 if token.group(0).startswith("</") else 1
                if depth == 0:
                    end = start + token.end()
                    break
            markup = markup[:opener.start()] + " " + markup[end:]
    return markup


def _find_root(markup):
    """→ (class_name, inner_html). Walks tag depth to find the element's real close, because
    the content root nests dozens of same-name children and a non-greedy match to the first
    </div> would truncate the body at the first paragraph."""
    for cls in CONTENT_ROOTS:
        opener = re.search(
            r'<(div|main|section)[^>]*class="[^"]*\b%s\b[^"]*"[^>]*>' % re.escape(cls), markup)
        if not opener:
            continue
        tag, start = opener.group(1), opener.end()
        depth, end = 1, len(markup)
        for token in re.finditer(r"</?%s\b[^>]*>" % tag, markup[start:]):
            depth += -1 if token.group(0).startswith("</") else 1
            if depth == 0:
                end = start + token.start()
                break
        return cls, markup[start:end]
    return None, None


def _merge_hard_wraps(lines):
    """Rejoin DITA's mid-sentence line breaks; keep headings and list items standing alone.

    A heading never absorbs what follows it, which the guard below has to say twice: once for the
    incoming line and once for the buffer. Guarding only the incoming line let "## Description"
    swallow the paragraph after it, because a heading does not end in sentence punctuation either.
    That merged 837 documents' first paragraph into their heading — invisible in the text, but the
    heading boundaries are exactly what the chunker splits on, so it moved every chunk edge in
    those documents."""
    merged, buffer = [], ""
    for line in lines:
        if not line:
            if buffer:
                merged.append(buffer)
                buffer = ""
            continue
        if (buffer and not buffer.startswith("#")
                and not _SENTENCE_END.search(buffer) and not line.startswith("#")):
            buffer += " " + line
        else:
            if buffer:
                merged.append(buffer)
            buffer = line
    if buffer:
        merged.append(buffer)
    return merged


def title_of(markup):
    found = _TITLE.search(markup)
    if not found:
        return None
    text = " ".join(html.unescape(_TAG.sub(" ", found.group(1))).split())
    # Every page ends its <title> with the site suffix; it is noise repeated 21,768 times.
    return re.sub(r"\s*[|\-–]\s*Palo Alto Networks.*$", "", text).strip() or None


def extract(markup):
    """→ (content_root_name, text). Raises NoContentRoot when the page is a shell response.

    Headings are kept as markdown '#' lines: they are the only structural signal that survives
    into the chunker, which uses them to avoid cutting a procedure away from the heading that
    says what the procedure is for.
    """
    # Order matters. <style> blocks name the content-root classes in CSS selectors, so a root
    # search run before they are stripped matches the stylesheet and picks the wrong container
    # (or a nonexistent one). Strip first, choose second.
    cleaned = _DROP_TAGS.sub(" ", markup)
    cleaned = _strip_containers(cleaned, _NAV_CLASSES)

    root, inner = _find_root(cleaned)
    if inner is None:
        raise NoContentRoot("no content root among %s" % (CONTENT_ROOTS,))

    inner = _HEADING.sub(lambda m: "\n\n" + "#" * int(m.group(1)) + " ", inner)
    inner = _BLOCK_END.sub("\n", inner)

    text = html.unescape(_TAG.sub(" ", inner))
    text = text.replace(" ", " ")
    text = re.sub(r"[ \t]+", " ", text)

    lines = [line.strip() for line in text.split("\n")]
    lines = [line for line in lines if line not in _CHROME_LINES]
    body = re.sub(r"\n{3,}", "\n\n", "\n".join(_merge_hard_wraps(lines))).strip()
    if not body:
        # Deliberately not a length threshold. A section landing page legitimately extracts to
        # "# Administration" and 80 characters; only *nothing* is evidence the page was not served.
        raise NoContentRoot(f"content root {root!r} extracted to nothing")
    return root, body


def residual(text):
    """The part of a body that is neither its masthead nor a restatement of its own headings.

    Every page opens with the same block: an "Updated on …" line, the product name, the docset
    name, and the title — then the first heading, then whatever the page actually says. So
    everything above the first heading is masthead by construction, and a page with nothing below
    it is a section landing page: it names itself and stops.

    What survives that is then stripped of headings, of the template's standing labels, and of
    repeated lines, because a breadcrumb trail says the same words more than once.

    Keyed on structure rather than on the document title so this stays a pure function of the body:
    one body is shared by many URLs whose titles need not agree, and a rule that consulted the
    title would give the same text two different answers depending on which URL asked.

    Deliberately not a length threshold. The corpus holds a 5.1 MB PAN-OS CLI command hierarchy
    whose lines are bare commands — no sentences, no punctuation, and exactly the reference
    material a support assistant is asked about. A rule phrased in terms of prose discards it.
    Phrased in terms of what sits below the masthead, it keeps all of it.
    """
    lines = [raw.strip() for raw in (text or "").split("\n")]
    lines = [line for line in lines if line]

    first_heading = next((i for i, line in enumerate(lines) if line.startswith("#")), None)
    if first_heading is None:
        # No heading at all: nothing marks where the masthead ends, so judge the whole body.
        body = lines
        headings = set()
    else:
        body = lines[first_heading + 1:]
        headings = {line.lstrip("#").strip().lower()
                    for line in lines if line.startswith("#")}

    seen, kept = set(), []
    for line in body:
        low = line.lower()
        if line.startswith("#") or _LABELS.match(line) or low in headings or low in seen:
            continue
        seen.add(low)
        kept.append(line)
    return "\n".join(kept)
