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
    """Rejoin DITA's mid-sentence line breaks; keep headings and list items standing alone."""
    merged, buffer = [], ""
    for line in lines:
        if not line:
            if buffer:
                merged.append(buffer)
                buffer = ""
            continue
        if buffer and not _SENTENCE_END.search(buffer) and not line.startswith("#"):
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
