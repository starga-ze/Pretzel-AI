"""The techdoc schema: reading the last crawl's state, and writing this one's.

Content is stored under the sha256 of its extracted text rather than under the URL it came from.
Palo Alto publishes the same page once per product version — 42% of the sitemap carries a version
segment, and roughly 40% of extracted bodies are byte-identical across those versions — so a
URL-keyed table would hold the same body dozens of times and, later, embed it dozens of times.
Keying on the hash makes that collapse automatic and permanent: many documents point at one
content row, and whatever the corpus schema derives from that row it derives once.

The write path is deliberately dumb about ordering: content first, then the document row that
references it, so the foreign key can never see a dangling sha.
"""

import hashlib
import logging
import os

import psycopg

log = logging.getLogger("pretzel-ai.crawler.store")

DSN_ENV = "PZ_KNOWLEDGE_DSN"
DEFAULT_DSN = "host=127.0.0.1 port=5432 dbname=pretzel_knowledge user=pretzel"


def dsn():
    """The knowledge DB connection string. The password follows pretzel's own convention —
    PZ_PG_PASSWORD, with the repo's localhost-only development default."""
    configured = os.environ.get(DSN_ENV, "").strip()
    if configured:
        return configured
    password = os.environ.get("PZ_PG_PASSWORD", "pretzel")
    return f"{DEFAULT_DSN} password={password}"


def connect():
    return psycopg.connect(dsn())


def sha256(text):
    return hashlib.sha256(text.encode("utf-8")).digest()


def load_documents(conn):
    """→ {url: {'lastmod', 'last_modified', 'content_sha', 'deleted_at'}} for every known URL.

    Loaded in one pass rather than queried per page: 21,768 round trips to answer "have I seen
    this before" would dominate a refresh that is otherwise a few hundred fetches.
    """
    with conn.cursor() as cur:
        cur.execute("""
            SELECT d.url, d.lastmod, d.last_modified, d.content_sha, d.deleted_at,
                   d.canonical_url, d.fetch_error, c.char_count, d.title, d.redirect_checked
              FROM techdoc.document d
              LEFT JOIN techdoc.content c ON c.sha = d.content_sha
        """)
        return {
            row[0]: {"lastmod": row[1], "last_modified": row[2],
                     "content_sha": row[3], "deleted_at": row[4],
                     "canonical_url": row[5], "fetch_error": row[6],
                     "char_count": row[7], "title": row[8],
                     "redirect_checked": row[9]}
            for row in cur
        }


def put_content(cur, text):
    """Insert the body if this exact text is new. → sha."""
    digest = sha256(text)
    cur.execute(
        """
        INSERT INTO techdoc.content (sha, text, char_count)
             VALUES (%s, %s, %s)
        ON CONFLICT (sha) DO NOTHING
        """,
        (digest, text, len(text)),
    )
    return digest


def put_document(cur, url, facets, lastmod, result, content_sha):
    """Upsert one document row. deleted_at is cleared: a URL that came back is not deleted.

    canonical_url is the URL the fetch ended on, stored only when it differs from the one asked
    for. NULL therefore means "nothing redirected", which is the common case and the cheap check.
    """
    canonical = getattr(result, "final_url", None)
    if canonical == url:
        canonical = None

    cur.execute(
        """
        INSERT INTO techdoc.document
               (url, product, version, docset, section_path, title,
                lastmod, etag, last_modified, content_sha, http_status,
                fetch_error, canonical_url, redirect_checked, fetched_at, deleted_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, true, now(), NULL)
        ON CONFLICT (url) DO UPDATE SET
               product       = EXCLUDED.product,
               version       = EXCLUDED.version,
               docset        = EXCLUDED.docset,
               section_path  = EXCLUDED.section_path,
               title         = COALESCE(EXCLUDED.title, techdoc.document.title),
               lastmod       = EXCLUDED.lastmod,
               etag          = EXCLUDED.etag,
               last_modified = EXCLUDED.last_modified,
               content_sha   = COALESCE(EXCLUDED.content_sha, techdoc.document.content_sha),
               http_status   = EXCLUDED.http_status,
               fetch_error   = EXCLUDED.fetch_error,
               canonical_url = EXCLUDED.canonical_url,
               redirect_checked = true,
               fetched_at    = now(),
               deleted_at    = NULL
        """,
        (url, facets["product"], facets["version"], facets["docset"], facets["section_path"],
         result.title, lastmod, result.etag, result.last_modified, content_sha,
         result.status or None, result.error, canonical),
    )


def touch_seen(cur, url, lastmod):
    """A 304: the body is unchanged, but the crawl still saw the page. Records that it looked,
    so a page is never mistaken for one that has stopped being published."""
    cur.execute(
        """
        UPDATE techdoc.document
           SET lastmod = %s, fetched_at = now(), fetch_error = NULL,
               http_status = 304, deleted_at = NULL
         WHERE url = %s
        """,
        (lastmod, url),
    )


def mark_deleted(cur, urls):
    """Tombstone URLs that have left the sitemap. Never a DELETE: retrieval has to be able to
    explain a citation pointing at a page Palo Alto has since withdrawn."""
    if not urls:
        return 0
    cur.execute(
        """
        UPDATE techdoc.document
           SET deleted_at = now()
         WHERE url = ANY(%s) AND deleted_at IS NULL
        """,
        (list(urls),),
    )
    return cur.rowcount


def start_run(conn, scope=None):
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO techdoc.crawl_run (scope) VALUES (%s) RETURNING id", (scope,))
        run_id = cur.fetchone()[0]
    conn.commit()
    return run_id


def finish_run(conn, run_id, status, counts, error=None):
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE techdoc.crawl_run
               SET finished_at = now(), status = %s, error = %s,
                   checked = %s, fetched = %s, changed = %s, added = %s, removed = %s,
                   skipped_304 = %s, skipped_same_sha = %s, skipped_alias = %s, failed = %s
             WHERE id = %s
            """,
            (status, error, counts.get("checked", 0), counts.get("fetched", 0),
             counts.get("changed", 0), counts.get("added", 0), counts.get("removed", 0),
             counts.get("skipped_304", 0), counts.get("skipped_same_sha", 0),
             counts.get("skipped_alias", 0), counts.get("failed", 0), run_id),
        )
    conn.commit()


def status(conn):
    """What the console card shows at rest: how much is stored, and how the last run ended."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT count(*) FILTER (WHERE deleted_at IS NULL),
                   count(*) FILTER (WHERE deleted_at IS NOT NULL),
                   count(DISTINCT content_sha)
              FROM techdoc.document
        """)
        live, tombstoned, bodies = cur.fetchone()
        cur.execute("SELECT coalesce(sum(char_count), 0) FROM techdoc.content")
        (chars,) = cur.fetchone()
        cur.execute("""
            SELECT id, coalesce(finished_at, started_at), status
              FROM techdoc.crawl_run ORDER BY id DESC LIMIT 1
        """)
        run = cur.fetchone()
    return {
        "documents": live or 0,
        "tombstoned": tombstoned or 0,
        "bodies": bodies or 0,
        "chars": int(chars or 0),
        "last_run_id": run[0] if run else 0,
        "last_run_at": run[1].isoformat() if run and run[1] else "",
        "last_run_status": run[2] if run else "",
    }


def prune_orphan_content(cur):
    """Delete bodies no document points at any more. → rows removed.

    Content is keyed by hash, so a page that is edited leaves its previous body behind the moment
    the last document referencing it moves to a new hash. Nothing reads those rows and nothing
    would ever delete them, so without this a long-lived appliance accumulates every version of
    every page it has ever crawled.

    Not a history mechanism being thrown away: the corpus is derived from what is published now,
    and a body no live URL serves is not something the assistant should be able to answer out of.
    """
    cur.execute("""
        DELETE FROM techdoc.content c
         WHERE NOT EXISTS (SELECT 1 FROM techdoc.document d WHERE d.content_sha = c.sha)
    """)
    return cur.rowcount


def running_run(conn):
    """→ (id, started_at) of a crawl already in flight, or None.

    Checked in the database rather than in the process, because the CLI and the gRPC service are
    two different processes writing the same schema. An in-process lock would let a console-driven
    refresh start on top of a terminal-driven one, and both would fetch every page twice.
    """
    with conn.cursor() as cur:
        cur.execute("""
            SELECT id, started_at FROM techdoc.crawl_run
             WHERE status = 'running' ORDER BY id DESC LIMIT 1
        """)
        return cur.fetchone()


def product_tree(conn):
    """The corpus as a product/docset tree, for the console's browsable view.

    Derived from the URL paths because the sitemap has no hierarchy of its own — it is 22,519 flat
    <loc> entries. 64 products over 321 docsets is small enough to return whole, so the console can
    render something an operator navigates rather than a number they have to trust.
    """
    with conn.cursor() as cur:
        cur.execute("""
            SELECT product,
                   coalesce(docset, ''),
                   count(*),
                   count(DISTINCT content_sha),
                   coalesce(sum(c.char_count), 0),
                   count(DISTINCT version),
                   count(*) FILTER (WHERE d.fetch_error IS NOT NULL)
              FROM techdoc.document d
              LEFT JOIN techdoc.content c ON c.sha = d.content_sha
             WHERE d.deleted_at IS NULL
          GROUP BY product, coalesce(docset, '')
          ORDER BY count(*) DESC
        """)
        return [
            {"product": row[0], "docset": row[1], "documents": row[2], "bodies": row[3],
             "chars": int(row[4]), "versions": row[5], "failed": row[6]}
            for row in cur
        ]
