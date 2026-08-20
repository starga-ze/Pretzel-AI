"""techdoc.document: one row per URL, and nothing that is not a document.

The store holds documents, not attempts. A page that 404s, redirects onto another page, renders to
nothing, or has no title never reaches this module — `pipeline` drops it — so every column here is
NOT NULL for a reason and the table cannot hold a half-record.

content_sha is stored but never joined on. Palo Alto ships the same section in several manuals
(twenty hardware references share one "Third-Party Component Support" page), so ~20% of rows carry
a body that is byte-identical to another's. Retrieval collapses those at ranking time; the hash is
how it recognises them.
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


def put(cur, url, title, text, lastmod):
    """Insert or replace one document."""
    cur.execute(
        """
        INSERT INTO techdoc.document (url, title, text, content_sha, char_count, lastmod, fetched_at)
             VALUES (%s, %s, %s, %s, %s, %s, now())
        ON CONFLICT (url) DO UPDATE SET
               title       = EXCLUDED.title,
               text        = EXCLUDED.text,
               content_sha = EXCLUDED.content_sha,
               char_count  = EXCLUDED.char_count,
               lastmod     = EXCLUDED.lastmod,
               fetched_at  = now()
        """,
        (url, title, text, sha256(text), len(text), lastmod),
    )


def drop_missing(cur, keep_urls):
    """Delete documents the sitemap no longer lists. → rows removed.

    A full crawl is the whole truth about what exists, so anything not seen in it is gone. There is
    no tombstone: a URL Palo Alto has withdrawn is not something the assistant should still cite.
    """
    cur.execute("DELETE FROM techdoc.document WHERE NOT (url = ANY(%s))", (list(keep_urls),))
    return cur.rowcount


def known_urls(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT url FROM techdoc.document")
        return {row[0] for row in cur}


def status(conn):
    """What the console card shows at rest."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT count(*), count(DISTINCT content_sha), coalesce(sum(char_count), 0),
                   max(fetched_at)
              FROM techdoc.document
        """)
        documents, bodies, chars, fetched = cur.fetchone()
        cur.execute("""
            SELECT id, coalesce(finished_at, started_at), status
              FROM techdoc.crawl_run ORDER BY id DESC LIMIT 1
        """)
        run = cur.fetchone()
    return {
        "documents": documents or 0,
        "bodies": bodies or 0,
        "chars": int(chars or 0),
        "last_run_id": run[0] if run else 0,
        "last_run_at": (run[1].isoformat() if run and run[1]
                        else fetched.isoformat() if fetched else ""),
        "last_run_status": run[2] if run else "",
    }


def product_tree(conn):
    """The corpus grouped by the product and book each URL implies.

    Derived in the query rather than stored in columns: the URL is the only authority on where a
    page sits, and a denormalised copy is one more thing that can drift out of agreement with it.
    """
    with conn.cursor() as cur:
        cur.execute("""
            WITH parts AS (
                SELECT url, char_count, content_sha,
                       split_part(replace(url, 'https://docs.paloaltonetworks.com/', ''), '/', 1) AS product,
                       split_part(replace(url, 'https://docs.paloaltonetworks.com/', ''), '/', 2) AS second
                  FROM techdoc.document
            )
            SELECT product,
                   CASE WHEN second ~ '^[0-9]+-[0-9]+$' THEN '' ELSE second END AS docset,
                   count(*), count(DISTINCT content_sha), coalesce(sum(char_count), 0)
              FROM parts
             WHERE product <> ''
          GROUP BY 1, 2
          ORDER BY count(*) DESC
        """)
        return [
            {"product": r[0], "docset": r[1], "documents": r[2], "bodies": r[3], "chars": int(r[4])}
            for r in cur
        ]


def start_run(conn):
    with conn.cursor() as cur:
        cur.execute("INSERT INTO techdoc.crawl_run DEFAULT VALUES RETURNING id")
        run_id = cur.fetchone()[0]
    conn.commit()
    return run_id


def finish_run(conn, run_id, status_text, counts, error=None):
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE techdoc.crawl_run
               SET finished_at = now(), status = %s, error = %s,
                   listed = %s, stored = %s, rejected = %s
             WHERE id = %s
            """,
            (status_text, error, counts.get("listed", 0), counts.get("stored", 0),
             counts.get("rejected", 0), run_id),
        )
    conn.commit()


# A crawl that has reported nothing for this long is not running any more. Generous against the
# survey pass, which is a single sweep of HEADs and reports only when it finishes.
STALE_AFTER = "30 minutes"


def reap_stale_runs(conn):
    """Close out runs whose process died without saying so. → rows closed.

    start_run() writes the row before the crawl reports anything, so a process killed in between
    leaves a row marked running that nothing will ever finish — and the database-level guard then
    refuses every later crawl as "already running". The guard is right; what was missing is anyone
    noticing the claimant is gone.

    Judged by silence rather than by a process check: the claimant may be the CLI or the gRPC
    service, on this host or not, and "has not written a document in half an hour" is true of a
    dead crawl however it died.
    """
    with conn.cursor() as cur:
        cur.execute(f"""
            UPDATE techdoc.crawl_run
               SET status = 'failed', finished_at = now(),
                   error = 'no progress reported; the crawl process is gone'
             WHERE status = 'running'
               AND started_at < now() - interval '{STALE_AFTER}'
               AND NOT EXISTS (
                   SELECT 1 FROM techdoc.document
                    WHERE fetched_at > now() - interval '{STALE_AFTER}')
        """)
        closed = cur.rowcount
    conn.commit()
    return closed


def running_run(conn):
    """→ (id, started_at) of a crawl already in flight, or None. Checked in the database because
    the CLI and the gRPC service are two processes writing the same schema.

    Stale claims are reaped first, so a crawl killed mid-run does not lock the appliance out of
    every later one.
    """
    reap_stale_runs(conn)
    with conn.cursor() as cur:
        cur.execute("""
            SELECT id, started_at FROM techdoc.crawl_run
             WHERE status = 'running' ORDER BY id DESC LIMIT 1
        """)
        return cur.fetchone()


def documents(conn, product, docset):
    """Titles and URLs under one product/book, for the corpus browser.

    The same path split the tree uses, applied as a filter. Bodies are deliberately not returned:
    they run to five megabytes and nothing in the browser reads them.
    """
    with conn.cursor() as cur:
        cur.execute("""
            WITH parts AS (
                SELECT url, title, char_count, lastmod,
                       split_part(replace(url, 'https://docs.paloaltonetworks.com/', ''), '/', 1) AS product,
                       split_part(replace(url, 'https://docs.paloaltonetworks.com/', ''), '/', 2) AS second
                  FROM techdoc.document
            )
            SELECT url, title, char_count, lastmod
              FROM parts
             WHERE product = %s
               AND CASE WHEN second ~ '^[0-9]+-[0-9]+$' THEN '' ELSE second END = %s
          ORDER BY url
        """, (product, docset or ""))
        return [
            {"url": r[0], "title": r[1], "char_count": r[2],
             "lastmod": r[3].isoformat() if r[3] else ""}
            for r in cur
        ]
