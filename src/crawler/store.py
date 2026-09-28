"""techdoc.document: one row per URL, and nothing that is not a document.

Seven columns, flat: url (PK), title, text, content_sha, char_count, lastmod, fetched_at. The
sha-keyed body table this schema started with is gone (009); a body lives inline on its row and
the hash is a column beside it. sql/001 still describes the old shape and says so at the top.

The store holds documents, not attempts. A page that 404s, redirects onto another page, renders to
nothing, or has no title never reaches this module — `pipeline` drops it — so the table cannot hold
a half-record. One column is nullable and it is the exception that proves it: `lastmod` comes from
the sitemap, and a page reached as a redirect target need not be listed there at all. A missing
vendor timestamp is a fact about the sitemap, not a half-written document.

content_sha carries the deduplication. Palo Alto ships the same section in several manuals (twenty
hardware references share one "Third-Party Component Support" page), so ~21% of rows carry a body
byte-identical to another's — 17,690 rows, 13,965 distinct bodies. Retrieval collapses those at
ranking time. It is also the grain chunking and embedding must work at: keyed by URL they would
embed one body twenty times and fill a top-k with the same text under different links.
document_sha_idx exists for that join.
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
    """Insert or replace one document. A REPLACE is total, and that is the point.

    Every column but the URL is overwritten with what this fetch found, so the row is always the
    page as the site serves it now. There is no history and no previous version to fall back on:
    the corpus mirrors the site rather than recording how it got here.

    Two consequences worth knowing before building on this table:

      * A fetch that FAILS writes nothing, so the old row survives the attempt — and survives
        the crawl too: `drop_missing` is passed the URLs whose fetch errored alongside the ones
        stored, precisely so a 403 does not read as a withdrawal. What does not survive is a
        page that WAS read and found not to be a document.
      * content_sha changes whenever the body does, which is exactly the signal for re-chunking
        and re-embedding. Anything derived from a body and stored elsewhere is orphaned by this
        statement, not updated by it.
    """
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
    """Delete documents this crawl neither stored nor failed to read. → rows removed.

    A full crawl is the whole truth about what exists - but only about the pages it actually
    read. `keep_urls` is therefore the stored URLs PLUS the ones whose fetch errored, because
    those two are different answers:

        stored          read, and it is a document
        fetch errored   not read at all - 403, timeout, a shell response. Says nothing about
                        whether the page exists, so it must not be grounds for deletion
        rejected        read, and it is not a document - a landing page, a book cover, a page
                        with no title. This IS an answer, so the row goes

    Passing only the stored URLs meant a rate-limited run deleted good documents: sixteen went
    on 2026-09-21 when another HEAD load ran beside the crawl and Palo Alto answered 403 to
    pages that were serving normally minutes later. The failure is transient, the deletion was
    not, and the log line below read the same as a genuine withdrawal.

    There is no tombstone: a URL Palo Alto has withdrawn is not something the assistant should
    still cite.
    """
    cur.execute("DELETE FROM techdoc.document WHERE NOT (url = ANY(%s))", (list(keep_urls),))
    return cur.rowcount


def prune_small_products(cur, minimum):
    """Delete every document under a product that has fewer than `minimum` of them. → rows removed.

    What this removes is not documentation. docs.paloaltonetworks.com puts a handful of one-page
    trees beside the manuals - a locale index, a release-notes stub, a redirect target that kept
    its own path - and each becomes a "product" in the browser holding a single page that answers
    no question about it. A count rather than a name list because the names change with the site
    and a hard-coded list would rot silently; a product that is really a manual has hundreds of
    pages, and the nearest real one above this line has 29.

    Run after drop_missing, and only on a full crawl: the count is over the whole table, so a run
    scoped to one product would measure that product against a corpus it did not refresh.
    """
    cur.execute(
        f"""
        WITH counted AS (
            SELECT url, {PRODUCT_SQL} AS product FROM techdoc.document
        ),
        small AS (
            SELECT product FROM counted GROUP BY product HAVING count(*) < %s
        )
        DELETE FROM techdoc.document
              WHERE url IN (SELECT url FROM counted WHERE product IN (SELECT product FROM small))
        """,
        (minimum,),
    )
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


# The product a URL implies: its first path segment. Written once because product_tree groups by
# it and prune_small_products deletes by it, and two spellings of the same derivation would
# disagree the day one of them is corrected.
PRODUCT_SQL = "split_part(replace(url, 'https://docs.paloaltonetworks.com/', ''), '/', 1)"


def product_tree(conn):
    """The corpus grouped by the product and book each URL implies.

    Derived in the query rather than stored in columns: the URL is the only authority on where a
    page sits, and a denormalised copy is one more thing that can drift out of agreement with it.
    """
    with conn.cursor() as cur:
        cur.execute(f"""
            WITH parts AS (
                SELECT url, char_count, content_sha,
                       {PRODUCT_SQL} AS product,
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


# A search answers while someone is typing, so it is capped rather than paged: row 201 is not
# what the next keystroke wants, and a page-two button on a list that is about to be replaced is
# a control nobody reaches. The count of what was cut is reported instead, which is the part an
# operator actually needs — "200 of 1,432" says refine the term.
SEARCH_LIMIT = 200


def _literal_like(term):
    """`term` as a LIKE pattern matching it literally, wildcards and all.

    LIKE reads %, _ and backslash as syntax, so a term carrying one searches for something other
    than itself: an operator typing "100%" matched every document in the corpus. Escaped into the
    PARAMETER rather than the statement, which is why no ESCAPE clause is needed — backslash is
    already LIKE's default escape character.
    """
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def search(conn, query, limit=SEARCH_LIMIT):
    """→ (rows, total). URL or title substring, case-insensitive, over the whole corpus.

    Both columns, because neither answers alone. A term like "globalprotect" is a product and
    lives in the path; "decryption profile" is a phrase from a title that the URL only carries as
    a slug with the space removed. Searching one column would silently answer half the questions.

    Whole corpus rather than within the open book: the tree is the way to narrow by product, and
    a search that inherited whatever book was open would answer a different question depending on
    where the reader happened to be standing.

    ORDER BY url, so results arrive grouped by product and book — the same order the tree uses,
    and the only one available: a substring match has no relevance to rank by.

    `total` comes from a window function rather than a second COUNT query, so the number and the
    rows are one statement and cannot disagree with each other.
    """
    pattern = _literal_like(query)
    with conn.cursor() as cur:
        cur.execute("""
            SELECT url, title, char_count, lastmod, count(*) OVER () AS total
              FROM techdoc.document
             WHERE url ILIKE %s OR title ILIKE %s
          ORDER BY url
             LIMIT %s
        """, (pattern, pattern, limit))
        rows = cur.fetchall()
    return (
        [{"url": r[0], "title": r[1], "char_count": r[2],
          "lastmod": r[3].isoformat() if r[3] else ""}
         for r in rows],
        rows[0][4] if rows else 0,
    )
