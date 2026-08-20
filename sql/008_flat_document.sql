-- The final shape: one row per URL, and nothing that is not a document.
--
-- Everything the previous schema carried for incremental crawling is gone, because there is no
-- incremental crawl any more. An update re-fetches the whole sitemap, so there is nothing to
-- compare against and nothing to remember between runs:
--
--   last_modified / lastmod-gating   no conditional requests; every page is fetched
--   fetch_error / http_status        a page that cannot be read is not stored
--   deleted_at                       a page that left the sitemap is not stored
--   canonical_url / redirect_checked  a redirect is followed and the target is what gets stored
--   product / version / docset        derivable from the URL whenever a reader wants them, and a
--                                    stored copy is one more thing that can disagree with it
--
-- The body moves onto the row. It was in its own table so that N URLs sharing one text embedded
-- once; with duplicate vectors now collapsed at ranking time instead, that indirection buys a 20%
-- saving and costs a join on every citation. content_sha stays — not to join on, but so the
-- ranking step can tell two identical bodies apart from two similar ones.
--
-- NOT NULL on title, text and content_sha is the point of this migration. The old schema let an
-- incomplete row exist and relied on a view to hide it; this one cannot hold one.

CREATE TABLE IF NOT EXISTS techdoc.document_v2 (
    url          TEXT        PRIMARY KEY,
    title        TEXT        NOT NULL,
    text         TEXT        NOT NULL,
    content_sha  BYTEA       NOT NULL,
    char_count   INTEGER     NOT NULL,
    lastmod      TIMESTAMPTZ,              -- vendor's last edit, from the sitemap
    fetched_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS document_v2_sha_idx ON techdoc.document_v2 (content_sha);

-- Carry over what already passes the new rules, so a rebuild is not required to start using it.
INSERT INTO techdoc.document_v2 (url, title, text, content_sha, char_count, lastmod, fetched_at)
SELECT d.url, d.title, c.text, c.sha, c.char_count, d.lastmod, d.fetched_at
  FROM techdoc.document d
  JOIN techdoc.content c ON c.sha = d.content_sha
 WHERE d.fetch_error IS NULL
   AND d.deleted_at IS NULL
   AND d.title IS NOT NULL AND d.title <> ''
   AND c.residual_chars > 0
   AND (d.canonical_url IS NULL
        OR NOT EXISTS (SELECT 1 FROM techdoc.document t WHERE t.url = d.canonical_url))
ON CONFLICT (url) DO NOTHING;
