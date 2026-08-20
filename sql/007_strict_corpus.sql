-- Strict corpus: the store keeps documents, not attempts.
--
-- Until now a failed fetch stayed as a row so the next refresh could retry it, and the corpus view
-- filtered those out at read time. That was the right shape for an incremental crawl. It is the
-- wrong shape for this one: every update re-fetches the whole sitemap, so a page that failed is
-- simply tried again from scratch, and a row recording last time's failure has no reader.
--
-- What is left after a crawl is therefore only what a reader can use — a URL with a title, a body,
-- and a date. Everything else is deleted rather than flagged:
--
--   fetch_error      404s and unreadable pages. 218 of the 21,926 are sitemap entries for pages
--                    Palo Alto has removed; they are not documents and never become any.
--   no content_sha   nothing was stored to read.
--   residual_chars=0 the page restates its own headings and says nothing else — a section landing
--                    page, which matches every query about its product and answers none.
--   alias            a URL that 301s onto a document stored under its own URL. 4,289 of them, and
--                    997 of those land on one page; keeping them would put that page in the index
--                    a thousand times.
--
-- The one exception is an alias whose target is not itself stored: there the alias row carries the
-- only copy of the text, so it stays and is treated as the document it is.

CREATE OR REPLACE FUNCTION techdoc.prune_incomplete() RETURNS TABLE(reason TEXT, removed BIGINT) AS $$
BEGIN
    RETURN QUERY
    WITH gone AS (
        DELETE FROM techdoc.document d
        USING techdoc.content c
        WHERE c.sha = d.content_sha AND c.residual_chars = 0
        RETURNING 'no content'::TEXT AS r
    ) SELECT r, count(*) FROM gone GROUP BY r;

    RETURN QUERY
    WITH gone AS (
        DELETE FROM techdoc.document d
        WHERE d.fetch_error IS NOT NULL OR d.content_sha IS NULL
        RETURNING 'unreadable'::TEXT AS r
    ) SELECT r, count(*) FROM gone GROUP BY r;

    RETURN QUERY
    WITH gone AS (
        DELETE FROM techdoc.document d
        WHERE d.canonical_url IS NOT NULL
          AND EXISTS (SELECT 1 FROM techdoc.document t WHERE t.url = d.canonical_url)
        RETURNING 'alias'::TEXT AS r
    ) SELECT r, count(*) FROM gone GROUP BY r;

    RETURN QUERY
    WITH gone AS (
        DELETE FROM techdoc.document d WHERE d.deleted_at IS NOT NULL
        RETURNING 'withdrawn'::TEXT AS r
    ) SELECT r, count(*) FROM gone GROUP BY r;

    RETURN QUERY
    WITH gone AS (
        DELETE FROM techdoc.content c
        WHERE NOT EXISTS (SELECT 1 FROM techdoc.document d WHERE d.content_sha = c.sha)
        RETURNING 'orphan body'::TEXT AS r
    ) SELECT r, count(*) FROM gone GROUP BY r;
END;
$$ LANGUAGE plpgsql;

-- With the store already strict, the view is just a join now: no filtering left to do.
CREATE OR REPLACE VIEW techdoc.corpus_source AS
    SELECT d.url, d.product, d.version, d.docset, d.section_path,
           d.title, d.lastmod, d.content_sha, c.text, c.char_count, c.residual_chars
      FROM techdoc.document d
      JOIN techdoc.content c ON c.sha = d.content_sha;
