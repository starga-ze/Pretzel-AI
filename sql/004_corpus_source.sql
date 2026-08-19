-- What the corpus stage is allowed to read.
--
-- Defined once, as a view, because this predicate is the boundary between "we crawled it" and "the
-- assistant may answer out of it", and the two halves of the pipeline must not each carry their own
-- idea of where that line is.
--
-- Four exclusions, each for a different reason:
--
--   no body            a fetch that failed, or a page whose content root rendered to nothing (the
--                      JS-rendered landing pages). Not documents; embedding them would put empty
--                      chunks in the index.
--   fetch_error        read failure of any kind. Kept in techdoc so a refresh can retry it, kept
--                      out of the corpus so the assistant never cites a page nobody could read.
--   deleted_at         withdrawn from the sitemap. The row survives so an old citation still
--                      resolves; the text stops being answerable.
--   resolvable alias   a URL that 301s onto a document already stored under its own URL. 997
--                      whats-new URLs redirect to /platform-explorer alone — embedding each of
--                      them would put that one landing page into the index a thousand times.
--
-- The alias exclusion is deliberately conditional on the target being present. Roughly thirty
-- aliases point at pages the sitemap never lists (product landing pages such as /enterprise-dlp),
-- and for those the alias row is the only copy of the text there is. Dropping every alias
-- unconditionally would silently lose them.
CREATE OR REPLACE VIEW techdoc.corpus_source AS
    SELECT d.url,
           d.product,
           d.version,
           d.docset,
           d.section_path,
           d.title,
           d.lastmod,
           d.content_sha,
           c.text,
           c.char_count
      FROM techdoc.document d
      JOIN techdoc.content c ON c.sha = d.content_sha
     WHERE d.fetch_error IS NULL
       AND d.deleted_at IS NULL
       AND (d.canonical_url IS NULL
            OR NOT EXISTS (SELECT 1 FROM techdoc.document t WHERE t.url = d.canonical_url));
