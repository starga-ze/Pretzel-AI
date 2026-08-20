-- The corpus source, with content-free pages excluded.
--
-- Five exclusions now. The first four are about whether the page was obtained; the last is about
-- whether obtaining it produced anything:
--
--   no body            fetch failed, or the content root rendered to nothing (JS-built landing
--                      pages). Embedding these puts empty chunks in the index.
--   fetch_error        read failure of any kind. Kept in techdoc so a refresh retries it, kept out
--                      of the corpus so the assistant never cites a page nobody could read.
--   deleted_at         withdrawn from the sitemap. The row survives so an old citation resolves;
--                      the text stops being answerable.
--   resolvable alias   a URL that 301s onto a document stored under its own URL. 997 whats-new
--                      URLs redirect to /platform-explorer alone. Conditional on the target being
--                      present: ~44 aliases point at pages the sitemap never lists, and for those
--                      the alias row is the only copy of the text there is.
--   residual_chars = 0 the page restates its own headings and carries nothing else — a section
--                      landing page. Structural, not a length cutoff: a 5.1 MB CLI command
--                      hierarchy has no sentence in it and is kept, a 113-character page that is
--                      a date line plus its own title is not.
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
           c.char_count,
           c.residual_chars
      FROM techdoc.document d
      JOIN techdoc.content c ON c.sha = d.content_sha
     WHERE d.fetch_error IS NULL
       AND d.deleted_at IS NULL
       AND coalesce(c.residual_chars, 0) > 0
       AND (d.canonical_url IS NULL
            OR NOT EXISTS (SELECT 1 FROM techdoc.document t WHERE t.url = d.canonical_url));
