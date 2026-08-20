-- Content-free pages, and one dead column.
--
-- residual_chars is how many characters a body has left once its headings, its template labels
-- ("Where Can I Use This?", "Updated on …") and its repeated breadcrumb lines are removed. Zero
-- means the page restates its own title and carries nothing else: a section landing page, of which
-- the corpus holds a couple of hundred. They embed to vectors that match every query about their
-- product and answer none of them.
--
-- Measured rather than thresholded on body length on purpose. A 5.1 MB PAN-OS CLI command
-- hierarchy is bare commands with no sentence in it anywhere, and it is exactly what a support
-- assistant gets asked about; any rule phrased in terms of prose would have discarded it.
ALTER TABLE techdoc.content
    ADD COLUMN IF NOT EXISTS residual_chars INTEGER;

-- etag is dead. It was recorded for conditional requests and never used for them: this site serves
-- a different ETag for the same unchanged page on consecutive requests, so If-None-Match never
-- matched and every request came back 200 with a full body. If-Modified-Since is what works, and
-- last_modified is what carries it.
ALTER TABLE techdoc.document DROP COLUMN IF EXISTS etag;

-- Redirect targets recorded before the URL normaliser learned to collapse repeated slashes. The
-- server answers some 301s with an empty path segment (ngfw/networking//session-settings), so the
-- stored target matched no document and the alias looked like it pointed nowhere.
UPDATE techdoc.document
   SET canonical_url = 'https://' || regexp_replace(substring(canonical_url from 9), '/+', '/', 'g')
 WHERE canonical_url LIKE 'https://%//%';
