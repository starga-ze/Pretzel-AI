-- Redirects, and what they cost.
--
-- docs.paloaltonetworks.com 301s whole subtrees onto a single page: 110 URLs under
-- pan-os/u-v/.../custom-signature-contexts/string-contexts/* all land on one Advanced Threat
-- Prevention page. urllib follows those silently, so the first crawl stored 110 documents whose
-- bodies were byte-identical and whose recorded URL was not the one the text came from.
--
-- Content deduplication already absorbed the storage cost, but two things were still wrong: a
-- citation pointed at the alias rather than at the page a reader should open, and every alias was
-- its own fetch candidate — one edit to the target scheduled 110 downloads of the same page.
--
-- canonical_url records where the fetch actually ended. It is NULL when nothing redirected, so
-- "did this move" stays a question with a cheap answer rather than a string comparison on
-- every row.
ALTER TABLE techdoc.document
    ADD COLUMN IF NOT EXISTS canonical_url TEXT;

-- Aliases are looked up by target when a refresh decides what it can skip.
CREATE INDEX IF NOT EXISTS document_canonical_idx
    ON techdoc.document (canonical_url) WHERE canonical_url IS NOT NULL;
