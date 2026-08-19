-- Which rows have been through a fetch that records redirects.
--
-- canonical_url alone cannot answer this: NULL means "nothing redirected" for a row fetched after
-- the redirect fix, and "nobody looked" for a row fetched before it. Those two are the same value
-- and completely different facts, and the second one is hiding real damage — 997 whats-new URLs
-- all 301 to /platform-explorer, so the store holds 997 documents whose body is a landing page
-- none of them is. They read as successful fetches, so no error-based retry finds them.
--
-- Defaulting to false marks every existing row as unverified, which is exactly what they are.
ALTER TABLE techdoc.document
    ADD COLUMN IF NOT EXISTS redirect_checked BOOLEAN NOT NULL DEFAULT false;

CREATE INDEX IF NOT EXISTS document_unchecked_idx
    ON techdoc.document (url) WHERE NOT redirect_checked;
