-- pretzel_knowledge — the tech-doc knowledge base behind the RAG assistant.
--
-- Two schemas, two owners, two lifecycles:
--
--   techdoc  crawled from docs.paloaltonetworks.com. Expensive to reacquire (an external
--            dependency and a full-corpus fetch), so this is the half that must be backed up.
--   corpus   chunks and embeddings, derived from techdoc. Reproducible locally from nothing
--            but CPU, and rebuilt outright whenever the chunking rules or the embedding model
--            change — which is why it is not mixed in with the crawl.
--
-- Schemas rather than separate databases: the foreign key from corpus into techdoc.content is
-- what stops embeddings outliving the text they describe, and retrieval joins chunk -> document
-- on every query to cite a source. Both are lost across a database boundary and neither is
-- worth giving up for an isolation that a schema already provides.
--
-- Note engined is untouched by all of this: it remains the sole writer of the `pretzel`
-- configuration database. This one has exactly one writer of its own, pretzel-ai.

CREATE SCHEMA IF NOT EXISTS techdoc;
CREATE SCHEMA IF NOT EXISTS corpus;

-- ---------------------------------------------------------------------------
-- techdoc.content — page bodies, keyed by hash rather than by URL.
--
-- 42% of the sitemap is version-tagged URLs and ~40% of extracted bodies are byte-identical
-- across them, so a URL-keyed table would store (and later embed) the same text dozens of
-- times. Keying on the hash collapses that automatically: N documents referencing one body
-- get chunked once and embedded once.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS techdoc.content (
    sha         BYTEA PRIMARY KEY,          -- sha256 of the extracted text
    text        TEXT        NOT NULL,
    char_count  INTEGER     NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- techdoc.document — one row per canonical URL (fragments stripped).
--
-- lastmod/etag/last_modified are the first two staleness gates. They answer "might this have
-- changed"; only the content hash answers "did it". Keeping all three means a refresh can skip
-- the fetch (304) or skip the re-embed (same sha) without ever guessing.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS techdoc.document (
    url            TEXT PRIMARY KEY,
    product        TEXT NOT NULL,           -- first path segment: pan-os, ngfw, prisma-access
    version        TEXT,                    -- '11-2' where the URL carries one, else NULL
    docset         TEXT,                    -- the book within the product
    section_path   TEXT,                    -- remainder of the path
    title          TEXT,

    lastmod        TIMESTAMPTZ,             -- gate 1: sitemap <lastmod>
    etag           TEXT,                    -- gate 2: conditional GET
    last_modified  TEXT,                    -- gate 2: conditional GET
    content_sha    BYTEA REFERENCES techdoc.content(sha),   -- gate 3

    http_status    INTEGER,
    fetch_error    TEXT,                    -- set when the last attempt failed
    fetched_at     TIMESTAMPTZ,
    -- Set when the URL leaves the sitemap. A tombstone rather than a DELETE: retrieval must be
    -- able to explain a citation that pointed at a page Palo Alto has since withdrawn.
    deleted_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS document_product_idx  ON techdoc.document (product);
CREATE INDEX IF NOT EXISTS document_sha_idx      ON techdoc.document (content_sha);
CREATE INDEX IF NOT EXISTS document_live_idx     ON techdoc.document (product)
    WHERE deleted_at IS NULL;

-- ---------------------------------------------------------------------------
-- techdoc.crawl_run — what the console card reads.
--
-- skipped_304 and skipped_same_sha are reported separately on purpose: together they are the
-- evidence that a refresh which "changed 12 of 21,768 pages" actually looked at all of them.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS techdoc.crawl_run (
    id                BIGSERIAL PRIMARY KEY,
    started_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at       TIMESTAMPTZ,
    status            TEXT NOT NULL DEFAULT 'running',  -- running|ok|failed|cancelled
    scope             TEXT,                             -- product filter, NULL = whole sitemap
    checked           INTEGER NOT NULL DEFAULT 0,
    fetched           INTEGER NOT NULL DEFAULT 0,
    changed           INTEGER NOT NULL DEFAULT 0,
    added             INTEGER NOT NULL DEFAULT 0,
    removed           INTEGER NOT NULL DEFAULT 0,
    skipped_304       INTEGER NOT NULL DEFAULT 0,
    skipped_same_sha  INTEGER NOT NULL DEFAULT 0,
    failed            INTEGER NOT NULL DEFAULT 0,
    error             TEXT
);
