-- Retire the incremental-crawl structures. document_v2 becomes document.
DROP VIEW  IF EXISTS techdoc.corpus_source;
DROP FUNCTION IF EXISTS techdoc.prune_incomplete();
DROP TABLE IF EXISTS techdoc.document CASCADE;
DROP TABLE IF EXISTS techdoc.content  CASCADE;
ALTER TABLE techdoc.document_v2 RENAME TO document;
ALTER INDEX techdoc.document_v2_sha_idx RENAME TO document_sha_idx;

-- crawl_run keeps only what a full re-crawl can report. The skip counters described gates that
-- no longer exist.
DROP TABLE IF EXISTS techdoc.crawl_run;
CREATE TABLE techdoc.crawl_run (
    id           BIGSERIAL PRIMARY KEY,
    started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at  TIMESTAMPTZ,
    status       TEXT NOT NULL DEFAULT 'running',   -- running | ok | failed | cancelled
    listed       INTEGER NOT NULL DEFAULT 0,        -- URLs the sitemap offered
    stored       INTEGER NOT NULL DEFAULT 0,        -- documents that passed every rule
    rejected     INTEGER NOT NULL DEFAULT 0,        -- fetched but not a usable document
    error        TEXT
);
