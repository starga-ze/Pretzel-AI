-- Additive migration: keep the active document contract; archive removals for recovery.
BEGIN;
ALTER TABLE techdoc.document ADD COLUMN IF NOT EXISTS product TEXT NOT NULL DEFAULT '';
ALTER TABLE techdoc.document ADD COLUMN IF NOT EXISTS docset TEXT NOT NULL DEFAULT '';
ALTER TABLE techdoc.document ADD COLUMN IF NOT EXISTS version TEXT NOT NULL DEFAULT '';
ALTER TABLE techdoc.document ADD COLUMN IF NOT EXISTS information_type TEXT NOT NULL DEFAULT '';
ALTER TABLE techdoc.document ADD COLUMN IF NOT EXISTS parser_version TEXT NOT NULL DEFAULT '';
UPDATE techdoc.document SET
    product = split_part(replace(url, 'https://docs.paloaltonetworks.com/', ''), '/', 1),
    docset = CASE WHEN split_part(replace(url, 'https://docs.paloaltonetworks.com/', ''), '/', 2) ~ '^[0-9]+-[0-9]+(-[0-9]+)?$'
        THEN split_part(replace(url, 'https://docs.paloaltonetworks.com/', ''), '/', 3)
        ELSE split_part(replace(url, 'https://docs.paloaltonetworks.com/', ''), '/', 2) END,
    version = CASE
        WHEN split_part(replace(url, 'https://docs.paloaltonetworks.com/', ''), '/', 2) ~ '^[0-9]+-[0-9]+(-[0-9]+)?$'
        THEN replace(split_part(replace(url, 'https://docs.paloaltonetworks.com/', ''), '/', 2), '-', '.')
        WHEN split_part(replace(url, 'https://docs.paloaltonetworks.com/', ''), '/', 3) ~ '^[0-9]+-[0-9]+(-[0-9]+)?$'
        THEN replace(split_part(replace(url, 'https://docs.paloaltonetworks.com/', ''), '/', 3), '-', '.')
        ELSE '' END
WHERE product = '';
CREATE INDEX IF NOT EXISTS document_category_idx ON techdoc.document(product, docset, version);
ALTER TABLE techdoc.crawl_run ADD COLUMN IF NOT EXISTS scope TEXT NOT NULL DEFAULT '';
ALTER TABLE techdoc.crawl_run ADD COLUMN IF NOT EXISTS dry_run BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE techdoc.crawl_run ADD COLUMN IF NOT EXISTS heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE techdoc.crawl_run ADD COLUMN IF NOT EXISTS summary JSONB NOT NULL DEFAULT '{}';
CREATE TABLE IF NOT EXISTS techdoc.crawl_observation (
    run_id BIGINT NOT NULL REFERENCES techdoc.crawl_run(id),
    url TEXT NOT NULL,
    final_url TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('document', 'non_document', 'unavailable', 'unknown')),
    reason TEXT NOT NULL,
    http_status INTEGER NOT NULL DEFAULT 0,
    detail TEXT NOT NULL DEFAULT '',
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (run_id, url)
);
CREATE INDEX IF NOT EXISTS crawl_observation_url_idx ON techdoc.crawl_observation(url, run_id DESC);
CREATE TABLE IF NOT EXISTS techdoc.document_archive (
    id BIGSERIAL PRIMARY KEY,
    run_id BIGINT NOT NULL REFERENCES techdoc.crawl_run(id),
    url TEXT NOT NULL,
    reason TEXT NOT NULL,
    snapshot JSONB NOT NULL,
    archived_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS document_archive_url_idx ON techdoc.document_archive(url, id DESC);
COMMIT;
