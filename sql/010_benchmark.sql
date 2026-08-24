-- Benchmark sets: the prompt files the guardrail is scored against.
--
-- The console uploads a .jsonl and it lands here whole. Several sets coexist on purpose — a run
-- recorded last week was scored against the generation that existed last week, and deleting or
-- overwriting that set would leave the result meaning nothing. So an upload never mutates an
-- existing set: it creates a new one, and the old one stays readable until somebody removes it.
--
-- Two tables, and the split is the important part:
--
--   dataset   one uploaded file. Carries what a reader needs to tell two sets apart — where it
--             came from, when, how big, and the digest of the bytes.
--   row       the prompts of one file. Owned by the dataset; a delete takes them with it.
--
-- content_sha is UNIQUE, so re-uploading the same bytes is recognised rather than duplicated. The
-- caller is told which set it already is instead of getting a second copy under a new name — two
-- identical sets with different ids is the one state that makes a result ambiguous.

CREATE SCHEMA IF NOT EXISTS benchmark;

CREATE TABLE IF NOT EXISTS benchmark.dataset (
    id           BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name         TEXT        NOT NULL,
    filename     TEXT        NOT NULL,
    content_sha  BYTEA       NOT NULL UNIQUE,
    byte_size    BIGINT      NOT NULL,
    row_count    INTEGER     NOT NULL,
    note         TEXT        NOT NULL DEFAULT '',
    uploaded_by  TEXT        NOT NULL DEFAULT '',
    uploaded_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT dataset_name_ck      CHECK (length(name) BETWEEN 1 AND 200),
    CONSTRAINT dataset_row_count_ck CHECK (row_count > 0),
    CONSTRAINT dataset_size_ck      CHECK (byte_size > 0)
);

-- The list is always newest first, and the name is what an operator searches by.
CREATE INDEX IF NOT EXISTS dataset_uploaded_idx ON benchmark.dataset (uploaded_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS dataset_name_idx     ON benchmark.dataset (lower(name));

CREATE TABLE IF NOT EXISTS benchmark.row (
    dataset_id      BIGINT  NOT NULL REFERENCES benchmark.dataset(id) ON DELETE CASCADE,

    -- Position in the uploaded file, 1-based. The primary key rather than the prompt id, because
    -- this is the address an upload error is reported against and it exists before the row has
    -- been validated. It also keeps the file's own order recoverable.
    row_no          INTEGER NOT NULL,

    -- The generator's identifier (ATK-A-0101). Unique inside a set: two prompts under one id
    -- would make every result recorded against that id ambiguous, so the constraint is here and
    -- not only in the loader.
    prompt_id       TEXT    NOT NULL,

    category        TEXT    NOT NULL DEFAULT '',
    category_ko     TEXT    NOT NULL DEFAULT '',
    category_en     TEXT    NOT NULL DEFAULT '',
    verdict         TEXT    NOT NULL DEFAULT '',   -- malicious | benign
    expected        TEXT    NOT NULL DEFAULT '',   -- block | allow
    scan_target     TEXT    NOT NULL DEFAULT '',   -- prompt | response | tool
    language        TEXT    NOT NULL DEFAULT '',   -- mix | ko | en
    technique       TEXT    NOT NULL DEFAULT '',
    expected_labels TEXT[]  NOT NULL DEFAULT '{}', -- AIRS detector ids expected to fire
    severity        TEXT    NOT NULL DEFAULT '',
    origin          TEXT    NOT NULL DEFAULT '',
    prompt          TEXT    NOT NULL,

    -- Any field the file carried that this schema has no column for. A benchmark from somewhere
    -- other than dataset/ will have some, and dropping them on import would make the stored set a
    -- lossy copy of the file the operator uploaded.
    extra           JSONB   NOT NULL DEFAULT '{}'::jsonb,

    PRIMARY KEY (dataset_id, row_no)
);

CREATE UNIQUE INDEX IF NOT EXISTS row_prompt_id_idx ON benchmark.row (dataset_id, prompt_id);

-- The console filters within one set on these; every listing is scoped by dataset_id first.
CREATE INDEX IF NOT EXISTS row_category_idx  ON benchmark.row (dataset_id, category);
CREATE INDEX IF NOT EXISTS row_verdict_idx   ON benchmark.row (dataset_id, verdict);
CREATE INDEX IF NOT EXISTS row_language_idx  ON benchmark.row (dataset_id, language);
CREATE INDEX IF NOT EXISTS row_technique_idx ON benchmark.row (dataset_id, technique);
