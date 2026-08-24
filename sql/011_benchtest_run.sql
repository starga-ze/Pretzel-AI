-- Benchtest runs: what was executed against a set, and what each prompt did.
--
-- Split for the same reason dataset/row is. A run is a fact independent of its cases: it has a
-- status while nothing has finished yet, it has a scope before the first prompt is sent, and it
-- still exists when the gateway was unreachable and no case ever ran. Folded into one table those
-- three states have nowhere to live — a run with no cases would simply not be a row.
--
-- The filter is snapshotted onto the run rather than referenced. It is what makes a result
-- readable a month later: "74% detected" is only an answer next to which prompts were in scope,
-- and re-deriving that from the filter the console happens to have selected now would answer a
-- different question.

CREATE TABLE IF NOT EXISTS benchmark.run (
    id           BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    dataset_id   BIGINT      NOT NULL REFERENCES benchmark.dataset(id) ON DELETE CASCADE,

    -- The scope, exactly as the console had it when Run was pressed. Empty means "not filtered on
    -- this column", which is what the All chip sets.
    f_category   TEXT        NOT NULL DEFAULT '',
    f_verdict    TEXT        NOT NULL DEFAULT '',
    f_language   TEXT        NOT NULL DEFAULT '',
    f_technique  TEXT        NOT NULL DEFAULT '',
    f_search     TEXT        NOT NULL DEFAULT '',

    -- How many prompts the filter matched when the run started. Recorded rather than counted from
    -- run_case: a cancelled run has fewer cases than it selected, and the difference is the point.
    selected     INTEGER     NOT NULL,

    status       TEXT        NOT NULL DEFAULT 'running',
    error        TEXT        NOT NULL DEFAULT '',
    model        TEXT        NOT NULL DEFAULT '',
    started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at     TIMESTAMPTZ,

    CONSTRAINT run_status_ck   CHECK (status IN ('running', 'done', 'cancelled', 'failed')),
    CONSTRAINT run_selected_ck CHECK (selected >= 0),
    -- A run that has ended has an end time, and one still going has none. Enforced here so the
    -- "is anything running" question is answerable from the row rather than from a convention.
    CONSTRAINT run_ended_ck    CHECK ((status = 'running') = (ended_at IS NULL))
);

CREATE INDEX IF NOT EXISTS run_dataset_idx ON benchmark.run (dataset_id, started_at DESC);
CREATE INDEX IF NOT EXISTS run_started_idx ON benchmark.run (started_at DESC, id DESC);

-- At most one run at a time on the appliance. A second one against the same set would interleave
-- with the first and neither result would be attributable; enforced in the schema rather than in
-- the runner, because a process restart must not be able to lose the fact.
CREATE UNIQUE INDEX IF NOT EXISTS run_single_active_idx
    ON benchmark.run ((status = 'running')) WHERE status = 'running';

CREATE TABLE IF NOT EXISTS benchmark.run_case (
    run_id        BIGINT  NOT NULL REFERENCES benchmark.run(id) ON DELETE CASCADE,

    -- Position within the run, 1-based. The key rather than the prompt id: it exists before the
    -- case has a result, and it is the order the console renders as the run ticks along.
    seq           INTEGER NOT NULL,

    prompt_id     TEXT    NOT NULL,
    row_no        INTEGER NOT NULL,   -- where it sits in the set, for lining up with the table
    expected      TEXT    NOT NULL,   -- block | allow, from the set

    -- What the gateway did: allow | block | flagged | not_inspected | error.
    verdict       TEXT    NOT NULL DEFAULT '',

    -- The scored outcome — 정탐 / 정탐(오분류) / 미탐 / 미탐(모델거부) / 미탐(도구호출) / 오탐 /
    -- 오탐(오분류) / 정상통과 / 미검사 / 호출실패. Stored as the runner decided it, not
    -- recomputed on read: the rules change as the benchmark is refined, and a result must keep
    -- meaning what it meant when it was recorded.
    cause         TEXT    NOT NULL DEFAULT '',
    ok            BOOLEAN,            -- NULL = excluded from the rate (uninspected / call failed)

    scan_id       TEXT    NOT NULL DEFAULT '',
    detectors     TEXT[]  NOT NULL DEFAULT '{}',  -- which AIRS detectors fired
    caught        TEXT    NOT NULL DEFAULT '',    -- 요청 | 응답 | 요청+응답 | -
    http_status   INTEGER,
    latency_ms    INTEGER,

    -- The whole exchange. This is what "details" means on the case drawer: an operator disputing a
    -- verdict needs the request that was sent and the document that came back, not a summary of
    -- them. Roughly 2 KB a case, so a 1,500-prompt run costs a few MB — cheap next to being unable
    -- to answer "why did this one fail" after the fact.
    request_json  JSONB,
    response_json JSONB,

    reply         TEXT    NOT NULL DEFAULT '',    -- the model's text, lifted out for the list view
    tool_calls    JSONB,                          -- tool calls the model issued, when it did

    PRIMARY KEY (run_id, seq)
);

CREATE UNIQUE INDEX IF NOT EXISTS run_case_prompt_idx ON benchmark.run_case (run_id, prompt_id);
CREATE INDEX IF NOT EXISTS run_case_cause_idx ON benchmark.run_case (run_id, cause);
