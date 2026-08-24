-- A name for a run, given when it is started.
--
-- Runs accumulate and are compared, and "#7" tells a reader nothing about why it was made. The
-- label is the operator's own note — "baseline before profile change", "db-security on" — and it
-- is the only thing in the row that a person wrote rather than the machine recorded.
--
-- Empty is allowed and normal: a run started without one is still a run, and forcing a name on
-- somebody who just wants to see a number would get names like "test" and "test2".
ALTER TABLE benchmark.run ADD COLUMN IF NOT EXISTS label TEXT NOT NULL DEFAULT '';
