-- A description alongside the run's name.
--
-- The name is what the run is called in a list; the description is why it was made — "profile
-- change: db-security on", "re-run of #12 after the C payload fix". Kept apart because the list
-- shows one and the summary shows both, and a single field would have to be short enough for the
-- list and long enough for the reason, which is two jobs.
ALTER TABLE benchmark.run ADD COLUMN IF NOT EXISTS note TEXT NOT NULL DEFAULT '';
