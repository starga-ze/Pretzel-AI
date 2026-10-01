-- A refresh rebuilds the corpus instead of reconciling with it.
--
-- What the newest completed run collected IS techdoc.document. Pages it excluded or could not
-- read are simply absent, so there is no candidate to weigh, no deferral to explain and no
-- removal count to reconcile against the counts on screen.
--
-- `run_id` is what lets that be a swap rather than a truncate-and-refill: every row records the
-- run that wrote it, and the rows belonging to older runs go in one statement once the fetch has
-- finished. A crawl that dies at page 9,000 leaves the previous corpus standing.
--
-- techdoc.document_archive goes with the model it belonged to. It existed so a selective deletion
-- could be undone; a rebuild deletes nothing selectively, and a row it drops comes back by
-- running the update again. Keeping it would leave a table nothing writes to and nothing reads.
BEGIN;

ALTER TABLE techdoc.document ADD COLUMN IF NOT EXISTS run_id BIGINT NOT NULL DEFAULT 0;

-- Existing rows are credited to the run that last fetched them, so the first rebuild after this
-- migration does not mistake the whole corpus for stale and empty the table before refilling it.
UPDATE techdoc.document d SET run_id = r.id
  FROM techdoc.crawl_run r
 WHERE d.run_id = 0
   AND r.id = (SELECT max(id) FROM techdoc.crawl_run
                WHERE NOT dry_run AND status IN ('ok', 'warning'));

CREATE INDEX IF NOT EXISTS document_run_idx ON techdoc.document(run_id);

DROP TABLE IF EXISTS techdoc.document_archive;

COMMIT;
