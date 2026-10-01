-- One vocabulary for the three outcomes: collected | excluded | unknown.
--
-- The same page outcome used to carry three different names - `document` on the decision column,
-- `stored` in the progress counters, "Collected" on screen - and a reader comparing a number to a
-- row had to know all three. This renames the stored ones to the words the console uses.
--
-- `unavailable` disappears as an outcome rather than being renamed. It always meant "correctly
-- not in the corpus", which is what `excluded` means; what actually separated it - that a 404
-- needs a second sighting before it may delete anything - is a property of the reason (http_404),
-- and that is where the crawler now reads it from. No information is lost: every row's `reason`
-- already says which kind of exclusion it was.
--
-- Historical runs are rewritten rather than read through a compatibility shim. A console that
-- understood both spellings would defeat the point of having one.
BEGIN;

-- The CHECK has to go before the values it forbids can be written.
ALTER TABLE techdoc.crawl_observation DROP CONSTRAINT IF EXISTS crawl_observation_decision_check;

UPDATE techdoc.crawl_observation SET decision =
    CASE decision
        WHEN 'document'     THEN 'collected'
        WHEN 'non_document' THEN 'excluded'
        WHEN 'unavailable'  THEN 'excluded'
        ELSE decision                          -- 'unknown' already agrees, and so does a re-run
    END
 WHERE decision IN ('document', 'non_document', 'unavailable');

ALTER TABLE techdoc.crawl_observation ADD CONSTRAINT crawl_observation_decision_check
    CHECK (decision IN ('collected', 'excluded', 'unknown'));

-- The run summaries the console reads for "Last result". `excluded` is the sum of the two old
-- counters, and `done` goes because it was only ever a copy of `processed`.
UPDATE techdoc.crawl_run SET summary =
    (summary - 'stored' - 'rejected' - 'unavailable' - 'done')
    || jsonb_build_object(
        'collected', coalesce(summary -> 'stored', '0'::jsonb),
        'excluded',  to_jsonb(coalesce((summary ->> 'rejected')::int, 0)
                            + coalesce((summary ->> 'unavailable')::int, 0)))
 WHERE summary ?| array['stored', 'rejected', 'unavailable', 'done'];

COMMIT;
