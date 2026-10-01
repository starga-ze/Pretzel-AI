# Technical documentation corpus

Refresh discovers candidates from validated sitemap XML, then GETs each candidate and each previously stored URL in scope. HEAD and sitemap absence are not deletion evidence. Four workers share a five-request/second start limit and back off together on server throttling. Redirects are restricted to the documentation host before following them. Downloads, redirect counts and retries are bounded; cancellation stops submission and wakes backoff waits.

DOM adapters extract technical topics and feature notes, remove explicit navigation, and preserve headings, lists, links, tables and command indentation. Unrecognized templates, incomplete responses and image-only topics are `unknown`, not rejected. Product/manual come from both supported URL layouts; version prefers vendor metadata. Short technical notes and small product collections are retained.

## Rollout

1. Stop old crawler workers before replacing the service; old releases do not participate in the new advisory lock.
2. Install the updated `requirements.txt` in the service environment.
3. Back up the knowledge DB, then run `python -m src.crawler migrate`. This applies additive migration `sql/018_corpus_lifecycle.sql` and backfills categories; it does not delete documents. It is safe to repeat. Do not replay historic destructive migrations.
4. Deploy the matching mgmtd binary and web assets alongside pretzel-ai (protobuf fields are additive; versioned browsing requires both sides).
5. Start with **Preview only** in Operation, or `python -m src.crawler crawl --dry-run --yes`. Review the summary and `python -m src.crawler audit RUN_ID` before the first full update.
6. Run an update and inspect retained/unverified counts. An `ok` run means no reported fetch uncertainty; `warning` means its summary needs attention. Neither guarantees coverage of every page the publisher has ever published.

Browser refresh/closing the progress dialog does not cancel the appliance worker. Cancel, mgmtd restart, or transport loss stops it. Earlier committed verified documents remain; reconciliation does not run on cancellation or failure. After a process crash the next worker acquires the PostgreSQL session advisory lock and closes abandoned run records. Database access should use a dedicated service role.

## Reconciliation and recovery

Every attempted URL records run, requested/final URL, HTTP status, decision and reason. No list-complement sweep or product-size deletion is performed. A successful same-scope redirect archives an old alias only after the destination is accepted. A GET 404/410 requires another completed non-preview observation at least 24 hours earlier. Unknown observations break this confirmation chain. Known URLs missing from the sitemap are fetched directly.

Non-documents and confirmed missing URLs become explicit candidates. Cleanup is deferred if sitemap candidates fall more than 30% versus the last healthy run, unknowns exceed the larger of 5 pages or 20% of attempts, proposed removals exceed the larger of 5 documents or 10% of the existing scope, or a product would lose all documents or more than the larger of 3 documents or 25%. These are conservative operational tripwires, not document classifiers. Diagnose repeated warnings using the audit log and improve the adapter; do not lower thresholds merely to silence warnings.

Approved automatic cleanup inserts a full JSON snapshot in `techdoc.document_archive` and removes the active row in the same transaction. Restore explicitly with `python -m src.crawler restore ARCHIVE_ID`; this never overwrites an existing active document. The archive ID can be found with:

```sql
SELECT id, run_id, url, reason, archived_at
FROM techdoc.document_archive
ORDER BY id DESC;
```

Audit records and archives have no automatic expiration, so recovery evidence is not silently discarded. Include them in backup and capacity planning. Embeddings should use `(parser_version, content_sha)` and exclude archived rows. A parser change can change hashes even when vendor prose did not change. Legacy documents show **Awaiting validation** until successfully re-fetched; unknown responses retain their old content and validation state.

## Verification

```sh
python -m unittest discover -s tests -v
```

Database tests run only when `PZ_TEST_DSN` names an isolated database named `corpus_test`; tests replace its `techdoc` schema. Never point them at the appliance knowledge database. They exercise additive migration, locking, scoped refresh, transient errors, absence from sitemap, dry run, missing confirmation, mass-removal deferral, cancellation, archive recovery and pagination.
