"""Active corpus, durable observations and reversible, evidence-based pruning."""
import hashlib
import os
from pathlib import Path

import psycopg
from psycopg.types.json import Jsonb

from src.crawler.extract import PARSER_VERSION, COLLECTED, EXCLUDED, UNKNOWN, REASONS
from src.crawler.sitemap import classify

LOCK_ID = 740120182


def dsn():
    return os.environ.get('PZ_KNOWLEDGE_DSN', '').strip() or (
        'host=127.0.0.1 port=5432 dbname=pretzel_knowledge user=pretzel password=' +
        os.environ.get('PZ_PG_PASSWORD', 'pretzel'))


def connect():
    return psycopg.connect(dsn(), connect_timeout=10, options='-c statement_timeout=30000 -c lock_timeout=5000')


# Applied in order, and each is written to be safe to re-run, so `migrate` is the one command an
# operator needs whatever state the database is in.
MIGRATIONS = ('sql/018_corpus_lifecycle.sql', 'sql/019_outcome_vocabulary.sql',
              'sql/020_rebuild_corpus.sql')


def migrate(conn):
    root = Path(__file__).resolve().parents[2]
    for name in MIGRATIONS:
        conn.execute((root / name).read_text())
        conn.commit()


MIGRATION_NEEDED = 'Corpus migration required: python -m src.crawler migrate'


def require_schema(conn):
    """Refuse to start a run against a database older than the code writing to it.

    Two things are checked, and the second exists because of what happened without it: renaming
    the outcomes left the CHECK on `decision` still spelling them the old way, so a deploy that
    skipped the migration started normally and died on the first page with a constraint violation
    — a message about a CHECK, hundreds of fetches in, for a migration nobody had run. The
    vocabulary is part of the contract, so it is verified with the table's existence.
    """
    if not conn.execute("SELECT to_regclass('techdoc.crawl_observation')").fetchone()[0]:
        raise RuntimeError(MIGRATION_NEEDED)
    rule = conn.execute("""SELECT pg_get_constraintdef(oid) FROM pg_constraint
         WHERE conrelid='techdoc.crawl_observation'::regclass
           AND conname='crawl_observation_decision_check'""").fetchone()
    if not rule or not all(word in rule[0] for word in (COLLECTED, EXCLUDED, UNKNOWN)):
        raise RuntimeError(MIGRATION_NEEDED)


def claim(conn, scope='', dry_run=False):
    require_schema(conn)
    if not conn.execute('SELECT pg_try_advisory_lock(%s)', (LOCK_ID,)).fetchone()[0]:
        raise RuntimeError('A corpus update is already running')
    try:
        # Holding the session lock proves that no compatible crawler owns these old runs.
        conn.execute("UPDATE techdoc.crawl_run SET status='failed', finished_at=now(), error='worker interrupted' WHERE status='running'")
        row = conn.execute('INSERT INTO techdoc.crawl_run(scope, dry_run) VALUES (%s,%s) RETURNING id', (scope or '', dry_run)).fetchone()
        conn.commit()
        return row[0]
    except BaseException:
        conn.rollback()
        release(conn)
        raise


def release(conn):
    conn.execute('SELECT pg_advisory_unlock(%s)', (LOCK_ID,))
    conn.commit()


def heartbeat(conn, run_id, counts):
    conn.execute('UPDATE techdoc.crawl_run SET heartbeat_at=now(), summary=%s WHERE id=%s', (Jsonb(counts), run_id))
    conn.commit()


def finish_run(conn, run_id, status_text, counts, error=None):
    conn.execute('''UPDATE techdoc.crawl_run SET finished_at=now(), heartbeat_at=now(), status=%s,
        listed=%s, stored=%s, rejected=%s, summary=%s, error=%s WHERE id=%s''',
        (status_text, counts.get('listed', 0), counts.get('stored', 0), counts.get('rejected', 0), Jsonb(counts), error, run_id))
    conn.commit()


def running_run(conn):
    # Informational only. The authoritative cross-process gate is claim's advisory lock.
    return conn.execute("SELECT id, started_at FROM techdoc.crawl_run WHERE status='running' ORDER BY id DESC LIMIT 1").fetchone()


def observe(cur, run_id, result):
    cur.execute('''INSERT INTO techdoc.crawl_observation(run_id,url,final_url,decision,reason,http_status,detail)
        VALUES (%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (run_id,url) DO UPDATE SET
        final_url=EXCLUDED.final_url, decision=EXCLUDED.decision, reason=EXCLUDED.reason,
        http_status=EXCLUDED.http_status, detail=EXCLUDED.detail''',
        (run_id, result.url, result.final_url or result.url, result.decision, result.reason, result.status, result.error[:1000]))


def sha256(text):
    return hashlib.sha256(text.encode('utf-8')).digest()


def put(cur, run_id, url, title, text, lastmod, metadata=None):
    """Write one document, stamped with the run that collected it.

    `run_id` is what makes a refresh a rebuild: rows carry the run they came from, so the rows a
    finished run did not write can be dropped in one statement (see retain_only) instead of being
    reasoned about one at a time.
    """
    parts = classify(url)
    metadata = metadata or {}
    version = metadata.get('os version') or (parts['version'] or '').replace('-', '.')
    cur.execute('''INSERT INTO techdoc.document
        (url,title,text,content_sha,char_count,lastmod,fetched_at,product,docset,version,information_type,parser_version,run_id)
        VALUES (%s,%s,%s,%s,%s,%s,now(),%s,%s,%s,%s,%s,%s)
        ON CONFLICT (url) DO UPDATE SET title=EXCLUDED.title,text=EXCLUDED.text,
        content_sha=EXCLUDED.content_sha,char_count=EXCLUDED.char_count,lastmod=EXCLUDED.lastmod,
        fetched_at=now(),product=EXCLUDED.product,docset=EXCLUDED.docset,version=EXCLUDED.version,
        information_type=EXCLUDED.information_type,parser_version=EXCLUDED.parser_version,
        run_id=EXCLUDED.run_id''',
        (url,title,text,sha256(text),len(text),lastmod,parts['product'],parts['docset'],version,
         metadata.get('information type', ''),PARSER_VERSION,run_id))


def retain_only(cur, run_id, scope=None):
    """Drop every document this run did not collect. → rows removed.

    The swap at the end of a rebuild. One statement, inside the run's transaction, so the table
    never holds half of one corpus and half of another; and only at the end, so a crawl that dies
    at page 9,000 leaves the previous corpus exactly as it found it.

    A scoped run may only empty its own product. Without that clause, refreshing one product would
    delete every other one — the rows are not the run's, but they were never its business either.
    """
    cur.execute('DELETE FROM techdoc.document WHERE run_id <> %s AND (%s = \'\' OR product = %s)',
                (run_id, scope or '', scope or ''))
    return cur.rowcount



def previous_listed(conn, scope):
    """How many pages the last healthy run of this scope was offered. Feeds the coverage guard."""
    row = conn.execute("SELECT listed FROM techdoc.crawl_run WHERE scope=%s AND NOT dry_run AND status='ok' ORDER BY id DESC LIMIT 1", (scope or '',)).fetchone()
    return row[0] if row else 0




def status(conn):
    require_schema(conn)
    count,bodies,chars = conn.execute('SELECT count(*),count(DISTINCT content_sha),coalesce(sum(char_count),0) FROM techdoc.document').fetchone()
    row = conn.execute('SELECT id,coalesce(finished_at,started_at),status,summary,error FROM techdoc.crawl_run ORDER BY id DESC LIMIT 1').fetchone()
    return dict(documents=count,bodies=bodies,chars=int(chars),last_run_id=row[0] if row else 0,
        last_run_at=row[1].isoformat() if row else '',last_run_status=row[2] if row else '',
        last_run_summary=__import__('json').dumps(row[3]) if row else '',last_run_error=(row[4] or '') if row else '')


def product_tree(conn):
    return [dict(product=r[0],docset=r[1],version=r[2],documents=r[3],bodies=r[4],chars=int(r[5]))
        for r in conn.execute('''SELECT product,docset,version,count(*),count(DISTINCT content_sha),sum(char_count)
            FROM techdoc.document GROUP BY product,docset,version ORDER BY product,docset,version DESC''')]


def exceptions(conn, run_id=0, reason='', offset=0, limit=100):
    """→ (rows, total, tally, run_id). Every URL a run looked at and did not collect.

    An exception is any decision other than `document`. The three that remain say different
    things and are deliberately not merged here — `non_document` is a verdict about the page,
    `unavailable` is the publisher having removed it, and `unknown` is this crawler failing to
    read it. Only the last is a defect on our side, and telling them apart is the whole reason
    an operator opens this list.

    `run_id=0` reads the newest run, which is what a console asking "what just happened" means.
    The tally counts the whole run rather than the page being returned, so the reasons can be
    offered as filters without a second round trip.

    Newest first, and that is load-bearing while a run is still going. A crawl walks its worklist
    in URL order, so ordering this the same way pinned the page to the alphabetical head of the
    run: once the exceptions passed the limit, the rows froze on the `a`s and nothing found
    afterwards could ever enter the window. Most recent first means the page always shows what
    just happened, which is the only reason to have it open mid-run.
    """
    run_id = run_id or (conn.execute('SELECT max(id) FROM techdoc.crawl_run').fetchone()[0] or 0)
    counted = {(r[0], r[1]): r[2] for r in conn.execute(
        """SELECT decision, reason, count(*) FROM techdoc.crawl_observation
            WHERE run_id=%s AND decision<>%s GROUP BY 1,2""", (run_id, COLLECTED))}
    # The whole vocabulary, not only what this run hit, so a reason at zero reads as "checked, and
    # it did not happen" rather than disappearing. Anything the database holds that the catalogue
    # does not know is appended, so a reason added in code shows up before it is catalogued.
    tally = [dict(decision=bucket, reason=name, count=counted.pop((bucket, name), 0))
             for name, bucket in REASONS.items() if bucket != COLLECTED]
    tally += [dict(decision=d, reason=r, count=n) for (d, r), n in counted.items()]
    tally.sort(key=lambda row: (-row['count'], row['reason']))
    rows = conn.execute(
        """SELECT url, final_url, decision, reason, http_status, detail, count(*) OVER ()
             FROM techdoc.crawl_observation
            WHERE run_id=%s AND decision<>%s AND (%s='' OR reason=%s)
         ORDER BY observed_at DESC, url LIMIT %s OFFSET %s""",
        (run_id, COLLECTED, reason, reason, min(max(limit or 100, 1), 500), max(offset, 0))).fetchall()
    items = [dict(url=r[0], final_url=r[1], decision=r[2], reason=r[3],
                  http_status=r[4], detail=r[5]) for r in rows]
    return items, (rows[0][6] if rows else 0), tally, run_id


def _literal_like(query):
    return '%' + query.replace('\\','\\\\').replace('%','\\%').replace('_','\\_') + '%'


def documents(conn, product='', docset='', query='', version=None, offset=0, limit=100):
    limit = min(max(limit or 100,1),200)
    offset = max(offset,0)
    pattern = _literal_like(query.strip())
    rows = conn.execute('''SELECT url,title,char_count,lastmod,version,information_type,fetched_at,parser_version,count(*) OVER ()
        FROM techdoc.document WHERE
        ((%s<>'' AND (url ILIKE %s OR title ILIKE %s)) OR
         (%s='' AND product=%s AND docset=%s AND (%s OR version=%s)))
        ORDER BY url LIMIT %s OFFSET %s''',
        (query,pattern,pattern,query,product,docset,version is None,version or '',limit,offset)).fetchall()
    items = [dict(url=r[0],title=r[1],char_count=r[2],lastmod=r[3].isoformat() if r[3] else '',
        version=r[4],information_type=r[5],fetched_at=r[6].isoformat(),validated=bool(r[7])) for r in rows]
    return items, rows[0][8] if rows else 0
