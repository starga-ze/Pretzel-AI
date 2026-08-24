"""benchmark.dataset / benchmark.row — uploaded benchmark sets and their prompts.

An upload creates a set; it never edits one. A result recorded against a prompt id only means
something next to the set that id came from, so sets accumulate and are removed deliberately
rather than overwritten. Re-uploading identical bytes is recognised by digest and returns the set
that already holds them instead of making a second copy under a new name.

Parsing is strict about the two fields that carry meaning — a prompt with no id cannot be scored
against, and a row with no prompt is not a row — and lenient about everything else. A benchmark
that came from somewhere other than dataset/ still renders, and whatever fields this schema has no
column for are kept in `extra` so the stored set is not a lossy copy of the uploaded file.
"""

import hashlib
import json
import logging
import re

import psycopg
from psycopg.types.json import Jsonb

from src.crawler.store import connect  # noqa: F401  (re-exported: one answer to "which database")

log = logging.getLogger("pretzel-ai.benchmark.store")

# Columns of benchmark.row that come from the file, in insert order. `prompt_id` is the file's
# "id"; the rename is deliberate — `id` on a child table reads like its own key.
ROW_COLUMNS = ("row_no", "prompt_id", "category", "category_ko", "category_en", "verdict",
               "expected", "scan_target", "language", "technique", "expected_labels",
               "severity", "origin", "prompt", "extra")

# The file's field names, mapped to the column that holds them. Anything outside this map lands in
# `extra` rather than being dropped.
FIELD_TO_COLUMN = {
    "id": "prompt_id", "category": "category", "category_ko": "category_ko",
    "category_en": "category_en", "verdict": "verdict", "expected": "expected",
    "scan_target": "scan_target", "language": "language", "technique": "technique",
    "expected_labels": "expected_labels", "severity": "severity", "origin": "origin",
    "prompt": "prompt",
}

TEXT_COLUMNS = ("category", "category_ko", "category_en", "verdict", "expected",
                "scan_target", "language", "technique", "severity", "origin")

# What the console may filter a listing by. Interpolated into the WHERE clause, so the legal set is
# closed here; the values themselves stay parameterised.
FILTERS = ("category", "verdict", "language", "technique", "scan_target", "severity")

MAX_LIMIT = 500
DEFAULT_LIMIT = 50

# Upload guards. A benchmark set is ~1,500 rows and ~1 MB; these are an order of magnitude clear of
# that, and exist so a wrong file is rejected with a sentence rather than by running the box out of
# memory.
MAX_UPLOAD_BYTES = 32 * 1024 * 1024
MAX_ROWS = 100_000
MAX_PROMPT_CHARS = 200_000
MAX_ERRORS_REPORTED = 20

_NAME_TRIM = re.compile(r"\s+")


class UploadError(Exception):
    """The file cannot become a set. `problems` is a list of human-readable lines, already capped.

    Raised for a file that is malformed, not for one that merely has fields this schema does not
    know about — those are kept in `extra` and are not a problem.
    """

    def __init__(self, message, problems=None):
        super().__init__(message)
        self.message = message
        self.problems = problems or []


class DuplicateUpload(Exception):
    """These exact bytes are already stored. Carries the set that holds them, so the caller can
    point at it rather than reporting a failure for something that already succeeded."""

    def __init__(self, dataset):
        super().__init__(f"already uploaded as dataset {dataset['id']}")
        self.dataset = dataset


# ── Parsing ─────────────────────────────────────────────────────────────────────

def _as_text(value):
    """Scalars become their string form; anything structural is refused by the caller. Booleans and
    numbers appear in real benchmark files and rendering them as text is what the console wants."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return value if isinstance(value, str) else None


def _as_labels(value):
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple)):
        out = []
        for item in value:
            text = _as_text(item)
            if text is None:
                return None
            out.append(text)
        return out
    return None


def parse(blob):
    """bytes -> list of row dicts ready for insert. Raises UploadError with per-line detail.

    Blank lines are skipped rather than counted, so a file that ends with a newline — every file
    written by a normal tool — does not report a phantom empty row. `row_no` therefore numbers the
    rows that exist, not the lines of the file.
    """
    if not blob:
        raise UploadError("The file is empty.")
    if len(blob) > MAX_UPLOAD_BYTES:
        raise UploadError(
            f"The file is {len(blob) / 1048576:.1f} MB; the limit is "
            f"{MAX_UPLOAD_BYTES // 1048576} MB.")

    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UploadError(f"The file is not UTF-8 text (byte {exc.start}).") from exc

    rows, problems, seen_ids = [], [], {}

    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        if len(rows) >= MAX_ROWS:
            problems.append(f"line {line_no}: more than {MAX_ROWS:,} rows; the rest was not read")
            break

        try:
            doc = json.loads(line)
        except json.JSONDecodeError as exc:
            problems.append(f"line {line_no}: not valid JSON ({exc.msg})")
            continue
        if not isinstance(doc, dict):
            problems.append(f"line {line_no}: expected a JSON object, found {type(doc).__name__}")
            continue

        prompt_id = _as_text(doc.get("id"))
        prompt = _as_text(doc.get("prompt"))
        if not prompt_id:
            problems.append(f"line {line_no}: no \"id\"")
            continue
        if not prompt:
            problems.append(f"line {line_no}: no \"prompt\"")
            continue
        if len(prompt) > MAX_PROMPT_CHARS:
            problems.append(f"line {line_no}: prompt is longer than {MAX_PROMPT_CHARS:,} characters")
            continue
        if prompt_id in seen_ids:
            problems.append(
                f"line {line_no}: id {prompt_id!r} already used on line {seen_ids[prompt_id]}")
            continue

        labels = _as_labels(doc.get("expected_labels"))
        if labels is None:
            problems.append(f"line {line_no}: \"expected_labels\" is not a list of strings")
            continue

        row = {"row_no": len(rows) + 1, "prompt_id": prompt_id, "prompt": prompt,
               "expected_labels": labels}
        bad_field = None
        for column in TEXT_COLUMNS:
            field = next(f for f, c in FIELD_TO_COLUMN.items() if c == column)
            value = _as_text(doc.get(field))
            if value is None:
                bad_field = field
                break
            row[column] = value
        if bad_field:
            problems.append(f"line {line_no}: \"{bad_field}\" is not a scalar value")
            continue

        row["extra"] = Jsonb({k: v for k, v in doc.items() if k not in FIELD_TO_COLUMN})
        seen_ids[prompt_id] = line_no
        rows.append(row)

    if problems:
        shown = problems[:MAX_ERRORS_REPORTED]
        if len(problems) > MAX_ERRORS_REPORTED:
            shown.append(f"…and {len(problems) - MAX_ERRORS_REPORTED} more")
        raise UploadError(f"{len(problems)} line(s) could not be read.", shown)
    if not rows:
        raise UploadError("The file holds no rows.")
    return rows


# ── Datasets ────────────────────────────────────────────────────────────────────

def _clean_name(name, filename):
    name = _NAME_TRIM.sub(" ", (name or "").strip())
    if not name:
        name = _NAME_TRIM.sub(" ", (filename or "").strip()) or "benchmark.jsonl"
    return name[:200]


def _dataset_row(record):
    return {"id": record[0], "name": record[1], "filename": record[2],
            "content_sha": record[3].hex() if record[3] else "",
            "byte_size": record[4], "row_count": record[5], "note": record[6],
            "uploaded_by": record[7],
            "uploaded_at": record[8].isoformat() if record[8] else ""}


_DATASET_SELECT = ("SELECT id, name, filename, content_sha, byte_size, row_count, note, "
                   "uploaded_by, uploaded_at FROM benchmark.dataset")


def create(conn, blob, filename, name="", note="", uploaded_by=""):
    """Store one uploaded file as a new set.

    The parse happens before the transaction opens: a malformed file should cost nothing and hold
    no locks. The insert of the header and of every row is one transaction, so a set is never
    visible with some of its prompts missing.
    """
    rows = parse(blob)
    digest = hashlib.sha256(blob).digest()

    existing = by_digest(conn, digest)
    if existing:
        raise DuplicateUpload(existing)

    name = _clean_name(name, filename)
    filename = (filename or name)[:200]

    try:
        with conn.transaction():
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO benchmark.dataset "
                    "  (name, filename, content_sha, byte_size, row_count, note, uploaded_by) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id",
                    (name, filename, digest, len(blob), len(rows), note[:2000], uploaded_by[:100]))
                dataset_id = cur.fetchone()[0]

                cur.executemany(
                    "INSERT INTO benchmark.row (dataset_id, " + ", ".join(ROW_COLUMNS) + ") "
                    "VALUES (%s, " + ", ".join(["%s"] * len(ROW_COLUMNS)) + ")",
                    [tuple([dataset_id] + [r.get(c) for c in ROW_COLUMNS]) for r in rows])
    except psycopg.errors.UniqueViolation as exc:
        # Two uploads of the same bytes racing each other: the loser reports the winner's set
        # rather than an error, which is the same answer it would have got a moment earlier.
        existing = by_digest(conn, digest)
        if existing:
            raise DuplicateUpload(existing) from exc
        raise

    log.info("benchmark set %d stored: %s, %d rows, %d bytes",
             dataset_id, name, len(rows), len(blob))
    return dataset(conn, dataset_id)


def by_digest(conn, digest):
    with conn.cursor() as cur:
        cur.execute(_DATASET_SELECT + " WHERE content_sha = %s", (digest,))
        got = cur.fetchone()
    return _dataset_row(got) if got else None


def dataset(conn, dataset_id):
    with conn.cursor() as cur:
        cur.execute(_DATASET_SELECT + " WHERE id = %s", (dataset_id,))
        got = cur.fetchone()
    return _dataset_row(got) if got else None


def datasets(conn, search=""):
    """Every stored set, newest first. The list is short by nature — one per uploaded file — so it
    is returned whole rather than paged."""
    where, params = "", []
    if search:
        where = " WHERE name ILIKE %s OR filename ILIKE %s"
        params = [f"%{search}%", f"%{search}%"]
    with conn.cursor() as cur:
        cur.execute(_DATASET_SELECT + where + " ORDER BY uploaded_at DESC, id DESC", params)
        return [_dataset_row(r) for r in cur.fetchall()]


def delete(conn, dataset_id):
    """Remove a set and its prompts. Returns whether anything was there to remove, so a caller can
    tell a delete from a no-op instead of reporting success for a set that never existed."""
    with conn.transaction():
        with conn.cursor() as cur:
            cur.execute("DELETE FROM benchmark.dataset WHERE id = %s", (dataset_id,))
            gone = cur.rowcount
    if gone:
        log.info("benchmark set %d deleted", dataset_id)
    return bool(gone)


def rename(conn, dataset_id, name, note=None):
    """Editing the label is not editing the set — the prompts and the digest are untouched, so a
    result recorded against this set still means what it meant."""
    fields, params = ["name = %s"], [_clean_name(name, "")]
    if note is not None:
        fields.append("note = %s")
        params.append(note[:2000])
    params.append(dataset_id)
    with conn.transaction():
        with conn.cursor() as cur:
            cur.execute(f"UPDATE benchmark.dataset SET {', '.join(fields)} WHERE id = %s", params)
            changed = cur.rowcount
    return dataset(conn, dataset_id) if changed else None


# ── Reading one set ─────────────────────────────────────────────────────────────

def summary(conn, dataset_id):
    """The composition of one set: the header band's counts, and the technique list its filter
    dropdown is built from. A detection rate is not interpretable without this, which is why it is
    computed from the rows rather than trusted from the file's own header."""
    head = dataset(conn, dataset_id)
    if not head:
        return None
    out = dict(head)
    out.update({"by_category": [], "by_verdict": [], "by_language": [], "techniques": []})
    with conn.cursor() as cur:
        for field in ("category", "verdict", "language"):
            cur.execute(
                f"SELECT {field}, count(*) FROM benchmark.row WHERE dataset_id = %s "
                f"GROUP BY {field} ORDER BY {field}", (dataset_id,))
            out["by_" + field] = [{"key": k or "—", "count": n} for k, n in cur.fetchall()]
        cur.execute(
            "SELECT category, technique, count(*) FROM benchmark.row WHERE dataset_id = %s "
            "GROUP BY category, technique ORDER BY category, technique", (dataset_id,))
        out["techniques"] = [{"category": c, "technique": t, "count": n}
                             for c, t, n in cur.fetchall() if t]
    return out


def export_jsonl(conn, dataset_id):
    """The whole set as the .jsonl it arrived as: one JSON object per line, in the file's order.

    Rebuilt from the columns rather than kept as a stored blob — a second copy of a file that is
    already fully represented in `row` is one more thing that can drift from it.

    The export is normalised, not byte-identical: every known field is written, in the order the
    generator writes them, and fields the schema had no column for are merged back from `extra`
    afterwards. A column cannot tell "the file had no severity" from "the file had an empty one" —
    both are '' — so omitting the empties would drop a field that was really there, and writing
    them all is the choice that never loses one. For a file from dataset/ the result is the input
    back exactly; for a file from elsewhere it gains the fields it did not carry, empty.
    """
    head = dataset(conn, dataset_id)
    if not head:
        return None

    ordered = ("id", "category", "category_ko", "category_en", "verdict", "expected",
               "scan_target", "language", "technique", "expected_labels", "severity",
               "origin", "prompt")
    lines = []
    with conn.cursor(name=f"bench_export_{dataset_id}") as cur:
        # A server-side cursor: a set is thousands of rows with a prompt on each, and materialising
        # all of them in one client-side list is the kind of thing that is fine until it is not.
        cur.itersize = 500
        cur.execute(
            "SELECT prompt_id, category, category_ko, category_en, verdict, expected, "
            "       scan_target, language, technique, expected_labels, severity, origin, "
            "       prompt, extra "
            "FROM benchmark.row WHERE dataset_id = %s ORDER BY row_no", (dataset_id,))
        for record in cur:
            values = dict(zip(ordered, record[:-1]))
            extra = record[-1] or {}
            doc = {key: values[key] for key in ordered}
            for key, value in extra.items():
                doc.setdefault(key, value)
            lines.append(json.dumps(doc, ensure_ascii=False))

    content = ("\n".join(lines) + "\n").encode("utf-8") if lines else b""
    return {"content": content, "filename": head["filename"] or f"{head['name']}.jsonl",
            "row_count": len(lines)}


# The two orders a listing can be in. Closed, because the value is interpolated into ORDER BY;
# `row_no` is the default because it is the file's own order and the only one that is stable when
# two prompts share everything else.
ORDERS = {"row_no": "row_no", "prompt_id": "prompt_id"}


def scope_rows(conn, dataset_id, filters=None, search=""):
    """Every row a filter matches, unpaged — what a run executes against.

    Separate from rows() rather than a large limit on it. rows() pages a table and caps at
    MAX_LIMIT for the reason a table should: nothing renders 1,500 lines at once. A run is the
    other job entirely, and borrowing the table's cap silently ran 500 of a 1,500-prompt set and
    reported it as the whole thing.
    """
    where, params = ["dataset_id = %s"], [dataset_id]
    for key, value in (filters or {}).items():
        if key in FILTERS and value:
            where.append(f"{key} = %s")
            params.append(value)
    if search:
        where.append("(prompt ILIKE %s OR prompt_id ILIKE %s)")
        params += [f"%{search}%", f"%{search}%"]

    columns = [c for c in ROW_COLUMNS if c != "extra"]
    with conn.cursor(name=f"bench_scope_{dataset_id}") as cur:
        cur.itersize = 500
        cur.execute("SELECT " + ", ".join(columns) + " FROM benchmark.row WHERE "
                    + " AND ".join(where) + " ORDER BY row_no", params)
        return [dict(zip(columns, r)) for r in cur]


def rows(conn, dataset_id, filters=None, search="", offset=0, limit=DEFAULT_LIMIT,
         order_by="row_no", descending=False):
    """One page of a set, in the file's own order.

    Unknown filter keys are dropped rather than rejected: the caller is a URL query string, and a
    stale bookmark should still return the table.
    """
    where, params = ["dataset_id = %s"], [dataset_id]
    for key, value in (filters or {}).items():
        if key in FILTERS and value:
            where.append(f"{key} = %s")
            params.append(value)
    if search:
        # ILIKE over the two columns an operator would look in, not a text index: a set is
        # thousands of rows, and an index here would be maintenance for no measurable gain.
        where.append("(prompt ILIKE %s OR prompt_id ILIKE %s)")
        params += [f"%{search}%", f"%{search}%"]

    clause = " WHERE " + " AND ".join(where)
    limit = max(1, min(int(limit or DEFAULT_LIMIT), MAX_LIMIT))
    offset = max(0, int(offset or 0))

    columns = [c for c in ROW_COLUMNS if c != "extra"]
    with conn.cursor() as cur:
        cur.execute(f"SELECT count(*) FROM benchmark.row{clause}", params)
        total = cur.fetchone()[0]
        # A tie-break on row_no keeps paging stable: ordering by prompt_id alone leaves rows that
        # share one in an order Postgres may change between pages, and a row could then appear on
        # two pages or on none.
        column = ORDERS.get(order_by, "row_no")
        direction = "DESC" if descending else "ASC"
        tie = "" if column == "row_no" else f", row_no {direction}"
        cur.execute(
            "SELECT " + ", ".join(columns) + f", extra FROM benchmark.row{clause} "
            f"ORDER BY {column} {direction}{tie} LIMIT %s OFFSET %s", params + [limit, offset])
        got = []
        for record in cur.fetchall():
            row = dict(zip(columns, record[:-1]))
            row["extra"] = record[-1] or {}
            got.append(row)
    return {"total": total, "offset": offset, "limit": limit, "rows": got}
