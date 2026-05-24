"""Persistent state for the bridge: cursor, conversations, audit log.

Lives at ``~/.claude-imessage-bridge/state.db`` (SQLite). The directory and
the DB file are created with mode 0o700/0o600 so other local users can't
read it — see threat model N8 (state.db unprotected).
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

logger = logging.getLogger(__name__)

DEFAULT_STATE_DIR = Path.home() / ".claude-imessage-bridge"


# Schema version. Bump when a migration is added, and register a
# ``_ensure_*_columns`` step in ``_apply_schema``. The bridge refuses to
# start if the on-disk DB has a HIGHER version than this code understands
# (forward incompatibility — operator probably downgraded without thinking).
#
# History:
#   v0 — pre-Phase-D state.db (no user_version stamp).
#   v1 — Phase D: added chatdb_rowid, cost_cents, error_category to
#        audit_log + idx_audit_chatdb_rowid index.
#   v2 — Live-test fix: retroactively add last_options_json + last_options_at
#        to conversations. Phase C introduced those columns but the
#        original migration was CREATE TABLE IF NOT EXISTS, a no-op for
#        any state.db that already existed from Phase A/B. Observed live
#        on a state.db that had survived the A→C transition.
#   v3 — Session 2 (trust modes): add pending_intent_json + pending_intent_at
#        to conversations for the natural-language intent confirmation
#        flow (60s TTL on a pending confirmation per handle).
SCHEMA_VERSION: int = 3


# v0 schema (what the project shipped pre-Phase-D). New installs leapfrog
# straight to v1 via the migration step.
_SCHEMA_V0 = """
CREATE TABLE IF NOT EXISTS cursor (
    name TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS conversations (
    handle TEXT PRIMARY KEY,
    current_session_id TEXT,
    last_options_json TEXT,   -- numbered list from last /sessions or /use
    last_options_at TEXT,     -- ts the options were captured (expiry check)
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    rowid INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    handle_redacted TEXT NOT NULL,
    direction TEXT NOT NULL,      -- 'in' or 'out'
    kind TEXT NOT NULL,           -- 'command' / 'text' / 'reply' / 'drop'
    detail TEXT,                  -- never raw body unless debug mode
    reply_bytes INTEGER
);

CREATE TABLE IF NOT EXISTS reply_counter (
    -- per-(handle, minute-bucket) reply counts for rate limiting
    bucket TEXT NOT NULL,
    handle TEXT NOT NULL,
    n INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, handle)
);

CREATE TABLE IF NOT EXISTS daily_cost (
    -- spend by UTC date in cents (integer math, no float comparisons)
    date_utc TEXT PRIMARY KEY,
    cents INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_reply_counter_bucket ON reply_counter(bucket);
"""


class SchemaTooNew(RuntimeError):
    """state.db has a higher user_version than this code understands."""


class SchemaMigrationMissing(RuntimeError):
    """state.db is on a lower version than this code, and no registered
    migration step knows how to advance it.

    Refusing to start is the right default: silently stamping forward
    would let newer code run against older data and hide real bugs.
    """


def _ensure_audit_log_v1_columns(conn: sqlite3.Connection) -> None:
    """v0 → v1. Add structured columns to ``audit_log``:

      chatdb_rowid    — the message.ROWID the row was triggered by.
      cost_cents      — claude spend on this row, integer cents.
      error_category  — one of timeout/exec_error/json_parse/claude_error/NULL.

    Idempotent: only ALTERs columns that don't already exist (covers the
    partial-migration crash path).
    """
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(audit_log)")}
    if "chatdb_rowid" not in existing:
        conn.execute("ALTER TABLE audit_log ADD COLUMN chatdb_rowid INTEGER")
    if "cost_cents" not in existing:
        conn.execute("ALTER TABLE audit_log ADD COLUMN cost_cents INTEGER")
    if "error_category" not in existing:
        conn.execute("ALTER TABLE audit_log ADD COLUMN error_category TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS " "idx_audit_chatdb_rowid ON audit_log(chatdb_rowid)")


def _ensure_conversations_v2_columns(conn: sqlite3.Connection) -> None:
    """v1 → v2. Retroactively add ``last_options_json`` and
    ``last_options_at`` to ``conversations``.

    Phase C added these columns to the schema, but the original migration
    relied on ``CREATE TABLE IF NOT EXISTS`` — which is a no-op when the
    table already exists from Phase A/B. A state.db that survived the
    A→C transition without ever being reset ends up missing the columns,
    and ``/sessions`` / ``/use`` crash with ``no such column:
    last_options_at`` when they try to stash the numbered options.

    Idempotent: only ALTERs columns that don't already exist.
    """
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(conversations)")}
    if "last_options_json" not in existing:
        conn.execute("ALTER TABLE conversations ADD COLUMN last_options_json TEXT")
    if "last_options_at" not in existing:
        conn.execute("ALTER TABLE conversations ADD COLUMN last_options_at TEXT")


def _ensure_conversations_v3_columns(conn: sqlite3.Connection) -> None:
    """v2 → v3. Add ``pending_intent_json`` and ``pending_intent_at`` to
    ``conversations`` for the NL-intent confirmation flow.

    The bridge stores a pending confirmation per handle (60s TTL): when
    the user says "kill the bridge" the bridge stashes the intended
    command + timestamp here, replies with a paraphrase, and waits for
    "yes"/"no". The columns hold the JSON-serialized command spec and
    the ISO timestamp the confirmation was offered.

    Idempotent — only ALTERs columns that don't already exist.
    """
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(conversations)")}
    if "pending_intent_json" not in existing:
        conn.execute("ALTER TABLE conversations ADD COLUMN pending_intent_json TEXT")
    if "pending_intent_at" not in existing:
        conn.execute("ALTER TABLE conversations ADD COLUMN pending_intent_at TEXT")


def _apply_schema(conn: sqlite3.Connection) -> None:
    """Apply schema migrations forward to ``SCHEMA_VERSION``.

    Uses SQLite's ``PRAGMA user_version`` as the migration ledger so we
    don't need a separate migrations table. The whole forward chain runs
    in a single transaction so a crash mid-migration doesn't leave the
    DB in an intermediate state.
    """
    current = int(conn.execute("PRAGMA user_version").fetchone()[0])
    if current > SCHEMA_VERSION:
        raise SchemaTooNew(
            f"state.db has user_version={current}, but this code only knows "
            f"how to handle up to {SCHEMA_VERSION}. Did you downgrade? "
            "Remove the DB to reset, or upgrade the daemon."
        )
    if current == SCHEMA_VERSION:
        return

    with conn:
        # Always run the base ``CREATE TABLE IF NOT EXISTS`` script — it's
        # a no-op for existing tables and creates anything that's missing.
        conn.executescript(_SCHEMA_V0)

        # Forward-chain registered migrations. ``current`` is incremented
        # as each step lands so the chain naturally fires only the
        # remaining steps.
        if current < 1:
            _ensure_audit_log_v1_columns(conn)
            current = 1
        if current < 2:
            _ensure_conversations_v2_columns(conn)
            current = 2
        if current < 3:
            _ensure_conversations_v3_columns(conn)
            current = 3

        # Any gap between the last registered step and SCHEMA_VERSION
        # means a maintainer bumped the version without adding a step.
        # Refuse rather than silently stamp.
        if current != SCHEMA_VERSION:
            raise SchemaMigrationMissing(
                f"state.db user_version stalled at {current} while "
                f"SCHEMA_VERSION={SCHEMA_VERSION}. A migration step for "
                f"v{current}→v{current+1} is not registered in "
                "_apply_schema. Either add the step, pull a newer build, "
                "or reset state.db deliberately (see docs/RECOVERY.md)."
            )

        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")


def _secure_open_db(path: Path) -> sqlite3.Connection:
    """Open or create state.db with 0o600 perms.

    If the file doesn't exist, create it and immediately chmod. If it exists
    but has loose perms, tighten them (warn the user).
    """
    new_file = not path.exists()
    conn = sqlite3.connect(str(path), timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        if new_file:
            os.chmod(path, 0o600)
        else:
            current_mode = path.stat().st_mode & 0o777
            if current_mode & 0o077:
                logger.warning(
                    "state.db at %s had mode %o; tightening to 0600",
                    path,
                    current_mode,
                )
                os.chmod(path, 0o600)
    except OSError as e:
        logger.warning("Could not chmod state.db: %s", e)
    return conn


def init_state_dir(state_dir: Path = DEFAULT_STATE_DIR) -> Path:
    """Create the state directory with restrictive perms and init schema.

    The sandbox + empty-mcp.json provisioning moved into ``claude_runner``
    as per-call tempdirs — see ``claude_runner.run_claude`` docstring. This
    closes both the symlink-write attack surface on a persistent
    empty-mcp.json and the sandbox-dir tamper window between invocations.

    Returns the state.db Path.
    """
    state_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(state_dir, 0o700)
    except OSError as e:
        logger.warning("Could not chmod state dir: %s", e)

    db_path = state_dir / "state.db"
    conn = _secure_open_db(db_path)
    try:
        _apply_schema(conn)
    finally:
        conn.close()
    return db_path


@contextmanager
def connection(state_dir: Path = DEFAULT_STATE_DIR) -> Iterator[sqlite3.Connection]:
    """Context-managed connection that auto-commits on success."""
    db_path = state_dir / "state.db"
    if not db_path.exists():
        init_state_dir(state_dir)
    conn = _secure_open_db(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_cursor(name: str, default: int = 0, *, state_dir: Path = DEFAULT_STATE_DIR) -> int:
    with connection(state_dir) as conn:
        row = conn.execute("SELECT value FROM cursor WHERE name = ?", (name,)).fetchone()
        return int(row["value"]) if row else default


class CursorRegression(RuntimeError):
    """Raised when set_cursor would move a cursor backward without an override."""


def set_cursor(
    name: str,
    value: int,
    *,
    state_dir: Path = DEFAULT_STATE_DIR,
    allow_regression: bool = False,
) -> None:
    """Set a cursor value.

    By default refuses to move a cursor strictly backward — protects against
    a restored backup of state.db replaying messages and against accidental
    overwrites. Use ``allow_regression=True`` for explicit ``--reset-cursor``
    operator commands. The regression attempt is logged loudly either way.
    """
    new_value = int(value)
    with connection(state_dir) as conn:
        row = conn.execute("SELECT value FROM cursor WHERE name = ?", (name,)).fetchone()
        if row is not None:
            current = int(row["value"])
            if new_value < current:
                logger.warning(
                    "cursor %s regression: current=%d new=%d allow_regression=%s",
                    name,
                    current,
                    new_value,
                    allow_regression,
                )
                if not allow_regression:
                    raise CursorRegression(
                        f"cursor {name!r}: refusing to move from {current} "
                        f"to {new_value}; pass allow_regression=True to override"
                    )
        conn.execute(
            "INSERT INTO cursor (name, value) VALUES (?, ?) "
            "ON CONFLICT(name) DO UPDATE SET value = excluded.value",
            (name, new_value),
        )


def get_current_session(handle: str, *, state_dir: Path = DEFAULT_STATE_DIR) -> Optional[str]:
    with connection(state_dir) as conn:
        row = conn.execute(
            "SELECT current_session_id FROM conversations WHERE handle = ?",
            (handle,),
        ).fetchone()
        return row["current_session_id"] if row else None


def set_current_session(
    handle: str, session_id: Optional[str], *, state_dir: Path = DEFAULT_STATE_DIR
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with connection(state_dir) as conn:
        conn.execute(
            "INSERT INTO conversations (handle, current_session_id, updated_at) "
            "VALUES (?, ?, ?) "
            "ON CONFLICT(handle) DO UPDATE SET "
            "current_session_id = excluded.current_session_id, "
            "updated_at = excluded.updated_at",
            (handle, session_id, now),
        )


def set_last_options(handle: str, options: list, *, state_dir: Path = DEFAULT_STATE_DIR) -> None:
    """Stash the numbered options shown to the user (for /pick N).

    Each option is a dict: ``{"id": session_id, "snippet": str}``. The
    list survives across messages until the next /sessions or /use
    overwrites it (or it ages out — see LAST_OPTIONS_TTL_SECONDS).
    """
    now = datetime.now(timezone.utc).isoformat()
    payload = json.dumps(options) if options else None
    with connection(state_dir) as conn:
        conn.execute(
            "INSERT INTO conversations "
            "  (handle, last_options_json, last_options_at, updated_at) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(handle) DO UPDATE SET "
            "  last_options_json = excluded.last_options_json, "
            "  last_options_at = excluded.last_options_at, "
            "  updated_at = excluded.updated_at",
            (handle, payload, now, now),
        )


LAST_OPTIONS_TTL_SECONDS = 30 * 60  # 30 min — stale picks aren't honored

# Pending NL-intent confirmation TTL. Was 60s — too short for phone-paced
# messaging. Live test on 2026-05-15: Sam took >60s to reply "Yes" to a
# permission-relay prompt; pending expired; "Yes" was then processed as a
# fresh message, claude resumed the session and asked clarifying questions
# which iCloud echoed back as inbound, kicking off a feedback loop.
# 15min is generous enough for "I'll come back to this after lunch" without
# being so long that a stale confirmation leaks into an unrelated topic.
PENDING_INTENT_TTL_SECONDS = 60 * 15


def get_last_options(handle: str, *, state_dir: Path = DEFAULT_STATE_DIR) -> list:
    """Return the numbered options shown to ``handle``, or [] if stale/absent.

    Options older than LAST_OPTIONS_TTL_SECONDS are treated as missing —
    prevents a much-later /pick from resurrecting an old context the user
    may have forgotten about.
    """
    with connection(state_dir) as conn:
        row = conn.execute(
            "SELECT last_options_json, last_options_at " "FROM conversations WHERE handle = ?",
            (handle,),
        ).fetchone()
        if not row or not row["last_options_json"] or not row["last_options_at"]:
            return []
        try:
            options_at = datetime.fromisoformat(row["last_options_at"])
        except (TypeError, ValueError):
            return []
        if (datetime.now(timezone.utc) - options_at).total_seconds() > LAST_OPTIONS_TTL_SECONDS:
            return []
        try:
            return json.loads(row["last_options_json"])
        except json.JSONDecodeError:
            return []


def set_pending_intent(
    handle: str,
    command: str,
    extra_arg: str = "",
    *,
    state_dir: Path = DEFAULT_STATE_DIR,
) -> None:
    """Stash a pending NL-intent confirmation for ``handle``.

    The next inbound message from this handle will be matched against
    confirmation patterns (yes/no/cancel). If yes → the stored
    ``command`` (+ optional ``extra_arg``) executes. If no/anything else
    → pending is cleared and the message is processed normally.

    Stale entries (older than PENDING_INTENT_TTL_SECONDS) are dropped
    by ``get_pending_intent``. There's no separate prune — TTL is
    enforced at read time.
    """
    now = datetime.now(timezone.utc).isoformat()
    payload = json.dumps({"command": command, "extra_arg": extra_arg})
    with connection(state_dir) as conn:
        conn.execute(
            "INSERT INTO conversations "
            "  (handle, pending_intent_json, pending_intent_at, updated_at) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(handle) DO UPDATE SET "
            "  pending_intent_json = excluded.pending_intent_json, "
            "  pending_intent_at = excluded.pending_intent_at, "
            "  updated_at = excluded.updated_at",
            (handle, payload, now, now),
        )


def get_pending_intent(handle: str, *, state_dir: Path = DEFAULT_STATE_DIR) -> Optional[dict]:
    """Return ``{"command": str, "extra_arg": str}`` or None.

    None means no pending confirmation OR the pending one has aged out
    past PENDING_INTENT_TTL_SECONDS. Aged-out entries are NOT auto-
    deleted from the row — the next ``set_pending_intent`` (or
    ``clear_pending_intent``) overwrites them.
    """
    with connection(state_dir) as conn:
        row = conn.execute(
            "SELECT pending_intent_json, pending_intent_at " "FROM conversations WHERE handle = ?",
            (handle,),
        ).fetchone()
        if not row or not row["pending_intent_json"] or not row["pending_intent_at"]:
            return None
        try:
            pending_at = datetime.fromisoformat(row["pending_intent_at"])
        except (TypeError, ValueError):
            return None
        if (datetime.now(timezone.utc) - pending_at).total_seconds() > PENDING_INTENT_TTL_SECONDS:
            return None
        try:
            payload = json.loads(row["pending_intent_json"])
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, dict) or "command" not in payload:
            return None
        return payload


def clear_pending_intent(handle: str, *, state_dir: Path = DEFAULT_STATE_DIR) -> None:
    """NULL out the pending intent for ``handle`` (post-execution or cancel)."""
    now = datetime.now(timezone.utc).isoformat()
    with connection(state_dir) as conn:
        conn.execute(
            "UPDATE conversations "
            "SET pending_intent_json = NULL, pending_intent_at = NULL, "
            "    updated_at = ? "
            "WHERE handle = ?",
            (now, handle),
        )


def audit(
    *,
    handle_redacted: str,
    direction: str,
    kind: str,
    detail: Optional[str] = None,
    reply_bytes: Optional[int] = None,
    chatdb_rowid: Optional[int] = None,
    cost_cents: Optional[int] = None,
    error_category: Optional[str] = None,
    state_dir: Path = DEFAULT_STATE_DIR,
) -> None:
    """Append one audit row.

    ``detail`` should NOT contain raw message bodies in normal mode — the
    daemon's debug flag controls whether bodies are passed in. Defaults
    pass commands (e.g., "/sessions"), classification labels, or short
    structured summaries.

    The structured columns (``chatdb_rowid``, ``cost_cents``,
    ``error_category``) were added in schema v1 to make the audit-log
    cookbook queries straightforward without regexing ``detail``. They're
    optional — older callers that pass only ``detail`` continue to work,
    NULL-filled in the new columns.
    """
    ts = datetime.now(timezone.utc).isoformat()
    with connection(state_dir) as conn:
        conn.execute(
            "INSERT INTO audit_log (ts, handle_redacted, direction, kind, "
            "detail, reply_bytes, chatdb_rowid, cost_cents, error_category) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                ts,
                handle_redacted,
                direction,
                kind,
                detail,
                reply_bytes,
                chatdb_rowid,
                cost_cents,
                error_category,
            ),
        )


def tail_audit_rows(n: int = 10, *, state_dir: Path = DEFAULT_STATE_DIR) -> list[dict]:
    """Return the last ``n`` audit rows, newest first.

    Each row is a dict mirroring the audit_log columns. ``handle_redacted``
    is already the redacted form by design — no PII to scrub here. Used
    by /tail-audit; never exposes the raw body (we don't store it).
    """
    if n < 1:
        n = 1
    if n > 500:
        n = 500
    with connection(state_dir) as conn:
        cursor = conn.execute(
            "SELECT ts, handle_redacted, direction, kind, detail, "
            "reply_bytes, chatdb_rowid, cost_cents, error_category "
            "FROM audit_log ORDER BY rowid DESC LIMIT ?",
            (n,),
        )
        return [dict(r) for r in cursor.fetchall()]


# --- Rate limiting --------------------------------------------------------


def _bucket(ts: Optional[float] = None) -> str:
    """Minute-bucket key. Same minute -> same key."""
    ts = ts if ts is not None else time.time()
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y%m%d%H%M")


def reply_count_this_minute(handle: str, *, state_dir: Path = DEFAULT_STATE_DIR) -> int:
    bucket = _bucket()
    with connection(state_dir) as conn:
        row = conn.execute(
            "SELECT n FROM reply_counter WHERE bucket = ? AND handle = ?",
            (bucket, handle),
        ).fetchone()
        return int(row["n"]) if row else 0


def reserve_reply_slot(
    handle: str,
    limit: int,
    *,
    state_dir: Path = DEFAULT_STATE_DIR,
) -> tuple[bool, int]:
    """Atomically reserve a per-minute reply slot for ``handle``.

    Returns ``(granted, new_count)``. If granted is False, the caller MUST
    NOT send — they've already been counted but we're at/over the limit, so
    we roll the increment back. This pattern closes the TOCTOU window in
    the check-then-act sequence the prior implementation had.
    """
    bucket = _bucket()
    with connection(state_dir) as conn:
        # Single transaction: increment, observe, conditionally roll back.
        conn.execute(
            "INSERT INTO reply_counter (bucket, handle, n) VALUES (?, ?, 1) "
            "ON CONFLICT(bucket, handle) DO UPDATE SET n = n + 1",
            (bucket, handle),
        )
        row = conn.execute(
            "SELECT n FROM reply_counter WHERE bucket = ? AND handle = ?",
            (bucket, handle),
        ).fetchone()
        new_count = int(row["n"])
        if new_count > limit:
            # Roll back the increment so other callers see accurate state.
            conn.execute(
                "UPDATE reply_counter SET n = n - 1 " "WHERE bucket = ? AND handle = ?",
                (bucket, handle),
            )
            return (False, new_count - 1)
        return (True, new_count)


def prune_reply_counter(*, keep_buckets: int = 10, state_dir: Path = DEFAULT_STATE_DIR) -> None:
    """Drop rate-limit buckets older than ``keep_buckets`` minutes.

    Called occasionally by the daemon to keep state.db small.
    """
    threshold = datetime.fromtimestamp(time.time() - keep_buckets * 60, tz=timezone.utc)
    cutoff = threshold.strftime("%Y%m%d%H%M")
    with connection(state_dir) as conn:
        conn.execute("DELETE FROM reply_counter WHERE bucket < ?", (cutoff,))


# --- Daily cost tracking ---------------------------------------------------


def _today_utc_date() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def today_cost_cents(*, state_dir: Path = DEFAULT_STATE_DIR) -> int:
    """Cents spent today (UTC). Returns 0 if no entry."""
    today = _today_utc_date()
    with connection(state_dir) as conn:
        row = conn.execute("SELECT cents FROM daily_cost WHERE date_utc = ?", (today,)).fetchone()
        return int(row["cents"]) if row else 0


def add_cost_cents(amount_cents: int, *, state_dir: Path = DEFAULT_STATE_DIR) -> int:
    """Add ``amount_cents`` to today's tally. Returns the new total.

    Use integer cents — float USD comparisons can flap around the cap due
    to FP precision. Round up partial cents at the callsite.
    """
    today = _today_utc_date()
    with connection(state_dir) as conn:
        conn.execute(
            "INSERT INTO daily_cost (date_utc, cents) VALUES (?, ?) "
            "ON CONFLICT(date_utc) DO UPDATE SET cents = cents + excluded.cents",
            (today, int(amount_cents)),
        )
        row = conn.execute("SELECT cents FROM daily_cost WHERE date_utc = ?", (today,)).fetchone()
        return int(row["cents"])


def cost_over_cap(cap_usd: float, *, state_dir: Path = DEFAULT_STATE_DIR) -> bool:
    """True if today's spend already meets or exceeds the cap."""
    cap_cents = int(round(cap_usd * 100))
    return today_cost_cents(state_dir=state_dir) >= cap_cents


# --- Circuit breaker for consecutive Claude failures -----------------------


def get_consecutive_failures(*, state_dir: Path = DEFAULT_STATE_DIR) -> int:
    """Current run of back-to-back Claude failures. Reset by success."""
    with connection(state_dir) as conn:
        row = conn.execute("SELECT value FROM cursor WHERE name = 'consec_failures'").fetchone()
        return int(row["value"]) if row else 0


def record_claude_failure(*, state_dir: Path = DEFAULT_STATE_DIR) -> int:
    """Increment consecutive-failure counter; return new value."""
    with connection(state_dir) as conn:
        conn.execute(
            "INSERT INTO cursor (name, value) VALUES ('consec_failures', 1) "
            "ON CONFLICT(name) DO UPDATE SET value = value + 1"
        )
        row = conn.execute("SELECT value FROM cursor WHERE name = 'consec_failures'").fetchone()
        return int(row["value"])


def reset_claude_failures(*, state_dir: Path = DEFAULT_STATE_DIR) -> None:
    """Set consecutive-failure counter to 0 (on success)."""
    with connection(state_dir) as conn:
        conn.execute(
            "INSERT INTO cursor (name, value) VALUES ('consec_failures', 0) "
            "ON CONFLICT(name) DO UPDATE SET value = 0"
        )


def trip_pause(state_dir: Path = DEFAULT_STATE_DIR, *, reason: str = "") -> None:
    """Create the PAUSE file so the daemon idles until the user removes it."""
    pause = state_dir / "PAUSE"
    pause.write_text(reason + "\n")
    try:
        os.chmod(pause, 0o600)
    except OSError:
        pass
