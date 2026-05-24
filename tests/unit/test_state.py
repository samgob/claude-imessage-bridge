"""Tests for the SQLite state primitives.

Focus areas:
  - Cursor regression guard (restore-from-backup safety)
  - Rate-limit reservation atomicity (TOCTOU closure)
  - Daily-cost integer-cents accounting (no float flap around the cap)
  - Last-options TTL (no stale /pick resurrecting old context)
  - Conversation session-id roundtrip
  - Failure counter + reset
  - state.db perms tightening
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from src import state


# --- Init ---------------------------------------------------------------


def test_init_state_dir_creates_db_with_tight_perms(state_dir: Path):
    db = state.init_state_dir(state_dir)
    assert db.exists()
    mode = db.stat().st_mode & 0o777
    assert mode == 0o600
    dir_mode = state_dir.stat().st_mode & 0o777
    assert dir_mode == 0o700


def test_init_state_dir_tightens_existing_loose_db(state_dir: Path):
    db = state_dir / "state.db"
    db.touch()
    os.chmod(db, 0o644)  # world-readable: not allowed
    state.init_state_dir(state_dir)
    mode = db.stat().st_mode & 0o777
    assert mode == 0o600


# --- Cursor regression --------------------------------------------------


def test_cursor_forward_motion_allowed(state_dir: Path):
    state.set_cursor("c", 1, state_dir=state_dir)
    state.set_cursor("c", 5, state_dir=state_dir)
    assert state.get_cursor("c", state_dir=state_dir) == 5


def test_cursor_same_value_allowed(state_dir: Path):
    state.set_cursor("c", 5, state_dir=state_dir)
    state.set_cursor("c", 5, state_dir=state_dir)  # not strictly backward
    assert state.get_cursor("c", state_dir=state_dir) == 5


def test_cursor_regression_refused_by_default(state_dir: Path):
    state.set_cursor("c", 100, state_dir=state_dir)
    with pytest.raises(state.CursorRegression):
        state.set_cursor("c", 50, state_dir=state_dir)
    # Verify cursor was NOT moved.
    assert state.get_cursor("c", state_dir=state_dir) == 100


def test_cursor_regression_allowed_with_override(state_dir: Path):
    state.set_cursor("c", 100, state_dir=state_dir)
    state.set_cursor("c", 50, state_dir=state_dir, allow_regression=True)
    assert state.get_cursor("c", state_dir=state_dir) == 50


def test_cursor_default_when_unset(state_dir: Path):
    assert state.get_cursor("missing", default=-1, state_dir=state_dir) == -1


# --- Rate limit reservation --------------------------------------------


def test_reserve_reply_slot_grants_under_limit(state_dir: Path):
    granted, n = state.reserve_reply_slot("+15551234567", 10, state_dir=state_dir)
    assert granted
    assert n == 1


def test_reserve_reply_slot_rolls_back_when_over_limit(state_dir: Path):
    handle = "+15551234567"
    # Saturate at limit
    for _ in range(3):
        granted, _ = state.reserve_reply_slot(handle, 3, state_dir=state_dir)
        assert granted
    # The 4th must be denied AND the counter must NOT advance to 4.
    granted, n = state.reserve_reply_slot(handle, 3, state_dir=state_dir)
    assert not granted
    assert n == 3, "denied reservation must roll back so other callers see accurate state"


def test_reserve_reply_slot_per_handle_isolated(state_dir: Path):
    """A saturated handle must not block a different handle."""
    a = "+15551234567"
    b = "+15559876543"
    for _ in range(5):
        state.reserve_reply_slot(a, 5, state_dir=state_dir)
    granted, n = state.reserve_reply_slot(b, 5, state_dir=state_dir)
    assert granted
    assert n == 1


def test_prune_reply_counter_drops_old_buckets(state_dir: Path):
    handle = "+15551234567"
    state.reserve_reply_slot(handle, 10, state_dir=state_dir)
    # Manually inject an old bucket
    old_bucket = "200001010000"
    with state.connection(state_dir) as conn:
        conn.execute(
            "INSERT INTO reply_counter (bucket, handle, n) VALUES (?, ?, 1)",
            (old_bucket, handle),
        )
    state.prune_reply_counter(keep_buckets=10, state_dir=state_dir)
    with state.connection(state_dir) as conn:
        row = conn.execute("SELECT n FROM reply_counter WHERE bucket = ?", (old_bucket,)).fetchone()
    assert row is None


# --- Daily cost ---------------------------------------------------------


def test_today_cost_cents_starts_zero(state_dir: Path):
    assert state.today_cost_cents(state_dir=state_dir) == 0


def test_add_cost_cents_accumulates(state_dir: Path):
    state.add_cost_cents(5, state_dir=state_dir)
    state.add_cost_cents(7, state_dir=state_dir)
    assert state.today_cost_cents(state_dir=state_dir) == 12


def test_cost_over_cap_uses_integer_math(state_dir: Path):
    """No float flap at the cap boundary."""
    # 5 dollars = 500 cents.
    state.add_cost_cents(499, state_dir=state_dir)
    assert state.cost_over_cap(5.0, state_dir=state_dir) is False
    state.add_cost_cents(1, state_dir=state_dir)
    assert state.cost_over_cap(5.0, state_dir=state_dir) is True


# --- Conversations / sessions ------------------------------------------


def test_get_current_session_default_none(state_dir: Path):
    state.init_state_dir(state_dir)
    assert state.get_current_session("+15551234567", state_dir=state_dir) is None


def test_set_current_session_roundtrip(state_dir: Path):
    state.set_current_session("+15551234567", "sess-abc", state_dir=state_dir)
    assert state.get_current_session("+15551234567", state_dir=state_dir) == "sess-abc"


def test_set_current_session_can_clear(state_dir: Path):
    state.set_current_session("+15551234567", "sess-abc", state_dir=state_dir)
    state.set_current_session("+15551234567", None, state_dir=state_dir)
    assert state.get_current_session("+15551234567", state_dir=state_dir) is None


# --- Last options TTL ---------------------------------------------------


def test_last_options_fresh_returned(state_dir: Path):
    opts = [{"id": "sess-1", "snippet": "first"}, {"id": "sess-2", "snippet": "second"}]
    state.set_last_options("+15551234567", opts, state_dir=state_dir)
    got = state.get_last_options("+15551234567", state_dir=state_dir)
    assert got == opts


def test_last_options_stale_returns_empty(state_dir: Path):
    handle = "+15551234567"
    state.set_last_options(handle, [{"id": "a"}], state_dir=state_dir)
    # Force the ts to be older than the TTL
    old = (
        datetime.now(timezone.utc) - timedelta(seconds=state.LAST_OPTIONS_TTL_SECONDS + 60)
    ).isoformat()
    with state.connection(state_dir) as conn:
        conn.execute(
            "UPDATE conversations SET last_options_at = ? WHERE handle = ?",
            (old, handle),
        )
    assert state.get_last_options(handle, state_dir=state_dir) == []


def test_last_options_missing_returns_empty(state_dir: Path):
    assert state.get_last_options("+15551111111", state_dir=state_dir) == []


def test_last_options_corrupt_json_returns_empty(state_dir: Path):
    """If the persisted JSON is malformed, treat as missing — never crash."""
    handle = "+15551234567"
    state.set_last_options(handle, [{"id": "a"}], state_dir=state_dir)
    now = datetime.now(timezone.utc).isoformat()
    with state.connection(state_dir) as conn:
        conn.execute(
            "UPDATE conversations SET last_options_json = ?, last_options_at = ? "
            "WHERE handle = ?",
            ("not-json", now, handle),
        )
    assert state.get_last_options(handle, state_dir=state_dir) == []


# --- Pending NL-intent confirmations (schema v3) ------------------------


def test_pending_intent_none_default(state_dir: Path):
    state.init_state_dir(state_dir)
    assert state.get_pending_intent("+15551234567", state_dir=state_dir) is None


def test_pending_intent_set_and_get(state_dir: Path):
    state.set_pending_intent("+15551234567", "/halt", state_dir=state_dir)
    pending = state.get_pending_intent("+15551234567", state_dir=state_dir)
    assert pending == {"command": "/halt", "extra_arg": ""}


def test_pending_intent_with_extra_arg(state_dir: Path):
    state.set_pending_intent(
        "+15551234567",
        "/use",
        "wesco",
        state_dir=state_dir,
    )
    pending = state.get_pending_intent("+15551234567", state_dir=state_dir)
    assert pending == {"command": "/use", "extra_arg": "wesco"}


def test_pending_intent_ttl_expires(state_dir: Path):
    """After PENDING_INTENT_TTL_SECONDS, the pending intent is treated as gone."""
    handle = "+15551234567"
    state.set_pending_intent(handle, "/halt", state_dir=state_dir)
    # Backdate the timestamp past the TTL.
    old = (
        datetime.now(timezone.utc) - timedelta(seconds=state.PENDING_INTENT_TTL_SECONDS + 5)
    ).isoformat()
    with state.connection(state_dir) as conn:
        conn.execute(
            "UPDATE conversations SET pending_intent_at = ? WHERE handle = ?",
            (old, handle),
        )
    assert state.get_pending_intent(handle, state_dir=state_dir) is None


def test_pending_intent_corrupt_json_returns_none(state_dir: Path):
    handle = "+15551234567"
    state.set_pending_intent(handle, "/halt", state_dir=state_dir)
    now = datetime.now(timezone.utc).isoformat()
    with state.connection(state_dir) as conn:
        conn.execute(
            "UPDATE conversations SET pending_intent_json = ?, "
            "pending_intent_at = ? WHERE handle = ?",
            ("not-json", now, handle),
        )
    assert state.get_pending_intent(handle, state_dir=state_dir) is None


def test_clear_pending_intent_nulls_columns(state_dir: Path):
    handle = "+15551234567"
    state.set_pending_intent(handle, "/halt", state_dir=state_dir)
    state.clear_pending_intent(handle, state_dir=state_dir)
    assert state.get_pending_intent(handle, state_dir=state_dir) is None
    # Verify the columns are actually NULL (not the TTL path):
    with state.connection(state_dir) as conn:
        row = conn.execute(
            "SELECT pending_intent_json, pending_intent_at " "FROM conversations WHERE handle = ?",
            (handle,),
        ).fetchone()
    assert row["pending_intent_json"] is None
    assert row["pending_intent_at"] is None


def test_set_pending_intent_overwrites(state_dir: Path):
    """A second set_pending_intent replaces the first cleanly."""
    handle = "+15551234567"
    state.set_pending_intent(handle, "/halt", state_dir=state_dir)
    state.set_pending_intent(handle, "/pause", state_dir=state_dir)
    pending = state.get_pending_intent(handle, state_dir=state_dir)
    assert pending["command"] == "/pause"


# --- Circuit breaker / failure tracking --------------------------------


def test_failure_counter_default_zero(state_dir: Path):
    state.init_state_dir(state_dir)
    assert state.get_consecutive_failures(state_dir=state_dir) == 0


def test_failure_counter_increments(state_dir: Path):
    assert state.record_claude_failure(state_dir=state_dir) == 1
    assert state.record_claude_failure(state_dir=state_dir) == 2
    assert state.get_consecutive_failures(state_dir=state_dir) == 2


def test_failure_reset_clears_count(state_dir: Path):
    state.record_claude_failure(state_dir=state_dir)
    state.record_claude_failure(state_dir=state_dir)
    state.reset_claude_failures(state_dir=state_dir)
    assert state.get_consecutive_failures(state_dir=state_dir) == 0


def test_trip_pause_creates_pause_file(state_dir: Path):
    state.init_state_dir(state_dir)
    state.trip_pause(state_dir, reason="test")
    pause = state_dir / "PAUSE"
    assert pause.exists()
    assert "test" in pause.read_text()
    mode = pause.stat().st_mode & 0o777
    assert mode == 0o600


# --- Audit -------------------------------------------------------------


def test_audit_persists_row(state_dir: Path):
    state.audit(
        handle_redacted="abc***@x",
        direction="in",
        kind="text",
        detail="ok",
        state_dir=state_dir,
    )
    with state.connection(state_dir) as conn:
        rows = conn.execute("SELECT direction, kind, detail FROM audit_log").fetchall()
    assert len(rows) == 1
    assert rows[0]["direction"] == "in"
    assert rows[0]["kind"] == "text"


def test_audit_supports_reply_bytes(state_dir: Path):
    state.audit(
        handle_redacted="abc***@x",
        direction="out",
        kind="reply",
        detail="ok",
        reply_bytes=42,
        state_dir=state_dir,
    )
    with state.connection(state_dir) as conn:
        row = conn.execute("SELECT reply_bytes FROM audit_log").fetchone()
    assert row["reply_bytes"] == 42


def test_audit_persists_structured_columns(state_dir: Path):
    """v1 schema: chatdb_rowid, cost_cents, error_category."""
    state.audit(
        handle_redacted="abc***@x",
        direction="out",
        kind="reply",
        detail="ok",
        reply_bytes=42,
        chatdb_rowid=12345,
        cost_cents=7,
        error_category=None,
        state_dir=state_dir,
    )
    state.audit(
        handle_redacted="abc***@x",
        direction="out",
        kind="reply",
        detail="err",
        chatdb_rowid=12346,
        cost_cents=0,
        error_category="timeout",
        state_dir=state_dir,
    )
    with state.connection(state_dir) as conn:
        rows = conn.execute(
            "SELECT chatdb_rowid, cost_cents, error_category " "FROM audit_log ORDER BY rowid"
        ).fetchall()
    assert [r["chatdb_rowid"] for r in rows] == [12345, 12346]
    assert [r["cost_cents"] for r in rows] == [7, 0]
    assert [r["error_category"] for r in rows] == [None, "timeout"]


def test_audit_legacy_signature_still_works(state_dir: Path):
    """Older callers that don't pass the new kwargs must still succeed."""
    state.audit(
        handle_redacted="abc***@x",
        direction="in",
        kind="text",
        detail="ok",
        state_dir=state_dir,
    )
    with state.connection(state_dir) as conn:
        row = conn.execute(
            "SELECT chatdb_rowid, cost_cents, error_category FROM audit_log"
        ).fetchone()
    assert row["chatdb_rowid"] is None
    assert row["cost_cents"] is None
    assert row["error_category"] is None


# --- Schema versioning ------------------------------------------------


def test_schema_version_stamped_on_init(state_dir: Path):
    state.init_state_dir(state_dir)
    with state.connection(state_dir) as conn:
        v = conn.execute("PRAGMA user_version").fetchone()[0]
    assert v == state.SCHEMA_VERSION


def test_schema_too_new_refused(state_dir: Path):
    state.init_state_dir(state_dir)
    # Forge a too-new version: bump user_version past what code knows.
    with state.connection(state_dir) as conn:
        conn.execute("PRAGMA user_version = 999")
    # Now re-init: should refuse.
    with pytest.raises(state.SchemaTooNew):
        state.init_state_dir(state_dir)


def test_apply_schema_is_idempotent(state_dir: Path):
    """Running init_state_dir twice in a row must not raise and must
    leave the schema in the same state."""
    state.init_state_dir(state_dir)
    state.init_state_dir(state_dir)
    with state.connection(state_dir) as conn:
        cols = {row["name"] for row in conn.execute("PRAGMA table_info(audit_log)")}
        version = conn.execute("PRAGMA user_version").fetchone()[0]
    assert {"chatdb_rowid", "cost_cents", "error_category"} <= cols
    assert version == state.SCHEMA_VERSION


def test_pragma_integrity_check_after_migration(state_dir: Path):
    """SQLite integrity_check must return 'ok' after init."""
    state.init_state_dir(state_dir)
    with state.connection(state_dir) as conn:
        result = conn.execute("PRAGMA integrity_check").fetchone()[0]
    assert result == "ok"


def test_schema_partial_migration_recovers(state_dir: Path):
    """A v0 DB where ONE of the new columns somehow already exists
    (simulates a crash mid-migration) must still complete the migration
    without raising "duplicate column"."""
    import sqlite3

    db_path = state_dir / "state.db"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript("""
            CREATE TABLE audit_log (
                rowid INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                handle_redacted TEXT NOT NULL,
                direction TEXT NOT NULL,
                kind TEXT NOT NULL,
                detail TEXT,
                reply_bytes INTEGER,
                chatdb_rowid INTEGER  -- one of the new columns already exists
            );
            CREATE TABLE cursor (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
            CREATE TABLE conversations (
                handle TEXT PRIMARY KEY, current_session_id TEXT,
                last_options_json TEXT, last_options_at TEXT,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE reply_counter (
                bucket TEXT NOT NULL, handle TEXT NOT NULL,
                n INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (bucket, handle)
            );
            CREATE TABLE daily_cost (
                date_utc TEXT PRIMARY KEY, cents INTEGER NOT NULL DEFAULT 0
            );
            PRAGMA user_version = 0;
        """)
        conn.commit()
    finally:
        conn.close()

    # Must NOT raise "duplicate column chatdb_rowid".
    state.init_state_dir(state_dir)
    with state.connection(state_dir) as conn:
        cols = {row["name"] for row in conn.execute("PRAGMA table_info(audit_log)")}
    assert {"chatdb_rowid", "cost_cents", "error_category"} <= cols


def test_schema_migration_missing_raises(state_dir: Path, monkeypatch):
    """Bump SCHEMA_VERSION above what _apply_schema knows; an existing
    fully-migrated DB should hit the no-registered-migration path and
    raise SchemaMigrationMissing (rather than silently stamping forward)."""
    state.init_state_dir(state_dir)  # stamps to SCHEMA_VERSION
    # Pretend the code is now SCHEMA_VERSION+1 with no migration registered.
    monkeypatch.setattr(state, "SCHEMA_VERSION", state.SCHEMA_VERSION + 1)
    with pytest.raises(state.SchemaMigrationMissing):
        state.init_state_dir(state_dir)


def test_schema_v1_to_v2_adds_conversations_columns(state_dir: Path):
    """A state.db at user_version=1 whose ``conversations`` table is
    missing ``last_options_json`` / ``last_options_at`` (the Phase C
    columns that were never migrated for pre-Phase-C DBs) must have
    them added on next init. Observed live on Sam's laptop.
    """
    import sqlite3

    db_path = state_dir / "state.db"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript("""
            CREATE TABLE cursor (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
            -- The pre-Phase-C conversations table: missing the options cols.
            CREATE TABLE conversations (
                handle TEXT PRIMARY KEY,
                current_session_id TEXT,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE audit_log (
                rowid INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                handle_redacted TEXT NOT NULL,
                direction TEXT NOT NULL,
                kind TEXT NOT NULL,
                detail TEXT,
                reply_bytes INTEGER,
                chatdb_rowid INTEGER,
                cost_cents INTEGER,
                error_category TEXT
            );
            CREATE TABLE reply_counter (
                bucket TEXT NOT NULL, handle TEXT NOT NULL,
                n INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (bucket, handle)
            );
            CREATE TABLE daily_cost (
                date_utc TEXT PRIMARY KEY, cents INTEGER NOT NULL DEFAULT 0
            );
            PRAGMA user_version = 1;
        """)
        conn.commit()
    finally:
        conn.close()

    # Run init — should advance to SCHEMA_VERSION (>= 2) and add cols.
    state.init_state_dir(state_dir)
    with state.connection(state_dir) as conn:
        cols = {row["name"] for row in conn.execute("PRAGMA table_info(conversations)")}
        version = conn.execute("PRAGMA user_version").fetchone()[0]
    assert "last_options_json" in cols
    assert "last_options_at" in cols
    assert version == state.SCHEMA_VERSION

    # And the post-migration set_last_options call must succeed (this is
    # the live failure mode — INSERT with last_options_at column).
    state.set_last_options(
        "+15551234567",
        [{"id": "x", "snippet": "y"}],
        state_dir=state_dir,
    )
    assert state.get_last_options("+15551234567", state_dir=state_dir) == [
        {"id": "x", "snippet": "y"}
    ]


def test_schema_v0_full_chain_to_current(state_dir: Path):
    """A v0 DB (no user_version stamp) must run the full forward chain —
    both audit_log v1 and conversations v2 columns end up present."""
    import sqlite3

    db_path = state_dir / "state.db"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript("""
            CREATE TABLE cursor (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
            CREATE TABLE conversations (
                handle TEXT PRIMARY KEY,
                current_session_id TEXT,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE audit_log (
                rowid INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                handle_redacted TEXT NOT NULL,
                direction TEXT NOT NULL,
                kind TEXT NOT NULL,
                detail TEXT,
                reply_bytes INTEGER
            );
            CREATE TABLE reply_counter (
                bucket TEXT NOT NULL, handle TEXT NOT NULL,
                n INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (bucket, handle)
            );
            CREATE TABLE daily_cost (
                date_utc TEXT PRIMARY KEY, cents INTEGER NOT NULL DEFAULT 0
            );
            PRAGMA user_version = 0;
        """)
        conn.commit()
    finally:
        conn.close()

    state.init_state_dir(state_dir)
    with state.connection(state_dir) as conn:
        audit_cols = {row["name"] for row in conn.execute("PRAGMA table_info(audit_log)")}
        conv_cols = {row["name"] for row in conn.execute("PRAGMA table_info(conversations)")}
        version = conn.execute("PRAGMA user_version").fetchone()[0]
    assert {"chatdb_rowid", "cost_cents", "error_category"} <= audit_cols
    assert {"last_options_json", "last_options_at"} <= conv_cols
    assert version == state.SCHEMA_VERSION


def test_schema_migration_from_v0_adds_columns(state_dir: Path):
    """An existing v0 DB (no new columns, user_version=0) must migrate forward."""
    import sqlite3

    # Build a v0 DB by hand: tables WITHOUT new columns, user_version=0.
    db_path = state_dir / "state.db"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript("""
            CREATE TABLE audit_log (
                rowid INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                handle_redacted TEXT NOT NULL,
                direction TEXT NOT NULL,
                kind TEXT NOT NULL,
                detail TEXT,
                reply_bytes INTEGER
            );
            CREATE TABLE cursor (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
            CREATE TABLE conversations (
                handle TEXT PRIMARY KEY,
                current_session_id TEXT,
                last_options_json TEXT,
                last_options_at TEXT,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE reply_counter (
                bucket TEXT NOT NULL, handle TEXT NOT NULL,
                n INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (bucket, handle)
            );
            CREATE TABLE daily_cost (
                date_utc TEXT PRIMARY KEY, cents INTEGER NOT NULL DEFAULT 0
            );
            PRAGMA user_version = 0;
        """)
        conn.commit()
    finally:
        conn.close()

    # Run init: should detect v0 and add new columns.
    state.init_state_dir(state_dir)
    with state.connection(state_dir) as conn:
        cols = {row["name"] for row in conn.execute("PRAGMA table_info(audit_log)")}
        version = conn.execute("PRAGMA user_version").fetchone()[0]
    assert "chatdb_rowid" in cols
    assert "cost_cents" in cols
    assert "error_category" in cols
    assert version == state.SCHEMA_VERSION
