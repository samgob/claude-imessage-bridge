"""Tests for the /-command dispatcher.

The commands surface is the only path through which iMessage controls
session resume. Bad behavior here = the user resumes the wrong session and
sees content from someone else's transcript through their iMessage.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from src import commands, session_discovery, state


HANDLE = "+15551234567"


# --- is_command --------------------------------------------------------

@pytest.mark.parametrize("body,expected", [
    ("/help", True),
    ("  /sessions ", True),
    ("/pick 3", True),
    ("hello", False),
    ("", False),
    ("// not a command", True),   # any leading slash counts
    ("hello /pick 1", False),    # /-prefix only at the start
])
def test_is_command(body, expected):
    assert commands.is_command(body) is expected


# --- /help / /new / /status (cheap, no discovery) ----------------------

def test_help(state_dir: Path):
    r = commands.parse_and_dispatch("/help", handle=HANDLE, state_dir=state_dir)
    assert "Commands:" in r.reply
    assert "/sessions" in r.reply
    assert "/pick" in r.reply
    assert r.set_session_id is None
    assert r.clear_session is False


def test_new_clears_session(state_dir: Path):
    r = commands.parse_and_dispatch("/new", handle=HANDLE, state_dir=state_dir)
    assert r.clear_session is True
    assert r.set_session_id is None


def test_status_with_no_active_session(state_dir: Path):
    r = commands.parse_and_dispatch("/status", handle=HANDLE, state_dir=state_dir)
    assert "No active session" in r.reply


def test_status_with_active_session_no_disk(state_dir: Path, monkeypatch):
    state.set_current_session(HANDLE, "sess-xyz", state_dir=state_dir)
    monkeypatch.setattr(session_discovery, "find_by_id", lambda sid: None)
    r = commands.parse_and_dispatch("/status", handle=HANDLE, state_dir=state_dir)
    assert "no longer on disk" in r.reply or "starts a fresh session" in r.reply


# --- /sessions ---------------------------------------------------------

def _mk_session(sid: str, snippet: str = "snip", is_routine: bool = False):
    return session_discovery.SessionInfo(
        session_id=sid,
        cwd=None,
        last_modified=datetime.now(timezone.utc),
        snippet=snippet,
        file_path=Path(f"/fake/{sid}.jsonl"),
        size_bytes=100,
        is_routine=is_routine,
    )


def test_sessions_returns_empty_message_when_no_sessions(state_dir: Path, monkeypatch):
    monkeypatch.setattr(session_discovery, "discover_sessions", lambda **kw: [])
    r = commands.parse_and_dispatch("/sessions", handle=HANDLE, state_dir=state_dir)
    assert "No sessions" in r.reply


def test_sessions_numbered_list_persists_options(state_dir: Path, monkeypatch):
    monkeypatch.setattr(
        session_discovery, "discover_sessions",
        lambda **kw: [_mk_session("aaa11111-x"), _mk_session("bbb22222-y")],
    )
    r = commands.parse_and_dispatch("/sessions", handle=HANDLE, state_dir=state_dir)
    assert "[1]" in r.reply
    assert "[2]" in r.reply
    # Options must have been stashed for /pick.
    opts = state.get_last_options(HANDLE, state_dir=state_dir)
    assert len(opts) == 2
    assert opts[0]["id"] == "aaa11111-x"


def test_sessions_all_flag_includes_routines(state_dir: Path, monkeypatch):
    captured = {}

    def fake_discover(**kw):
        captured.update(kw)
        return []

    monkeypatch.setattr(session_discovery, "discover_sessions", fake_discover)
    commands.parse_and_dispatch("/sessions --all", handle=HANDLE, state_dir=state_dir)
    assert captured.get("include_routines") is True


def test_sessions_default_excludes_routines(state_dir: Path, monkeypatch):
    captured = {}

    def fake_discover(**kw):
        captured.update(kw)
        return []

    monkeypatch.setattr(session_discovery, "discover_sessions", fake_discover)
    commands.parse_and_dispatch("/sessions", handle=HANDLE, state_dir=state_dir)
    assert captured.get("include_routines") is False


# --- /use --------------------------------------------------------------

def test_use_requires_query(state_dir: Path):
    r = commands.parse_and_dispatch("/use", handle=HANDLE, state_dir=state_dir)
    assert "Usage" in r.reply


def test_use_single_match_auto_resumes(state_dir: Path, monkeypatch):
    monkeypatch.setattr(
        session_discovery, "search_sessions",
        lambda q, limit, exclude_session_ids: [_mk_session("auth-refactor-1")],
    )
    r = commands.parse_and_dispatch(
        "/use auth-refactor", handle=HANDLE, state_dir=state_dir,
    )
    assert r.set_session_id == "auth-refactor-1"
    assert "Resumed" in r.reply


def test_use_multiple_matches_offers_pick(state_dir: Path, monkeypatch):
    monkeypatch.setattr(
        session_discovery, "search_sessions",
        lambda q, limit, exclude_session_ids: [
            _mk_session("auth-refactor-1"), _mk_session("auth-refactor-2"),
        ],
    )
    r = commands.parse_and_dispatch(
        "/use auth-refactor", handle=HANDLE, state_dir=state_dir,
    )
    assert "[1]" in r.reply
    assert "[2]" in r.reply
    assert r.set_session_id is None  # user must /pick first


def test_use_no_matches_reports(state_dir: Path, monkeypatch):
    monkeypatch.setattr(
        session_discovery, "search_sessions",
        lambda q, limit, exclude_session_ids: [],
    )
    r = commands.parse_and_dispatch(
        "/use nothingmatches", handle=HANDLE, state_dir=state_dir,
    )
    assert "No sessions match" in r.reply


def test_use_excludes_current_session(state_dir: Path, monkeypatch):
    state.set_current_session(HANDLE, "current-sess", state_dir=state_dir)
    captured = {}

    def fake_search(q, limit, exclude_session_ids):
        captured["exclude"] = exclude_session_ids
        return []

    monkeypatch.setattr(session_discovery, "search_sessions", fake_search)
    commands.parse_and_dispatch("/use foo", handle=HANDLE, state_dir=state_dir)
    assert "current-sess" in captured["exclude"]


# --- /pick -------------------------------------------------------------

def test_pick_requires_n(state_dir: Path):
    r = commands.parse_and_dispatch("/pick", handle=HANDLE, state_dir=state_dir)
    assert "Usage" in r.reply


def test_pick_rejects_non_int(state_dir: Path):
    r = commands.parse_and_dispatch("/pick abc", handle=HANDLE, state_dir=state_dir)
    assert "Not a number" in r.reply


def test_pick_no_recent_list(state_dir: Path):
    r = commands.parse_and_dispatch("/pick 1", handle=HANDLE, state_dir=state_dir)
    assert "No recent list" in r.reply


def test_pick_out_of_range(state_dir: Path, monkeypatch):
    state.set_last_options(
        HANDLE, [{"id": "a", "snippet": "x"}], state_dir=state_dir,
    )
    r = commands.parse_and_dispatch("/pick 5", handle=HANDLE, state_dir=state_dir)
    assert "between 1 and 1" in r.reply


def test_pick_returns_set_session_id(state_dir: Path, monkeypatch):
    state.set_last_options(
        HANDLE,
        [{"id": "sess-target-12345678", "snippet": "x"}],
        state_dir=state_dir,
    )
    monkeypatch.setattr(
        session_discovery, "find_by_id",
        lambda sid: _mk_session(sid) if sid == "sess-target-12345678" else None,
    )
    r = commands.parse_and_dispatch("/pick 1", handle=HANDLE, state_dir=state_dir)
    assert r.set_session_id == "sess-target-12345678"


def test_pick_stale_session_gone_from_disk(state_dir: Path, monkeypatch):
    state.set_last_options(
        HANDLE,
        [{"id": "vanished-sid", "snippet": "x"}],
        state_dir=state_dir,
    )
    monkeypatch.setattr(session_discovery, "find_by_id", lambda sid: None)
    r = commands.parse_and_dispatch("/pick 1", handle=HANDLE, state_dir=state_dir)
    assert "no longer on disk" in r.reply
    assert r.set_session_id is None


def test_pick_after_options_aged_out(state_dir: Path):
    state.set_last_options(
        HANDLE, [{"id": "a", "snippet": "x"}], state_dir=state_dir,
    )
    # Manually backdate the options past the TTL
    old = (datetime.now(timezone.utc) - timedelta(
        seconds=state.LAST_OPTIONS_TTL_SECONDS + 60)
    ).isoformat()
    with state.connection(state_dir) as conn:
        conn.execute(
            "UPDATE conversations SET last_options_at = ? WHERE handle = ?",
            (old, HANDLE),
        )
    r = commands.parse_and_dispatch("/pick 1", handle=HANDLE, state_dir=state_dir)
    assert "No recent list" in r.reply


# --- Unknown command ---------------------------------------------------

def test_unknown_command_returns_help_hint(state_dir: Path):
    r = commands.parse_and_dispatch("/bogus", handle=HANDLE, state_dir=state_dir)
    assert "Unknown command" in r.reply
    assert "/help" in r.reply


# --- /use with aliases -------------------------------------------------

def test_use_alias_hit_resumes_directly(state_dir: Path, monkeypatch):
    """Configured alias matches: skip keyword search, resume the named sid."""
    aliases = {"wesco": "4fe39c70-21d7-467e-801b-ca3167ac130f"}
    info = session_discovery.SessionInfo(
        session_id="4fe39c70-21d7-467e-801b-ca3167ac130f",
        cwd=None,
        last_modified=datetime.now(timezone.utc),
        snippet="Wesco POC notes",
        file_path=Path("/fake/4fe39c70.jsonl"),
        size_bytes=200,
    )
    monkeypatch.setattr(
        session_discovery, "find_by_id",
        lambda sid: info if sid == aliases["wesco"] else None,
    )
    # search_sessions must NOT be called on the happy alias path.
    def fail_search(*args, **kwargs):
        raise AssertionError("alias hit should skip keyword search")
    monkeypatch.setattr(session_discovery, "search_sessions", fail_search)

    r = commands.parse_and_dispatch(
        "/use wesco", handle=HANDLE, state_dir=state_dir, aliases=aliases,
    )
    assert r.set_session_id == aliases["wesco"]
    assert "alias 'wesco'" in r.reply
    assert "Resumed" in r.reply


def test_use_alias_case_insensitive(state_dir: Path, monkeypatch):
    """/use Wesco and /use WESCO must resolve the same as /use wesco."""
    aliases = {"wesco": "4fe39c70-21d7-467e-801b-ca3167ac130f"}
    info = session_discovery.SessionInfo(
        session_id=aliases["wesco"],
        cwd=None,
        last_modified=datetime.now(timezone.utc),
        snippet="x",
        file_path=Path("/fake/x.jsonl"),
        size_bytes=10,
    )
    monkeypatch.setattr(session_discovery, "find_by_id", lambda sid: info)
    for q in ("/use Wesco", "/use WESCO", "/use wesco", "/use  wesco  "):
        r = commands.parse_and_dispatch(
            q, handle=HANDLE, state_dir=state_dir, aliases=aliases,
        )
        assert r.set_session_id == aliases["wesco"], (
            f"query {q!r} failed to match alias"
        )


def test_use_alias_miss_falls_through(state_dir: Path, monkeypatch):
    """Alias points at a vanished session → keyword search still runs."""
    aliases = {"arden": "8a1b2c3d-aaaa-bbbb-cccc-deadbeef0001"}
    monkeypatch.setattr(session_discovery, "find_by_id", lambda sid: None)
    fallback = _mk_session("fallback-1", snippet="arden insurance")
    monkeypatch.setattr(
        session_discovery, "search_sessions",
        lambda q, limit, exclude_session_ids: [fallback],
    )
    r = commands.parse_and_dispatch(
        "/use arden", handle=HANDLE, state_dir=state_dir, aliases=aliases,
    )
    assert "alias 'arden'" in r.reply  # the miss note
    assert "points at a session that's gone" in r.reply
    assert r.set_session_id == "fallback-1"


def test_use_no_alias_match_falls_through(state_dir: Path, monkeypatch):
    """Query doesn't match any alias → regular keyword search runs."""
    aliases = {"wesco": "4fe39c70-21d7-467e-801b-ca3167ac130f"}
    captured = {}

    def fake_search(q, limit, exclude_session_ids):
        captured["q"] = q
        return [_mk_session("kw-hit-1")]

    monkeypatch.setattr(session_discovery, "search_sessions", fake_search)
    monkeypatch.setattr(session_discovery, "find_by_id", lambda sid: None)

    r = commands.parse_and_dispatch(
        "/use somethingelse", handle=HANDLE, state_dir=state_dir,
        aliases=aliases,
    )
    assert captured["q"] == "somethingelse"
    assert r.set_session_id == "kw-hit-1"
    # No alias-miss note (the query didn't match any alias).
    assert "alias" not in r.reply


# --- /aliases command --------------------------------------------------

def test_aliases_empty_message(state_dir: Path):
    r = commands.parse_and_dispatch(
        "/aliases", handle=HANDLE, state_dir=state_dir, aliases={},
    )
    assert "No aliases configured" in r.reply


def test_aliases_lists_with_age_and_snippet(state_dir: Path, monkeypatch):
    aliases = {
        "wesco": "4fe39c70-21d7-467e-801b-ca3167ac130f",
        "arden": "8a1b2c3d-aaaa-bbbb-cccc-deadbeef0001",
    }
    wesco_info = session_discovery.SessionInfo(
        session_id=aliases["wesco"], cwd=None,
        last_modified=datetime.now(timezone.utc),
        snippet="POC deck for Wesco", file_path=Path("/fake/w.jsonl"),
        size_bytes=10,
    )
    monkeypatch.setattr(
        session_discovery, "find_by_id",
        lambda sid: wesco_info if sid == aliases["wesco"] else None,
    )
    r = commands.parse_and_dispatch(
        "/aliases", handle=HANDLE, state_dir=state_dir, aliases=aliases,
    )
    assert "wesco" in r.reply
    assert "arden" in r.reply
    assert "missing on disk" in r.reply  # arden has no info
    assert "POC deck for Wesco" in r.reply  # wesco has snippet
    assert "/use <name>" in r.reply  # footer


def test_help_mentions_aliases(state_dir: Path):
    r = commands.parse_and_dispatch("/help", handle=HANDLE, state_dir=state_dir)
    assert "/aliases" in r.reply


# --- /pause and /resume ------------------------------------------------

def test_pause_creates_pause_file(state_dir: Path):
    r = commands.parse_and_dispatch(
        "/pause", handle=HANDLE, state_dir=state_dir,
    )
    assert "paused" in r.reply.lower()
    pause = state_dir / "PAUSE"
    assert pause.exists()
    assert "manual via /pause" in pause.read_text()


def test_pause_with_reason(state_dir: Path):
    r = commands.parse_and_dispatch(
        "/pause testing the system overnight",
        handle=HANDLE, state_dir=state_dir,
    )
    assert "testing the system overnight" in r.reply
    pause = state_dir / "PAUSE"
    assert "testing the system overnight" in pause.read_text()


def test_resume_removes_pause_file(state_dir: Path):
    state.trip_pause(state_dir=state_dir, reason="test")
    assert (state_dir / "PAUSE").exists()
    r = commands.parse_and_dispatch(
        "/resume", handle=HANDLE, state_dir=state_dir,
    )
    assert "resumed" in r.reply.lower()
    assert not (state_dir / "PAUSE").exists()


def test_resume_no_op_when_not_paused(state_dir: Path):
    assert not (state_dir / "PAUSE").exists()
    r = commands.parse_and_dispatch(
        "/resume", handle=HANDLE, state_dir=state_dir,
    )
    assert "wasn't paused" in r.reply
    assert "Nothing to do" in r.reply


def test_resume_resets_consecutive_failures(state_dir: Path):
    """After /resume, the circuit-breaker counter resets — otherwise a
    /resume after a circuit-breaker-tripped pause would immediately re-trip
    on the next failure."""
    state.trip_pause(state_dir=state_dir, reason="auto: 5 consecutive failures")
    # Simulate accumulated failures
    state.record_claude_failure(state_dir=state_dir)
    state.record_claude_failure(state_dir=state_dir)
    state.record_claude_failure(state_dir=state_dir)
    assert state.get_consecutive_failures(state_dir=state_dir) >= 3
    commands.parse_and_dispatch("/resume", handle=HANDLE, state_dir=state_dir)
    assert state.get_consecutive_failures(state_dir=state_dir) == 0


def test_status_surfaces_pause_reason(state_dir: Path, monkeypatch):
    state.trip_pause(state_dir=state_dir, reason="manual via /pause")
    r = commands.parse_and_dispatch(
        "/status", handle=HANDLE, state_dir=state_dir,
    )
    assert "Paused" in r.reply
    assert "manual via /pause" in r.reply


def test_help_mentions_pause_resume(state_dir: Path):
    r = commands.parse_and_dispatch("/help", handle=HANDLE, state_dir=state_dir)
    assert "/pause" in r.reply
    assert "/resume" in r.reply


# --- /cost-today --------------------------------------------------------

def _fake_cfg(**overrides):
    base = {
        "daily_cost_cap_usd": 5.0,
        "project_directory": Path("/Users/sam/Desktop/Claude Homebase"),
        "session_aliases": {},
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def test_cost_today_with_no_spend(state_dir: Path):
    r = commands.parse_and_dispatch(
        "/cost-today", handle=HANDLE, state_dir=state_dir, cfg=_fake_cfg(),
    )
    assert "$0.00" in r.reply
    assert "$5.00" in r.reply
    assert "0.0%" in r.reply
    assert "$5.00 remaining" in r.reply
    assert "00:00 UTC" in r.reply


def test_cost_today_after_spend(state_dir: Path):
    state.add_cost_cents(123, state_dir=state_dir)  # $1.23
    r = commands.parse_and_dispatch(
        "/cost-today", handle=HANDLE, state_dir=state_dir, cfg=_fake_cfg(),
    )
    assert "$1.23" in r.reply
    # Spend is 24.6% of $5.00 cap. Formatted to 1 decimal.
    assert "24.6%" in r.reply
    assert "$3.77 remaining" in r.reply


def test_cost_today_no_cfg_falls_back_gracefully(state_dir: Path):
    state.add_cost_cents(50, state_dir=state_dir)
    r = commands.parse_and_dispatch(
        "/cost-today", handle=HANDLE, state_dir=state_dir,
    )
    assert "$0.50" in r.reply
    assert "cap unavailable" in r.reply


# --- /whoami -----------------------------------------------------------

def test_whoami_redacts_handle(state_dir: Path):
    r = commands.parse_and_dispatch(
        "/whoami", handle=HANDLE, state_dir=state_dir, cfg=_fake_cfg(),
    )
    # +15551234567 should be redacted to +15***67 form
    assert HANDLE not in r.reply
    assert "+15***67" in r.reply
    assert "Project dir:" in r.reply
    assert "Session: none" in r.reply


def test_whoami_with_active_session_no_alias(state_dir: Path, monkeypatch):
    state.set_current_session(HANDLE, "abcd1234-x", state_dir=state_dir)
    monkeypatch.setattr(
        session_discovery, "find_by_id",
        lambda sid: _mk_session(sid, snippet="x"),
    )
    r = commands.parse_and_dispatch(
        "/whoami", handle=HANDLE, state_dir=state_dir, cfg=_fake_cfg(),
    )
    assert "abcd1234" in r.reply
    assert "alias: none" in r.reply


def test_whoami_with_active_session_alias_match(state_dir: Path, monkeypatch):
    sid = "4fe39c70-21d7-467e-801b-ca3167ac130f"
    aliases = {"wesco": sid}
    state.set_current_session(HANDLE, sid, state_dir=state_dir)
    monkeypatch.setattr(
        session_discovery, "find_by_id",
        lambda s: _mk_session(s, snippet="x"),
    )
    r = commands.parse_and_dispatch(
        "/whoami", handle=HANDLE, state_dir=state_dir,
        aliases=aliases, cfg=_fake_cfg(),
    )
    assert "alias: wesco" in r.reply


def test_whoami_session_gone_from_disk(state_dir: Path, monkeypatch):
    state.set_current_session(HANDLE, "vanished-sid", state_dir=state_dir)
    monkeypatch.setattr(session_discovery, "find_by_id", lambda sid: None)
    r = commands.parse_and_dispatch(
        "/whoami", handle=HANDLE, state_dir=state_dir, cfg=_fake_cfg(),
    )
    assert "gone-from-disk" in r.reply


# --- /tail-audit -------------------------------------------------------

def test_tail_audit_empty(state_dir: Path):
    r = commands.parse_and_dispatch(
        "/tail-audit", handle=HANDLE, state_dir=state_dir,
    )
    assert "No audit events" in r.reply


def test_tail_audit_default_n_10(state_dir: Path):
    # Write 15 rows; default tail should show 10.
    for i in range(15):
        state.audit(
            handle_redacted=f"+15***{i:02d}",
            direction="in", kind="text",
            detail=f"event-{i}",
            chatdb_rowid=i, state_dir=state_dir,
        )
    r = commands.parse_and_dispatch(
        "/tail-audit", handle=HANDLE, state_dir=state_dir,
    )
    # Default 10 rows + header line
    assert "Last 10 audit events:" in r.reply
    assert r.reply.count("\n") == 10  # header + 10 rows = 11 lines, 10 \n


def test_tail_audit_custom_n(state_dir: Path):
    for i in range(5):
        state.audit(
            handle_redacted="+15***99", direction="in", kind="text",
            detail=f"e-{i}", chatdb_rowid=i, state_dir=state_dir,
        )
    r = commands.parse_and_dispatch(
        "/tail-audit 3", handle=HANDLE, state_dir=state_dir,
    )
    assert "Last 3 audit events:" in r.reply


def test_tail_audit_redacts_handles(state_dir: Path):
    """The handle_redacted column is already redacted by design; verify
    we don't accidentally expose raw handles."""
    raw_handle = "+15551234567"  # full E.164, must NOT appear
    state.audit(
        handle_redacted="+15***67",  # what the daemon stores
        direction="in", kind="text",
        detail="hello", chatdb_rowid=1, state_dir=state_dir,
    )
    r = commands.parse_and_dispatch(
        "/tail-audit", handle=HANDLE, state_dir=state_dir,
    )
    assert raw_handle not in r.reply
    assert "+15***67" in r.reply


def test_tail_audit_rejects_non_int(state_dir: Path):
    r = commands.parse_and_dispatch(
        "/tail-audit abc", handle=HANDLE, state_dir=state_dir,
    )
    assert "Not a number" in r.reply


def test_tail_audit_caps_huge_n(state_dir: Path):
    """N > 100 is capped to 100 to avoid huge replies."""
    for i in range(120):
        state.audit(
            handle_redacted="+15***99", direction="in", kind="text",
            detail=f"e-{i}", chatdb_rowid=i, state_dir=state_dir,
        )
    r = commands.parse_and_dispatch(
        "/tail-audit 9999", handle=HANDLE, state_dir=state_dir,
    )
    assert "Last 100 audit events:" in r.reply


def test_tail_audit_state_helper(state_dir: Path):
    """Direct test of state.tail_audit_rows."""
    for i in range(3):
        state.audit(
            handle_redacted="+15***00", direction="in", kind="text",
            detail=f"e{i}", chatdb_rowid=i, state_dir=state_dir,
        )
    rows = state.tail_audit_rows(2, state_dir=state_dir)
    assert len(rows) == 2
    # Newest first
    assert rows[0]["detail"] == "e2"
    assert rows[1]["detail"] == "e1"


def test_help_mentions_new_commands(state_dir: Path):
    r = commands.parse_and_dispatch("/help", handle=HANDLE, state_dir=state_dir)
    assert "/cost-today" in r.reply
    assert "/whoami" in r.reply
    assert "/tail-audit" in r.reply
    assert "/sources" in r.reply
    assert "/last" in r.reply
    assert "/halt" in r.reply


def test_help_advertises_natural_language(state_dir: Path):
    r = commands.parse_and_dispatch("/help", handle=HANDLE, state_dir=state_dir)
    # The non-developer-friendly framing.
    assert "Natural language" in r.reply


# --- /sources -----------------------------------------------------------

def test_sources_empty_when_no_memory_loaded(state_dir: Path, monkeypatch):
    """If daemon._last_memory_sources is empty, /sources says so."""
    from src import daemon as daemon_mod
    monkeypatch.setattr(daemon_mod, "_last_memory_sources", [])
    r = commands.parse_and_dispatch("/sources", handle=HANDLE, state_dir=state_dir)
    assert "No memory context" in r.reply


def test_sources_lists_loaded_files(state_dir: Path, monkeypatch):
    from src import daemon as daemon_mod
    monkeypatch.setattr(
        daemon_mod, "_last_memory_sources",
        [
            ("/Users/sam/.claude/CLAUDE.md", 5234),
            ("/Users/sam/.claude/memory/projects/wesco.md", 2841),
        ],
    )
    r = commands.parse_and_dispatch("/sources", handle=HANDLE, state_dir=state_dir)
    assert "CLAUDE.md" in r.reply
    assert "wesco.md" in r.reply
    assert "5,234 bytes" in r.reply
    assert "Total:" in r.reply


# --- /last --------------------------------------------------------------

def test_last_no_history(state_dir: Path):
    state.init_state_dir(state_dir)
    r = commands.parse_and_dispatch("/last", handle=HANDLE, state_dir=state_dir)
    assert "No claude calls" in r.reply


def test_last_reports_most_recent_claude_call(state_dir: Path):
    state.init_state_dir(state_dir)
    # Add a few audit rows; the most recent claude-reply should win.
    state.audit(
        handle_redacted="abc***", direction="in", kind="text",
        detail="ok", chatdb_rowid=1, state_dir=state_dir,
    )
    state.audit(
        handle_redacted="abc***", direction="out", kind="reply",
        detail="ok dur=1234ms cost_cents=5 sid=abc12345",
        reply_bytes=42, chatdb_rowid=1, cost_cents=5, state_dir=state_dir,
    )
    r = commands.parse_and_dispatch("/last", handle=HANDLE, state_dir=state_dir)
    assert "1234ms" in r.reply
    assert "$0.05" in r.reply
    assert "42" in r.reply  # reply_bytes


# --- /halt --------------------------------------------------------------

def test_halt_sets_flag(state_dir: Path):
    r = commands.parse_and_dispatch("/halt", handle=HANDLE, state_dir=state_dir)
    assert r.halt_after_send is True
    assert "Daemon halting" in r.reply
    assert "Terminal" in r.reply
