"""Tests for the /-command dispatcher.

The commands surface is the only path through which iMessage controls
session resume. Bad behavior here = the user resumes the wrong session and
sees content from someone else's transcript through their iMessage.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

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
