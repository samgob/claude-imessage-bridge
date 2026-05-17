"""Tests for the daemon's pure decision/classification helpers.

The full daemon loop is integration-tested live. These unit tests cover
the small surface that's cleanly separable:
  - _decide: allowlist + group-chat acceptance
  - _classify: command-vs-text routing
  - _user_facing_error: error-category redaction (NEVER leak stderr or
    failure count)
"""

from __future__ import annotations

import argparse
from types import SimpleNamespace


from src import daemon, imessage_reader


def _msg(handle: str, *, body: str = "hi", is_group: bool = False,
         chat_guid: str = "1:1", has_attachment: bool = False,
         ) -> imessage_reader.Message:
    return imessage_reader.Message(
        rowid=1,
        chat_guid=chat_guid,
        is_group=is_group,
        sender_handle=handle,
        timestamp_iso="2024-01-01T00:00:00Z",
        body=body,
        body_truncated=False,
        has_attachment=has_attachment,
    )


def _cfg(*, allowlist=("+15551234567",), groups=()) -> SimpleNamespace:
    return SimpleNamespace(
        allowlist=list(allowlist),
        allowlist_set=set(allowlist),
        allow_group_chat_guids=list(groups),
        debug=False,
        reply_rate_limit_per_minute=10,
    )


# --- _decide -----------------------------------------------------------

def test_decide_accepts_allowlisted():
    accept, reason = daemon._decide(_msg("+15551234567"), _cfg())
    assert accept
    assert reason == "ok"


def test_decide_rejects_non_allowlisted():
    accept, reason = daemon._decide(_msg("+15559999999"), _cfg())
    assert not accept
    assert reason == "sender-not-allowlisted"


def test_decide_rejects_invalid_handle_format():
    accept, reason = daemon._decide(_msg("not-a-handle"), _cfg())
    assert not accept
    assert reason == "invalid-handle-format"


def test_decide_rejects_group_chat_by_default():
    accept, reason = daemon._decide(
        _msg("+15551234567", is_group=True, chat_guid="group-1"),
        _cfg(),
    )
    assert not accept
    assert reason == "group-chat-not-opted-in"


def test_decide_accepts_opted_in_group():
    accept, reason = daemon._decide(
        _msg("+15551234567", is_group=True, chat_guid="group-1"),
        _cfg(groups=("group-1",)),
    )
    assert accept


def test_decide_normalizes_email_case():
    """Case-folded email in chat.db must still match a normalized allowlist."""
    accept, reason = daemon._decide(
        _msg("USER@example.COM"),
        _cfg(allowlist=("user@example.com",)),
    )
    assert accept


# --- _classify ---------------------------------------------------------

def test_classify_command():
    assert daemon._classify("/help") == "command"
    assert daemon._classify("/sessions --all") == "command"


def test_classify_text():
    assert daemon._classify("hello") == "text"
    assert daemon._classify("") == "text"


# --- _user_facing_error: redaction ------------------------------------

def test_user_facing_error_never_leaks_failure_count():
    """The user-facing error message must NOT include a number that would
    let an attacker probe the circuit-breaker threshold."""
    for cat in ("timeout", "exec_error", "json_parse", "claude_error", None, "unknown"):
        msg = daemon._user_facing_error(cat)
        # No digits 0-9 should appear; the user message is purely descriptive.
        assert not any(c.isdigit() for c in msg), (
            f"category {cat!r} returned {msg!r} — leaks a number"
        )


def test_user_facing_error_returns_canned_strings():
    assert "timed out" in daemon._user_facing_error("timeout")
    assert "Couldn't run" in daemon._user_facing_error("exec_error")
    assert "malformed" in daemon._user_facing_error("json_parse")
    assert "Claude reported" in daemon._user_facing_error("claude_error")


def test_user_facing_error_unknown_category_falls_back():
    assert "unavailable" in daemon._user_facing_error("nonsense")
    assert "unavailable" in daemon._user_facing_error(None)


# --- _normalize_for_allowlist -----------------------------------------

def test_normalize_for_allowlist_email_lowercased():
    assert daemon._normalize_for_allowlist("User@Example.COM") == "user@example.com"


def test_normalize_for_allowlist_phone_passthrough():
    assert daemon._normalize_for_allowlist("+15551234567") == "+15551234567"


def test_normalize_for_allowlist_invalid_returns_empty():
    assert daemon._normalize_for_allowlist("garbage") == ""


# --- Audit-row redaction regression (round-4 adversarial finding) ------

def test_self_send_echo_recorded_and_detected():
    """Track outbound bodies in the in-memory ring; the same (handle, body)
    coming back inbound (via iCloud Messages sync to the user's other
    device) must be detected and skipped."""
    # Reset the ring deterministically.
    daemon._recent_self_sends.clear()

    handle = "+15551234567"
    body = "Hey Sam! How can I help you today?"
    assert not daemon._is_recent_self_send(handle, body)

    daemon._record_self_send(handle, body)
    assert daemon._is_recent_self_send(handle, body)
    # Different handle must NOT collide on body hash.
    assert not daemon._is_recent_self_send("+15559999999", body)
    # Different body must NOT collide on handle.
    assert not daemon._is_recent_self_send(handle, body + " extra")


def test_self_send_echo_ttl_expires(monkeypatch):
    """An echo recorded long enough ago must NOT count as a self-send."""
    daemon._recent_self_sends.clear()
    handle = "+15551234567"
    body = "ok"
    daemon._record_self_send(handle, body)
    assert daemon._is_recent_self_send(handle, body)

    # Pretend time advanced past the TTL.
    real_time = daemon.time.time
    monkeypatch.setattr(
        daemon.time, "time",
        lambda: real_time() + daemon.RECENT_SELF_SEND_TTL_SECONDS + 1,
    )
    assert not daemon._is_recent_self_send(handle, body)


def test_self_send_ring_bounded():
    """The ring buffer is bounded so a long-running daemon doesn't grow
    memory without bound."""
    daemon._recent_self_sends.clear()
    handle = "+15551234567"
    for i in range(daemon.RECENT_SELF_SEND_CAP + 50):
        daemon._record_self_send(handle, f"msg {i}")
    assert len(daemon._recent_self_sends) <= daemon.RECENT_SELF_SEND_CAP


def test_dedupe_handles_smart_quotes():
    """Regression: 2026-05-15 loop. iMessage autocorrect rewrites ASCII
    quotes to curly quotes between send and iCloud sync-echo. Without
    normalization, the echo doesn't match and we reply to our own reply.
    """
    daemon._recent_self_sends.clear()
    handle = "+15551234567"
    sent = "Yes, I'll handle the \"peptides\" log update."
    daemon._record_self_send(handle, sent)
    # iCloud echoed back with curly quotes / em-dash
    echoed = "Yes, I’ll handle the “peptides” log update."
    assert daemon._is_recent_self_send(handle, echoed)


def test_dedupe_handles_whitespace_variation():
    """Whitespace runs and trailing newlines must not defeat dedupe."""
    daemon._recent_self_sends.clear()
    handle = "+15551234567"
    daemon._record_self_send(handle, "hello   world")
    assert daemon._is_recent_self_send(handle, "hello world")
    assert daemon._is_recent_self_send(handle, "hello world\n")
    assert daemon._is_recent_self_send(handle, "  hello\tworld  ")


def test_dedupe_handles_case_difference():
    """Some devices capitalize sentence starts; dedupe should be case-insensitive."""
    daemon._recent_self_sends.clear()
    handle = "+15551234567"
    daemon._record_self_send(handle, "okay, on it")
    assert daemon._is_recent_self_send(handle, "Okay, on it")
    assert daemon._is_recent_self_send(handle, "OKAY, ON IT")


def test_dedupe_em_dash_normalized():
    """Em-dashes (autocorrected from `--`) must not break dedupe."""
    daemon._recent_self_sends.clear()
    handle = "+15551234567"
    daemon._record_self_send(handle, "running tests -- back soon")
    assert daemon._is_recent_self_send(handle, "running tests — back soon")
    assert daemon._is_recent_self_send(handle, "running tests – back soon")


# --- Outbound-rate auto-PAUSE safety net --------------------------------

class _PauseSpy:
    """Drop-in replacement for state.trip_pause that records calls."""
    def __init__(self):
        self.calls: list = []
    def __call__(self, *args, **kwargs):
        self.calls.append(kwargs.get("reason", ""))


def test_outbound_rate_pause_trips_after_threshold(monkeypatch):
    """Regression: 2026-05-15 overnight loop. >6 outbound sends to the
    same handle inside 60s must trip the PAUSE file, killing the reply
    pipeline before the daily cost cap is exhausted.
    """
    spy = _PauseSpy()
    monkeypatch.setattr(daemon.state, "trip_pause", spy)
    daemon._recent_self_sends.clear()
    daemon._recent_outbound.clear()
    handle = "+15551234567"
    # 6 sends — under threshold, no trip.
    for i in range(daemon.OUTBOUND_PAUSE_THRESHOLD):
        daemon._record_self_send(handle, f"reply {i}")
    assert spy.calls == []
    # 7th send — trips.
    daemon._record_self_send(handle, "reply 7")
    assert len(spy.calls) == 1
    assert "outbound rate exceeded" in spy.calls[0]


def test_outbound_rate_per_handle_isolated(monkeypatch):
    """Bursts to different handles should not aggregate."""
    spy = _PauseSpy()
    monkeypatch.setattr(daemon.state, "trip_pause", spy)
    daemon._recent_self_sends.clear()
    daemon._recent_outbound.clear()
    # Alternate handles, 5 each — neither crosses threshold alone.
    for i in range(5):
        daemon._record_self_send("+15551111111", f"a{i}")
        daemon._record_self_send("+15552222222", f"b{i}")
    assert spy.calls == []


def test_outbound_rate_window_slides(monkeypatch):
    """Old sends outside the window are pruned and shouldn't count."""
    import time as _time
    spy = _PauseSpy()
    monkeypatch.setattr(daemon.state, "trip_pause", spy)
    daemon._recent_self_sends.clear()
    daemon._recent_outbound.clear()
    handle = "+15551234567"
    # Backdate 6 sends so they fall outside the window.
    old_t = _time.time() - daemon.OUTBOUND_PAUSE_WINDOW_SECONDS - 5
    for i in range(6):
        daemon._recent_outbound.append((old_t, handle))
    # A fresh send: only 1 in-window, no trip.
    daemon._record_self_send(handle, "fresh")
    assert spy.calls == []


def test_outbound_rate_does_not_leak_raw_handle(monkeypatch):
    """The PAUSE reason must use a redacted handle, not the raw phone
    number (the PAUSE file persists on disk and shouldn't reveal PII)."""
    spy = _PauseSpy()
    monkeypatch.setattr(daemon.state, "trip_pause", spy)
    daemon._recent_self_sends.clear()
    daemon._recent_outbound.clear()
    handle = "+15551234567"
    for i in range(daemon.OUTBOUND_PAUSE_THRESHOLD + 1):
        daemon._record_self_send(handle, f"reply {i}")
    assert len(spy.calls) >= 1
    assert handle not in spy.calls[0]  # raw handle must not appear


def test_audit_failure_detail_string_redacted():
    """The audit detail string for a claude failure MUST NOT contain the
    raw error string or the consecutive-failure count.

    This is the round-4 adversarial finding: state.db is documented as not
    containing internal error paths or the circuit-breaker threshold. The
    daemon failure-path code constructs the detail string locally; a future
    refactor that re-adds ``consec=`` or ``raw=`` would silently violate
    THREAT_MODEL S8 + SECURITY.md CVE policy. This test guards that.
    """
    # Inline the string-shape this test asserts. We're not running the
    # daemon — we're verifying that the source-of-truth string template
    # in daemon.py does NOT include the forbidden tokens.
    import inspect

    source = inspect.getsource(daemon._handle_one)
    # The success-path detail intentionally has cost_cents/sid; that's
    # fine and documented. Look for the failure-path template.
    # The forbidden tokens MUST NOT appear in the audit detail builder
    # for failure rows.
    assert "consec=" not in source or "consec=%d" in source, (
        "audit_log.detail leaks consecutive-failure count — must move to logger"
    )
    assert "raw={result.error" not in source, (
        "audit_log.detail leaks raw error string — must move to logger"
    )
    assert "raw=%r" in source, (
        "expected the raw error to be logged server-side via logger.warning"
    )


# --- --skip-selftest dev flag ------------------------------------------

def _parser_for_skip_selftest_test():
    """Reconstruct the daemon's argparse for the parsing-only tests."""
    parser = argparse.ArgumentParser(prog="imessage-bridge")
    parser.add_argument("--config")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--reset-cursor", action="store_true")
    parser.add_argument("--skip-selftest", action="store_true")
    return parser


def test_skip_selftest_accepted_interactive(monkeypatch, tmp_path, fake_claude_binary):
    """When stdin is a tty, --skip-selftest is parsed cleanly. We don't
    boot the full daemon (network, signals, etc.) — we just verify the
    flag landed in args and is honored by the same conditional branch."""
    args = _parser_for_skip_selftest_test().parse_args(["--skip-selftest"])
    assert args.skip_selftest is True

    # Confirm the daemon's source carries the tty guard for the flag. The
    # behavior is tested via the not-a-tty case below; this guards against
    # a future refactor that removes the guard entirely.
    import inspect
    source = inspect.getsource(daemon.main)
    assert "skip_selftest" in source
    assert "isatty" in source
    assert "SELFTEST SKIPPED" in source


def test_skip_selftest_refused_when_not_tty(monkeypatch, tmp_path, fake_claude_binary):
    """Refuse --skip-selftest when stdin is not a tty — protects against
    accidental embedding in a launchd plist / systemd unit / cron job."""
    # Write a minimal valid config so load() succeeds.
    import yaml
    project = tmp_path / "proj"
    project.mkdir()
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(yaml.safe_dump({
        "project_directory": str(project),
        "allowlist": ["+15551234567"],
        "allow_group_chat_guids": [],
        "allowed_tools": [],
        "forbidden_tools": [],
        "poll_interval_seconds": 3.0,
        "reply_rate_limit_per_minute": 10,
        "daily_cost_cap_usd": 5.0,
        "per_call_cost_cap_usd": 0.50,
        "per_call_max_turns": 1,
        "per_call_timeout_seconds": 90,
        "circuit_breaker_failures": 5,
        "claude_binary": str(fake_claude_binary),
        "debug": False,
    }))

    # Point state.DEFAULT_STATE_DIR at a tmp dir so init_state_dir doesn't
    # touch the real ~/.claude-imessage-bridge/.
    monkeypatch.setattr(daemon.state, "DEFAULT_STATE_DIR", tmp_path / "state")

    # Stub preflight (it touches osascript path) so we reach the
    # skip-selftest branch.
    monkeypatch.setattr(daemon, "_preflight", lambda _sd: None)

    # Force stdin.isatty() False to simulate launchd/systemd.
    monkeypatch.setattr(daemon.sys.stdin, "isatty", lambda: False)

    rc = daemon.main(["--config", str(cfg_path), "--skip-selftest"])
    assert rc == 6


# --- Pause refactor: claude path gated, command path not -------------

def test_read_pause_reason_returns_first_line(tmp_path):
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    (state_dir / "PAUSE").write_text("manual via /pause\nextra context line\n")
    assert daemon._read_pause_reason(state_dir) == "manual via /pause"


def test_read_pause_reason_empty_when_absent(tmp_path):
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    assert daemon._read_pause_reason(state_dir) == ""


def test_daemon_main_loop_no_longer_top_level_pause_check():
    """Regression guard. The top-of-loop ``if _is_paused`` short-circuit was
    removed so command dispatch (incl. /resume) still runs while paused.
    If a future refactor restores it, /resume becomes unreachable via
    iMessage — guard the refactor with this test."""
    import inspect
    source = inspect.getsource(daemon.main)
    # The string "PAUSE file present, idling" used to be the top-of-loop
    # log line. Its absence is the invariant we care about.
    assert "PAUSE file present, idling" not in source, (
        "Top-of-loop pause short-circuit was re-added — that breaks "
        "/resume reachability over iMessage. The pause check should "
        "live inside _handle_one, gating only the claude-invocation path."
    )


# --- Image / attachment ack path ---------------------------------------

class _SendSpy:
    def __init__(self):
        self.sent: list = []

    def __call__(self, request, *, dry_run=False):
        self.sent.append((request.handle, request.body, dry_run))


def _stub_state_for_handle_one(monkeypatch):
    """Stub the state-layer side effects so _handle_one can run without
    a real state.db. Returns nothing — caller still patches sender/etc."""
    monkeypatch.setattr(daemon.state, "audit", lambda **_: None)
    monkeypatch.setattr(
        daemon.state, "reserve_reply_slot", lambda handle, limit: (True, 1),
    )
    monkeypatch.setattr(daemon.state, "get_pending_intent", lambda handle: None)
    monkeypatch.setattr(daemon.state, "clear_pending_intent", lambda handle: None)
    monkeypatch.setattr(daemon.state, "trip_pause", lambda **_: None)


def test_image_only_message_gets_polite_ack(monkeypatch):
    """Regression: 2026-05-17 — Sam reported no response when sending
    images. Image-only rows now reach the daemon (instead of being
    dropped at SQL) and produce a polite ack instead of silence."""
    _stub_state_for_handle_one(monkeypatch)
    daemon._recent_self_sends.clear()
    daemon._recent_outbound.clear()
    spy = _SendSpy()
    monkeypatch.setattr(daemon.imessage_sender, "send", spy)

    msg = _msg("+15551234567", body="", has_attachment=True)
    daemon._handle_one(msg, _cfg())

    assert len(spy.sent) == 1
    handle, body, _ = spy.sent[0]
    assert handle == "+15551234567"
    assert "attachment" in body.lower() or "image" in body.lower()
    assert "📎" in body


def test_image_with_caption_does_not_ack(monkeypatch):
    """Captions should be processed as normal text, not trigger the
    image-only ack. (The body has real intent; downstream code can
    route it to claude or commands.)"""
    _stub_state_for_handle_one(monkeypatch)
    # Stub the claude-call path so we don't actually invoke claude or
    # any downstream code; we just need to verify the image-ack short-
    # circuit did NOT fire.
    daemon._recent_self_sends.clear()
    daemon._recent_outbound.clear()
    spy = _SendSpy()
    monkeypatch.setattr(daemon.imessage_sender, "send", spy)
    # Short-circuit everything after the image-ack check by patching the
    # pause + claude paths. We don't care what happens after, just that
    # the image-ack reply text didn't go out.
    monkeypatch.setattr(daemon, "_is_paused", lambda _sd: True)

    msg = _msg("+15551234567", body="caption text", has_attachment=True)
    daemon._handle_one(msg, _cfg())

    # If anything was sent, it must NOT be the image-only ack text.
    for _, body, _ in spy.sent:
        assert "I can't process images" not in body


def test_text_only_message_does_not_trigger_ack(monkeypatch):
    """Sanity: a plain text message (no attachment) doesn't accidentally
    trigger the image-ack path."""
    _stub_state_for_handle_one(monkeypatch)
    daemon._recent_self_sends.clear()
    daemon._recent_outbound.clear()
    spy = _SendSpy()
    monkeypatch.setattr(daemon.imessage_sender, "send", spy)
    monkeypatch.setattr(daemon, "_is_paused", lambda _sd: True)

    msg = _msg("+15551234567", body="hello", has_attachment=False)
    daemon._handle_one(msg, _cfg())

    for _, body, _ in spy.sent:
        assert "📎" not in body
