"""Tests for the daemon's pure decision/classification helpers.

The full daemon loop is integration-tested live. These unit tests cover
the small surface that's cleanly separable:
  - _decide: allowlist + group-chat acceptance
  - _classify: command-vs-text routing
  - _user_facing_error: error-category redaction (NEVER leak stderr or
    failure count)
"""

from __future__ import annotations

from types import SimpleNamespace


from src import daemon, imessage_reader


def _msg(handle: str, *, body: str = "hi", is_group: bool = False,
         chat_guid: str = "1:1") -> imessage_reader.Message:
    return imessage_reader.Message(
        rowid=1,
        chat_guid=chat_guid,
        is_group=is_group,
        sender_handle=handle,
        timestamp_iso="2024-01-01T00:00:00Z",
        body=body,
        body_truncated=False,
    )


def _cfg(*, allowlist=("+15551234567",), groups=()) -> SimpleNamespace:
    return SimpleNamespace(
        allowlist=list(allowlist),
        allowlist_set=set(allowlist),
        allow_group_chat_guids=list(groups),
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
