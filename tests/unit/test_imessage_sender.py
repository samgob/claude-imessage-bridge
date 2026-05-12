"""Tests for the iMessage send path.

The send path crosses an AppleScript boundary. Two security-critical
properties:
  - argv-only AppleScript: nothing in the body or handle can re-enter the
    AppleScript source via shell interpolation or string concatenation.
  - Display-attack stripping: BiDi/zero-width/control chars are removed
    so what the recipient sees matches what we logged.
"""

from __future__ import annotations

import subprocess
from unittest import mock

import pytest

from src import imessage_sender


# --- validate_handle ----------------------------------------------------

@pytest.mark.parametrize("good", [
    "+15551234567",
    "+447911123456",
    "user@example.com",
    "first.last+tag@sub.example.co",
])
def test_validate_handle_accepts_valid_formats(good):
    out = imessage_sender.validate_handle(good)
    assert out  # non-empty


def test_validate_handle_lowercases_email():
    assert imessage_sender.validate_handle("User@Example.COM") == "user@example.com"


def test_validate_handle_preserves_phone_case_unchanged():
    assert imessage_sender.validate_handle("+15551234567") == "+15551234567"


@pytest.mark.parametrize("bad", [
    "",
    "5551234567",          # missing +
    "+0123456789",         # leading 0 after +
    "+1 555 123 4567",     # spaces
    "user@@example.com",   # double @
    "user@nope",           # no TLD
    "user @example.com",   # internal space
    "user\nname@x.com",    # newline
    "user@x.c",            # short TLD
])
def test_validate_handle_rejects_bad_formats(bad):
    with pytest.raises(imessage_sender.HandleError):
        imessage_sender.validate_handle(bad)


def test_validate_handle_rejects_non_string():
    with pytest.raises(imessage_sender.HandleError):
        imessage_sender.validate_handle(12345)  # type: ignore[arg-type]


def test_validate_handle_strips_whitespace():
    assert imessage_sender.validate_handle("  +15551234567  ") == "+15551234567"


# --- Display attack stripping ------------------------------------------

def test_strip_display_attacks_removes_bidi():
    body = "Hello ‮ world"  # RTL override
    out = imessage_sender._strip_display_attacks(body)
    assert "‮" not in out
    assert "Hello " in out


def test_strip_display_attacks_removes_zero_width():
    body = "vi​si‌bly‍gapped﻿"
    out = imessage_sender._strip_display_attacks(body)
    assert out == "visiblygapped"


def test_strip_display_attacks_removes_c0_controls_except_tnr():
    # Tab, newline, CR preserved; bell, vertical tab, formfeed stripped
    body = "a\tb\nc\rd\x07e\x0bf\x0cg"
    out = imessage_sender._strip_display_attacks(body)
    assert "\t" in out
    assert "\n" in out
    assert "\r" in out
    assert "\x07" not in out
    assert "\x0b" not in out
    assert "\x0c" not in out


def test_strip_display_attacks_removes_c1_controls():
    body = "before\x82after"
    out = imessage_sender._strip_display_attacks(body)
    assert "\x82" not in out


def test_strip_display_attacks_preserves_normal_unicode():
    body = "café 日本語 🎉"
    out = imessage_sender._strip_display_attacks(body)
    assert out == body


# --- Truncation --------------------------------------------------------

def test_truncate_short_body_unchanged():
    body = "hi there"
    assert imessage_sender._truncate(body) == body


def test_truncate_long_body_capped():
    body = "A" * (imessage_sender.MAX_REPLY_BYTES + 100)
    out = imessage_sender._truncate(body)
    assert len(out.encode("utf-8")) <= imessage_sender.MAX_REPLY_BYTES + len(
        "\n…[truncated]".encode("utf-8")
    )
    assert out.endswith("[truncated]")


def test_truncate_safe_utf8_boundary():
    """Never split a multibyte character mid-bytes."""
    body = "é" * (imessage_sender.MAX_REPLY_BYTES // 2 + 10)
    out = imessage_sender._truncate(body)
    # Must decode cleanly.
    out.encode("utf-8").decode("utf-8")


# --- send() argv shape -------------------------------------------------

def test_send_uses_argv_form(monkeypatch):
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(imessage_sender.subprocess, "run", fake_run)
    imessage_sender.send(
        imessage_sender.SendRequest(handle="+15551234567", body="hi"),
    )
    argv = captured["argv"]
    # Must be: osascript -e <script> -- <handle> <body>
    assert argv[0] == imessage_sender._OSASCRIPT_BIN
    assert argv[1] == "-e"
    assert argv[3] == "--"
    assert argv[4] == "+15551234567"
    assert argv[5] == "hi"


def test_send_never_uses_shell(monkeypatch):
    captured = {}

    def fake_run(argv, **kwargs):
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(imessage_sender.subprocess, "run", fake_run)
    imessage_sender.send(
        imessage_sender.SendRequest(handle="+15551234567", body="hi"),
    )
    # subprocess.run kwargs must not contain shell=True
    assert captured["kwargs"].get("shell") is None or captured["kwargs"]["shell"] is False


def test_send_re_validates_handle(monkeypatch):
    monkeypatch.setattr(
        imessage_sender.subprocess, "run",
        lambda *a, **kw: subprocess.CompletedProcess(a, 0),
    )
    # SendRequest is a frozen dataclass; bypass to test defense-in-depth.
    bad = imessage_sender.SendRequest(handle="not-a-handle", body="hi")
    with pytest.raises(imessage_sender.HandleError):
        imessage_sender.send(bad)


def test_send_strips_bidi_from_body(monkeypatch):
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(imessage_sender.subprocess, "run", fake_run)
    imessage_sender.send(
        imessage_sender.SendRequest(handle="+15551234567", body="hi ‮ world"),
    )
    sent_body = captured["argv"][5]
    assert "‮" not in sent_body


def test_send_skips_empty_body(monkeypatch):
    called = {"count": 0}

    def fake_run(argv, **kwargs):
        called["count"] += 1
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(imessage_sender.subprocess, "run", fake_run)
    imessage_sender.send(
        imessage_sender.SendRequest(handle="+15551234567", body="   "),
    )
    # Whitespace-only body must not invoke osascript.
    assert called["count"] == 0


def test_send_dry_run_skips_subprocess(monkeypatch):
    called = {"count": 0}

    def fake_run(argv, **kwargs):
        called["count"] += 1
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(imessage_sender.subprocess, "run", fake_run)
    imessage_sender.send(
        imessage_sender.SendRequest(handle="+15551234567", body="hi"),
        dry_run=True,
    )
    assert called["count"] == 0


def test_send_raises_on_osascript_failure(monkeypatch):
    def fake_run(argv, **kwargs):
        return subprocess.CompletedProcess(
            argv, returncode=1, stdout="", stderr="execution error"
        )

    monkeypatch.setattr(imessage_sender.subprocess, "run", fake_run)
    with pytest.raises(imessage_sender.SendError):
        imessage_sender.send(
            imessage_sender.SendRequest(handle="+15551234567", body="hi"),
        )


# --- Handle redaction --------------------------------------------------

def test_redact_handle_email_masks_local():
    out = imessage_sender._redact_handle("samuel.gobrail@example.com")
    assert "samuel" not in out
    assert out.startswith("sa")
    assert "@example.com" in out


def test_redact_handle_phone_masks_middle():
    out = imessage_sender._redact_handle("+15551234567")
    assert "555" not in out
    assert "1234" not in out
    assert out.startswith("+15")
    assert out.endswith("67")


def test_redact_handle_short_input():
    out = imessage_sender._redact_handle("x")
    assert out == "***"
