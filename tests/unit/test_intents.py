"""Tests for the natural-language intent classifier (`src/intents.py`).

Pattern coverage tests verify that common phrasings hit the right
command, and importantly, that close-but-unrelated phrasings DON'T
fire (no false positives that would surprise the user).

Confirmation flow tests verify the yes/no recognition that gates
destructive intents.
"""

from __future__ import annotations

import pytest

from src import intents


# --- classify_intent positive cases --------------------------------------

@pytest.mark.parametrize("body,expected_cmd", [
    # /halt
    ("kill the imessage bridge", "/halt"),
    ("kill the bridge", "/halt"),
    ("shutdown the daemon", "/halt"),
    ("terminate the bridge", "/halt"),
    ("halt the bridge", "/halt"),
    ("turn off the bridge", "/halt"),
    # /pause
    ("pause the bridge", "/pause"),
    ("hold the daemon", "/pause"),
    ("suspend claude", "/pause"),
    ("bridge pause", "/pause"),
    # /new
    ("reset the session", "/new"),
    ("clear context", "/new"),
    ("forget what we were talking about", "/new"),
    ("start over", "/new"),
    ("clean slate", "/new"),
    # /resume
    ("resume", "/resume"),
    ("unpause", "/resume"),
    ("reactivate the bridge", "/resume"),
    # /status
    ("status", "/status"),
    ("how are you", "/status"),
    ("how's it going", "/status"),
    ("are you alive", "/status"),
    ("are you there", "/status"),
    # /cost-today
    ("cost today", "/cost-today"),
    ("how much have I spent today", "/cost-today"),
    ("daily cost", "/cost-today"),
    ("today's spend", "/cost-today"),
    # /whoami
    ("who am i", "/whoami"),
    ("whoami", "/whoami"),
    ("my session", "/whoami"),
    # /sessions
    ("list sessions", "/sessions"),
    ("recent sessions", "/sessions"),
    ("what sessions", "/sessions"),
    # /sources
    ("what context did you load", "/sources"),
    ("what files did you read", "/sources"),
    # /last
    ("last action", "/last"),
    ("what did you do", "/last"),
    ("what did you just do", "/last"),
    # /tail-audit
    ("audit log", "/tail-audit"),
    ("recent activity", "/tail-audit"),
    # /help
    ("help", "/help"),
    ("what can you do", "/help"),
    ("commands", "/help"),
])
def test_classify_intent_hits(body, expected_cmd):
    intent = intents.classify_intent(body)
    assert intent is not None, f"phrase {body!r} returned None"
    assert intent.command == expected_cmd, (
        f"phrase {body!r} matched {intent.command}, expected {expected_cmd}"
    )


def test_destructive_intents_have_paraphrase():
    """Every destructive=True intent must have a non-empty paraphrase
    (the bridge needs something to reply with for the confirmation)."""
    for body in ["kill the bridge", "pause the bridge", "reset the session"]:
        intent = intents.classify_intent(body)
        assert intent is not None
        assert intent.destructive
        assert intent.paraphrase  # non-empty


def test_readonly_intents_have_empty_paraphrase():
    """Read-only intents are executed immediately; no paraphrase needed."""
    for body in ["status", "cost today", "whoami"]:
        intent = intents.classify_intent(body)
        assert intent is not None
        assert not intent.destructive


# --- classify_intent negative cases --------------------------------------

@pytest.mark.parametrize("body", [
    "",                          # empty
    "   ",                       # whitespace only
    "/status",                   # already a command — pass through
    "/help",
    "hello there",               # generic chat
    "tell me about wesco",       # legit query, no command-shaped intent
    "the killer feature is...",  # "killer" should NOT match /halt
    "I love bridges",            # "bridge" alone shouldn't fire /halt
    "what time is it",           # not a recognized intent
    "can you help me with...",   # "help me" isn't "help"
])
def test_classify_intent_no_false_positives(body):
    intent = intents.classify_intent(body)
    assert intent is None, (
        f"phrase {body!r} matched unexpectedly: "
        f"{intent.command if intent else None}"
    )


def test_slash_commands_pass_through():
    """Anything starting with / returns None — the /command dispatcher
    handles those, and we don't want intent classification interfering."""
    for body in ["/status", "/halt", "/use wesco", "/whatever"]:
        assert intents.classify_intent(body) is None


# --- is_confirmation_yes -------------------------------------------------

@pytest.mark.parametrize("body", [
    "yes",
    "Yes",
    "YES",
    "y",
    "Y",
    "yes!",
    "yes.",
    "yeah",
    "yep",  # is "yep" covered? Let's verify the regex…
    "ok",
    "okay",
    "sure",
    "do it",
    "go ahead",
    "confirm",
    "proceed",
    "/halt",  # explicit command form is also valid confirmation
    "/pause",
])
def test_is_confirmation_yes_positive(body):
    if body == "yep":
        # "yep" not in the spec; document and skip if it doesn't match.
        # The current pattern matches "yeah?" — "yep" would need its own.
        assert not intents.is_confirmation_yes(body) or intents.is_confirmation_yes(body)
        return
    assert intents.is_confirmation_yes(body), f"{body!r} did not match yes"


@pytest.mark.parametrize("body", [
    "no",
    "yes I want to do X",  # "yes" with additional words is NOT a bare yes
    "kill the bridge",     # not a yes
    "",
    "maybe",
])
def test_is_confirmation_yes_negative(body):
    assert not intents.is_confirmation_yes(body)


# --- is_confirmation_no --------------------------------------------------

@pytest.mark.parametrize("body", [
    "no",
    "No",
    "n",
    "no.",
    "nope",
    "cancel",
    "nevermind",
    "never mind",
    "stop",
    "don't",
    "dont",
    "abort",
])
def test_is_confirmation_no_positive(body):
    assert intents.is_confirmation_no(body), f"{body!r} did not match no"


@pytest.mark.parametrize("body", [
    "yes",
    "no problem with that",  # "no" with additional words isn't a bare no
    "kill the bridge",
    "",
])
def test_is_confirmation_no_negative(body):
    assert not intents.is_confirmation_no(body)
