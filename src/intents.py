"""Natural-language intent classifier with confirmation flow.

The bridge's ``/command`` UX is developer-grade. A non-developer user
won't remember ``/halt`` or ``/cost-today`` — they'll say "kill the
bridge" or "how much have I spent today." This module maps natural-
language phrasings to the appropriate slash command.

**Pattern-based, deterministic, no LLM.** A regex matcher is fast (free
per message), testable (each pattern gets a test), and crucially
NOT prompt-injectable — a regex can't be tricked into reclassifying.
LLM-based intent classification would add a step where attacker-
controlled text gets reasoned over by a model BEFORE the bridge's deny
list applies, which is exactly the kind of layer we don't want.

Trade-off: misses paraphrases the patterns don't cover. Cost of a miss
is low — the message falls through to normal claude chat. After live
use, missed phrasings get added to the patterns.

**Confirmation flow.** Destructive intents (``/halt``, ``/pause``,
``/new``) don't execute immediately. The classifier returns the intent
and the bridge stashes it as a 60s-TTL ``pending_intent`` in state.db,
replies with a paraphrase ("Halt the daemon? Reply 'yes' to confirm."),
and waits. The next message from that handle is matched against
``is_confirmation_yes`` / ``is_confirmation_no`` to either execute the
stored command or cancel.

Read-only intents (``/status``, ``/cost-today``, ``/whoami``, etc.)
execute immediately — the friction-vs-safety tradeoff is different.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class IntentMatch:
    """A classified natural-language intent.

    ``command`` is the slash command this maps to (e.g. ``"/halt"``).
    ``destructive`` controls whether confirmation is required before
    execution. ``paraphrase`` is the bridge's reply when destructive=True;
    ignored otherwise.
    ``extra_arg`` is an optional argument captured from the body (e.g.
    for a future ``/use <alias>`` intent that wants to extract the alias
    name from "switch to myproject").
    """

    command: str
    destructive: bool
    paraphrase: str
    extra_arg: str = ""


# Pattern definitions. Order matters — earlier entries win on ambiguous
# phrasings. Each pattern is a regex; matching is case-insensitive
# (``re.IGNORECASE`` applied at classify time, not bake into pattern).
#
# Patterns are deliberately conservative: they require named tokens to
# avoid catastrophic false positives like "kill the noise" matching the
# halt intent. Live-tuned over time as we observe missed phrasings.

_INTENTS: List[dict] = [
    # --- Destructive: require confirmation -----------------------------
    {
        "command": "/halt",
        "destructive": True,
        "paraphrase": (
            "Halt the daemon? You'll need to restart from Terminal — "
            "the bridge exits and won't auto-recover. Reply 'yes' to "
            "confirm, anything else cancels."
        ),
        "patterns": [
            r"\b(kill|halt|shutdown?|terminate)\b.*\b(bridge|daemon|service|imessage)\b",
            r"\b(bridge|daemon|service|imessage)\b.*\b(kill|halt|shutdown?|terminate)\b",
            r"\bturn (it )?off\b.*\b(bridge|daemon)\b",
        ],
    },
    {
        "command": "/pause",
        "destructive": True,
        "paraphrase": (
            "Pause the bridge? Claude calls will be suspended until you "
            "say resume. Reply 'yes' to confirm."
        ),
        "patterns": [
            r"\b(pause|hold|suspend)\b.*\b(bridge|daemon|imessage|claude|messages)\b",
            r"\b(bridge|daemon|claude)\b.*\b(pause|suspend)\b",
        ],
    },
    {
        "command": "/new",
        "destructive": True,
        "paraphrase": (
            "Start a fresh session (lose the current thread)? Reply " "'yes' to confirm."
        ),
        "patterns": [
            r"\b(reset|clear|forget|new)\b.*\b(session|context|chat|conversation|thread)\b",
            r"\bforget what we (were|are) talking\b",
            r"\bstart (over|fresh|new)\b",
            r"\bclean slate\b",
        ],
    },
    # --- Restorative: light/no confirmation ----------------------------
    {
        "command": "/resume",
        "destructive": False,
        "paraphrase": "",
        "patterns": [
            r"\bunpause\b",
            r"\b(resume|reactivate)\b.*\b(bridge|daemon|claude|messages)\b",
            r"\b(bridge|daemon|claude)\b.*\bresume\b",
            r"^\s*resume\s*$",
        ],
    },
    # --- Read-only: execute immediately, no confirmation ---------------
    {
        "command": "/status",
        "destructive": False,
        "paraphrase": "",
        "patterns": [
            # Bare "status" or "status?" — alone on a line, not embedded
            # in something like "myproject status" or "deploy status."
            r"^\s*status\??\s*$",
            # Explicit "bridge/daemon/claude status"
            r"\b(bridge|daemon|claude) status\b",
            r"\bstatus of (the )?(bridge|daemon|claude)\b",
            # Conversational openings
            r"^\s*how are you\b",
            r"^\s*how'?s it going\b",
            r"\bare you (alive|up|running|working|ok)\b",
            r"\bare you there\b",
        ],
    },
    {
        "command": "/cost-today",
        "destructive": False,
        "paraphrase": "",
        "patterns": [
            r"\b(cost|spend|spending|usage|bill|billed)\b.*\b(today|so far|day)\b",
            r"\bhow much\b.*\b(spent|cost|spending)\b",
            r"\b(daily|today'?s) (cost|spend|usage)\b",
        ],
    },
    {
        "command": "/whoami",
        "destructive": False,
        "paraphrase": "",
        "patterns": [
            r"\bwho am i\b",
            r"\bwhoami\b",
            r"\bmy (handle|session|alias|number)\b",
            r"\bwhat session am i\b",
        ],
    },
    {
        "command": "/sessions",
        "destructive": False,
        "paraphrase": "",
        "patterns": [
            r"\b(list|show) sessions\b",
            r"\brecent sessions\b",
            r"\bwhat sessions\b",
            r"\bsessions\?\s*$",
        ],
    },
    {
        "command": "/sources",
        "destructive": False,
        "paraphrase": "",
        "patterns": [
            r"\b(what (context|files|sources)|what did you load|sources)\b",
            r"\bwhich files did you (read|see|load)\b",
        ],
    },
    {
        "command": "/last",
        "destructive": False,
        "paraphrase": "",
        "patterns": [
            r"\blast action\b",
            r"\b(what|tell me what) did you (just )?do\b",
            r"\blast call\b",
        ],
    },
    {
        "command": "/tail-audit",
        "destructive": False,
        "paraphrase": "",
        "patterns": [
            r"\b(audit (log|trail)|recent activity|recent events|audit history)\b",
            r"^\s*audit\??\s*$",
        ],
    },
    {
        "command": "/help",
        "destructive": False,
        "paraphrase": "",
        "patterns": [
            r"\bwhat can you do\b",
            r"\b(help|commands)\b\??\s*$",
            r"\bshow me (the )?commands\b",
        ],
    },
]


# Pre-compile patterns once at module load.
_COMPILED: List[tuple] = []
for entry in _INTENTS:
    for pat in entry["patterns"]:
        _COMPILED.append(
            (
                re.compile(pat, re.IGNORECASE),
                IntentMatch(
                    command=entry["command"],
                    destructive=entry["destructive"],
                    paraphrase=entry["paraphrase"],
                ),
            )
        )


def classify_intent(body: str) -> Optional[IntentMatch]:
    """Return the first matching IntentMatch, or None if no match.

    Order in _INTENTS determines precedence — earlier wins. Empty body
    returns None. Bodies starting with ``/`` return None (those are
    already explicit commands — pass through unchanged).
    """
    body = body.strip()
    if not body or body.startswith("/"):
        return None
    for pattern, intent in _COMPILED:
        if pattern.search(body):
            return intent
    return None


# --- Confirmation pattern recognition ------------------------------------

# "Yes" patterns: explicit affirmatives, plus the literal /command if
# the user knows the dialect and wants to skip the natural-language
# routing on the second message.
_YES_PATTERNS: List[re.Pattern] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"^\s*y(es)?\s*[!.]?\s*$",
        r"^\s*confirm\b",
        r"^\s*go ahead\b",
        r"^\s*do it\b",
        r"^\s*ok(ay)?\s*[!.]?\s*$",
        r"^\s*sure\s*[!.]?\s*$",
        r"^\s*yeah?\s*[!.]?\s*$",
        r"^\s*proceed\b",
        r"^\s*/(halt|pause|resume|new)\b",
    ]
]

# "No" patterns: explicit cancellations.
_NO_PATTERNS: List[re.Pattern] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"^\s*n(o)?\s*[!.]?\s*$",
        r"^\s*nope\s*[!.]?\s*$",
        r"^\s*cancel\b",
        r"^\s*nevermind\b",
        r"^\s*never mind\b",
        r"^\s*stop\b",
        r"^\s*don'?t\b",
        r"^\s*abort\b",
    ]
]


def is_confirmation_yes(body: str) -> bool:
    """True if ``body`` reads as 'yes confirm the pending action'."""
    body = body.strip()
    if not body:
        return False
    return any(p.match(body) for p in _YES_PATTERNS)


def is_confirmation_no(body: str) -> bool:
    """True if ``body`` reads as 'no cancel'."""
    body = body.strip()
    if not body:
        return False
    return any(p.match(body) for p in _NO_PATTERNS)
