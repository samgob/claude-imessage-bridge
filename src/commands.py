"""Parse and dispatch ``/`` commands inbound from iMessage.

UX is numbered-options-style: text-only, no inline UI. /sessions and /use
show a numbered list; /pick N references the most recent list shown to
that handle. Lists age out after LAST_OPTIONS_TTL_SECONDS so a much-later
/pick doesn't resurrect stale state.

A CommandResult is returned to the daemon — the daemon decides how to
audit and send the reply.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from . import session_discovery, state

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CommandResult:
    """What a command handler returns to the daemon."""

    reply: str
    # If set, the daemon should update the per-handle session pointer to
    # this id (used by /use, /pick, /new with reset semantics).
    set_session_id: Optional[str] = None
    # If True, the daemon clears the per-handle session pointer regardless
    # of set_session_id. Used by /new.
    clear_session: bool = False


# Coarse classification — does this body look like a command?
def is_command(body: str) -> bool:
    return body.lstrip().startswith("/")


def parse_and_dispatch(
    body: str,
    *,
    handle: str,
    state_dir: Path,
    aliases: Optional[Dict[str, str]] = None,
) -> CommandResult:
    """Parse a /command and return its CommandResult.

    ``aliases`` is the session-alias map from config (name → session UUID,
    keys already case-folded). Used by /use and /aliases. None means
    "no aliases configured" — the dispatcher behaves as it did pre-aliases.
    """
    if aliases is None:
        aliases = {}
    text = body.strip()
    if not text.startswith("/"):
        return CommandResult(
            reply="(internal error: parse_and_dispatch called on non-command)"
        )
    parts = text.split(maxsplit=1)
    cmd = parts[0].lower()
    arg = parts[1].strip() if len(parts) > 1 else ""

    if cmd == "/help":
        return _help()
    if cmd == "/new":
        return _new()
    if cmd == "/sessions":
        return _sessions(handle=handle, state_dir=state_dir, raw_arg=arg)
    if cmd == "/use":
        return _use(handle=handle, state_dir=state_dir, query=arg, aliases=aliases)
    if cmd == "/pick":
        return _pick(handle=handle, state_dir=state_dir, raw_arg=arg)
    if cmd == "/status":
        return _status(handle=handle, state_dir=state_dir)
    if cmd == "/aliases":
        return _aliases(aliases=aliases)
    if cmd == "/pause":
        return _pause(state_dir=state_dir, reason=arg)
    if cmd == "/resume":
        return _resume(state_dir=state_dir)
    return CommandResult(
        reply=(
            f"Unknown command {cmd!r}. Try /help for the list, or send a "
            "plain message to chat."
        )
    )


def _help() -> CommandResult:
    return CommandResult(reply=(
        "Commands:\n"
        "/help — this list\n"
        "/new — start a fresh session\n"
        "/status — current session info\n"
        "/sessions — list recent sessions (numbered)\n"
        "/use <query> — alias or keyword search; resumes a session\n"
        "/pick <N> — switch to a numbered match from the last list\n"
        "/aliases — list configured session aliases\n"
        "/pause [reason] — pause the bridge (Claude calls suspended)\n"
        "/resume — resume the bridge\n"
        "\n"
        "Anything else continues your current session."
    ))


def _new() -> CommandResult:
    return CommandResult(
        reply="Started fresh. What's next?",
        clear_session=True,
    )


def _status(*, handle: str, state_dir: Path) -> CommandResult:
    paused_line = ""
    pause_file = state_dir / "PAUSE"
    if pause_file.exists():
        try:
            reason = pause_file.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
            first = reason[0].strip() if reason else ""
        except OSError:
            first = ""
        paused_line = (
            f"⏸ Paused (reason: {first or 'unknown'}). Send /resume to restart.\n"
        )

    sid = state.get_current_session(handle, state_dir=state_dir)
    if not sid:
        return CommandResult(reply=(
            f"{paused_line}No active session — your next message starts a fresh one."
        ))
    info = session_discovery.find_by_id(sid)
    if info is None:
        return CommandResult(reply=(
            f"{paused_line}Active session: {sid[:8]} — but the transcript "
            "file is no longer on disk. Your next message starts a fresh "
            "session."
        ))
    return CommandResult(reply=(
        f"{paused_line}Active session: {info.short_id} · "
        f"{info.relative_age()} ago\n"
        f"Last user msg: {info.snippet[:120]}"
    ))


def _pause(*, state_dir: Path, reason: str = "") -> CommandResult:
    """Create the PAUSE file. Idempotent: re-pausing rewrites the reason."""
    final_reason = reason.strip() or "manual via /pause"
    state.trip_pause(state_dir=state_dir, reason=final_reason)
    return CommandResult(reply=(
        f"⏸ Bridge paused. Send /resume to restart. Reason: {final_reason}"
    ))


def _resume(*, state_dir: Path) -> CommandResult:
    """Remove the PAUSE file. No-op message if not currently paused."""
    pause_file = state_dir / "PAUSE"
    if not pause_file.exists():
        return CommandResult(reply=(
            "Bridge wasn't paused (no PAUSE file). Nothing to do."
        ))
    try:
        pause_file.unlink()
    except OSError as e:
        logger.error("could not remove PAUSE file: %s", e)
        return CommandResult(reply=(
            "⚠️ Tried to resume but couldn't remove PAUSE file. "
            "Check daemon logs."
        ))
    # Reset the consecutive-failure counter so a circuit-breaker-tripped
    # PAUSE doesn't immediately re-trip on the next failure.
    state.reset_claude_failures(state_dir=state_dir)
    return CommandResult(reply="▶ Bridge resumed.")


def _sessions(*, handle: str, state_dir: Path, raw_arg: str) -> CommandResult:
    """List recent sessions. Stashes numbered options for /pick N.

    By default excludes routines (``<scheduled-task>`` transcripts) and
    bridge-internal sessions (selftests + per-call hermetic sandboxes —
    these pollute the list with security-plumbing prompts). ``--all``
    opts both back in.
    """
    include_all = "--all" in raw_arg.lower().split()
    sessions = session_discovery.discover_sessions(
        limit=10,
        include_routines=include_all,
        include_bridge_internal=include_all,
    )
    if not sessions:
        return CommandResult(reply="No sessions found.")
    return _build_options_result(
        handle=handle,
        state_dir=state_dir,
        sessions=sessions,
        header="Recent sessions",
        footer="Reply /pick <N> to switch. Add --all to include routines + bridge internals.",
    )


def _use(
    *,
    handle: str,
    state_dir: Path,
    query: str,
    aliases: Optional[Dict[str, str]] = None,
) -> CommandResult:
    """Search sessions by keyword. Auto-resume if single match; numbered list otherwise.

    If ``aliases`` contains a case-insensitive exact match for the query,
    use that session id directly. If the alias points at a session that's
    no longer on disk, fall through to keyword search with a note appended
    to the reply.
    """
    if not query:
        return CommandResult(reply="Usage: /use <keyword>. Example: /use auth-refactor")

    aliases = aliases or {}
    alias_note = ""
    alias_key = query.strip().lower()
    if alias_key in aliases:
        sid = aliases[alias_key]
        info = session_discovery.find_by_id(sid)
        if info is not None:
            return CommandResult(
                reply=(
                    f"Resumed (alias {alias_key!r}) {info.short_id} · "
                    f"{info.relative_age()} ago\n"
                    f"Last user msg: {info.snippet[:120]}"
                ),
                set_session_id=info.session_id,
            )
        logger.warning(
            "alias %r points at session %s which is no longer on disk; "
            "falling through to keyword search", alias_key, sid[:8],
        )
        alias_note = (
            f"(alias {alias_key!r} points at a session that's gone — "
            "searching by keyword)\n"
        )

    current = state.get_current_session(handle, state_dir=state_dir)
    excluded = {current} if current else set()
    sessions = session_discovery.search_sessions(
        query, limit=10, exclude_session_ids=excluded,
    )
    if not sessions:
        return CommandResult(reply=f"{alias_note}No sessions match {query!r}.")
    if len(sessions) == 1:
        target = sessions[0]
        return CommandResult(
            reply=(
                f"{alias_note}"
                f"Resumed {target.short_id} · {target.relative_age()} ago\n"
                f"Last user msg: {target.snippet[:120]}"
            ),
            set_session_id=target.session_id,
        )
    result = _build_options_result(
        handle=handle,
        state_dir=state_dir,
        sessions=sessions,
        header=f"Matches for {query!r}",
        footer="Reply /pick <N> to switch.",
    )
    if alias_note:
        # Prepend the alias-miss note to the options reply.
        return CommandResult(
            reply=alias_note + result.reply,
            set_session_id=result.set_session_id,
            clear_session=result.clear_session,
        )
    return result


def _aliases(*, aliases: Dict[str, str]) -> CommandResult:
    """List configured aliases with on-disk status."""
    if not aliases:
        return CommandResult(reply=(
            "No aliases configured. Add a session_aliases block to "
            "config.yaml — see config.example.yaml."
        ))
    lines = ["Configured aliases:"]
    for name in sorted(aliases.keys()):
        sid = aliases[name]
        info = session_discovery.find_by_id(sid)
        if info is None:
            lines.append(f"{name} · {sid[:8]} · <missing on disk>")
        else:
            snippet = (info.snippet[:60] or "(no user msg)").strip()
            lines.append(
                f"{name} · {info.short_id} · {info.relative_age()} ago "
                f"({snippet})"
            )
    lines.append("")
    lines.append("Send /use <name> to resume.")
    return CommandResult(reply="\n".join(lines))


def _pick(*, handle: str, state_dir: Path, raw_arg: str) -> CommandResult:
    """Resume the Nth session from the most-recent /sessions or /use list."""
    if not raw_arg:
        return CommandResult(reply="Usage: /pick <N>. Run /sessions first.")
    try:
        n = int(raw_arg.split()[0])
    except (ValueError, IndexError):
        return CommandResult(reply=f"Not a number: {raw_arg!r}. Usage: /pick <N>.")
    options = state.get_last_options(handle, state_dir=state_dir)
    if not options:
        return CommandResult(reply=(
            "No recent list to pick from (either you haven't run /sessions "
            "or /use, or the list aged out). Run /sessions first."
        ))
    if n < 1 or n > len(options):
        return CommandResult(reply=(
            f"Pick must be between 1 and {len(options)}. "
            f"Run /sessions to see the current list."
        ))
    chosen = options[n - 1]
    sid = chosen.get("id", "")
    info = session_discovery.find_by_id(sid)
    if info is None:
        return CommandResult(reply=(
            f"Session {sid[:8] if sid else 'N/A'} is no longer on disk — "
            "list may be stale. Run /sessions to refresh."
        ))
    return CommandResult(
        reply=(
            f"Resumed [{n}] {info.short_id} · {info.relative_age()} ago\n"
            f"Last user msg: {info.snippet[:120]}"
        ),
        set_session_id=info.session_id,
    )


def _build_options_result(
    *,
    handle: str,
    state_dir: Path,
    sessions: List[session_discovery.SessionInfo],
    header: str,
    footer: str,
) -> CommandResult:
    """Render a numbered list, stash options for /pick, return a CommandResult."""
    lines = [header]
    options = []
    for i, s in enumerate(sessions, start=1):
        marker = " ⚙" if s.is_routine else (" 🔧" if s.is_bridge_internal else "")
        snippet = s.snippet[:60] or "(no user msg)"
        lines.append(f"[{i}] {s.short_id}{marker} · {s.relative_age()} ago — {snippet}")
        options.append({"id": s.session_id, "snippet": snippet})
    lines.append("")
    lines.append(footer)
    state.set_last_options(handle, options, state_dir=state_dir)
    return CommandResult(reply="\n".join(lines))
