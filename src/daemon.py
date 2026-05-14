"""Phase A daemon: read new iMessages, route through allowlist, echo back.

This is a security-baseline build. It does NOT invoke Claude — that's
Phase B. The goal here is to prove the chat.db → router → AppleScript-send
plumbing works correctly and safely.

Ordering invariants (see THREAT_MODEL S1 and C3 finding):

  1. Audit "received" row written BEFORE any handling.
  2. Cursor advanced BEFORE any reply is sent. A crash mid-send loses ONE
     reply (recoverable: the user re-asks) instead of double-sending.
  3. Reply sent.
  4. Audit "reply" or "drop" row written AFTER send completes (or fails).

Bodies are NEVER written to state.db audit_log, even in --debug mode.
Debug mode logs bodies to stderr at WARNING level so the user sees a
runtime hint that bodies are being printed, and so they don't end up
persisted in a Time Machine backup of state.db.
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import signal
import sys
import time
from collections import Counter, deque
from pathlib import Path
from typing import Deque, Optional, Tuple

from . import backups
from . import claude_runner
from . import commands as commands_mod
from . import config as config_mod
from . import health
from . import imessage_reader
from . import imessage_sender
from . import intents
from . import memory as memory_mod
from . import state
from . import trust as trust_mod

logger = logging.getLogger("imessage_bridge")

DEFAULT_CONFIG_PATH = Path.home() / ".claude-imessage-bridge" / "config.yaml"
CURSOR_NAME = "chatdb_last_rowid"
HEARTBEAT_INTERVAL_SECONDS = 300

_running = True
_metrics: Counter = Counter()

# Memory backend is instantiated once at startup so its cache survives
# across messages. The /sources command also reads from this instance's
# last-call source list (which it exposes via a small recorder helper).
_memory_backend: Optional[memory_mod.MemoryBackend] = None
# Last-call source list for the /sources command. Mutated on every
# context_for call; read by commands._sources.
_last_memory_sources: list = []


# --- Self-chat echo prevention ------------------------------------------
#
# When the user messages themselves (single Apple-ID, two devices), the
# bridge's outbound replies are written to the Mac's chat.db as
# ``is_from_me=1`` (correctly filtered at the SQL layer). BUT the iPhone
# also receives the reply, records it in its own chat.db, and iCloud
# Messages sync pushes a copy back to the Mac as ``is_from_me=0`` —
# indistinguishable from the user typing the same thing. Without
# deduplication this creates a reply loop.
#
# Mitigation: track the (handle, body) pairs we sent in the last
# RECENT_SELF_SEND_TTL_SECONDS in an in-memory deque, and skip any
# inbound row that matches. Body is hashed; we don't store plaintext.
#
# False-negative cost: if the user happens to send a message that
# exactly matches a bridge reply within the TTL window, the bridge will
# ignore it. Acceptable.

RECENT_SELF_SEND_TTL_SECONDS: int = 180
RECENT_SELF_SEND_CAP: int = 256  # bounded; old entries fall off
_recent_self_sends: Deque[Tuple[float, str, str]] = deque(maxlen=RECENT_SELF_SEND_CAP)


def _body_digest(body: str) -> str:
    """Stable short hash of an outgoing body, for echo dedupe."""
    return hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()[:16]


def _record_self_send(handle: str, body: str) -> None:
    """Note that the bridge just sent ``body`` to ``handle``."""
    _recent_self_sends.append((time.time(), handle, _body_digest(body)))


def _is_recent_self_send(handle: str, body: str) -> bool:
    """True if (handle, body) matches a send we made within the TTL window."""
    now = time.time()
    cutoff = now - RECENT_SELF_SEND_TTL_SECONDS
    # Prune the head of the deque (oldest entries). The deque is bounded
    # by maxlen so this is cheap.
    while _recent_self_sends and _recent_self_sends[0][0] < cutoff:
        _recent_self_sends.popleft()
    target = _body_digest(body)
    return any(h == handle and bh == target for _, h, bh in _recent_self_sends)


# ---------------------------------------------------------------------------
# Boot-time
# ---------------------------------------------------------------------------

def _setup_logging(debug: bool) -> None:
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )


def _install_signal_handlers() -> None:
    def _stop(signum, _frame):
        global _running
        logger.info("signal %s received, stopping", signum)
        _running = False
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)


def _preflight(state_dir: Path) -> None:
    """Hard-fail on environment invariants before the loop starts.

    See solver review #2. The set of checks is intentionally cheap — anything
    that takes more than a few ms doesn't belong here. The point is to catch
    a misconfigured environment now rather than 30 minutes into a run.
    """
    # 1. osascript at the pinned path.
    if not Path("/usr/bin/osascript").is_file():
        raise RuntimeError(
            "/usr/bin/osascript missing — refuse to run "
            "(unexpected macOS install state)"
        )
    # 2. Messages.app exists and is the Apple bundle.
    messages_app = Path("/System/Applications/Messages.app")
    if not messages_app.is_dir():
        # Fall back to the older location on some macOS versions.
        messages_app = Path("/Applications/Messages.app")
    if not messages_app.is_dir():
        raise RuntimeError(
            "Messages.app not found in /System/Applications or /Applications"
        )
    # 3. state.db not a symlink.
    db_path = state_dir / "state.db"
    if db_path.exists() and db_path.is_symlink():
        raise RuntimeError(
            f"{db_path} is a symlink; refuse to run (possible swap attack)"
        )
    # 4. config.yaml perms are not world/group readable (it has PII).
    cfg_path_str = os.environ.get("CIMB_CONFIG_PATH")
    if cfg_path_str:
        cfg_path = Path(cfg_path_str)
        if cfg_path.exists():
            mode = cfg_path.stat().st_mode & 0o777
            if mode & 0o077:
                logger.warning(
                    "config at %s is world/group-readable (mode %o); "
                    "tighten to 0600",
                    cfg_path,
                    mode,
                )


# ---------------------------------------------------------------------------
# Per-message processing
# ---------------------------------------------------------------------------

def _normalize_for_allowlist(handle: str) -> str:
    """Apply the same normalization the allowlist uses, returning '' if invalid."""
    try:
        return imessage_sender.validate_handle(handle)
    except imessage_sender.HandleError:
        return ""


def _decide(msg: imessage_reader.Message, cfg) -> tuple[bool, str]:
    """Return (accept, reason)."""
    norm = _normalize_for_allowlist(msg.sender_handle)
    if not norm:
        return False, "invalid-handle-format"
    if norm not in cfg.allowlist_set:
        return False, "sender-not-allowlisted"
    if msg.is_group and msg.chat_guid not in set(cfg.allow_group_chat_guids):
        return False, "group-chat-not-opted-in"
    return True, "ok"


def _classify(body: str) -> str:
    """Coarse classification for audit log (NEVER the body itself)."""
    if body.startswith("/"):
        return "command"
    return "text"


def _user_facing_error(category: Optional[str]) -> str:
    """Translate a claude_runner error category into a user-safe message.

    Critically: NEVER include the underlying error string OR the
    consecutive-failure count. Claude's stderr can contain file paths,
    MCP server names, traceback fragments — all leak info to anyone with
    iMessage access to this account. The consecutive-failure counter
    also leaks the circuit-breaker threshold to a probing attacker (per
    adversarial review S3 + D2).
    """
    if category == "timeout":
        return "⚠️ Claude timed out. Try a simpler prompt."
    if category == "exec_error":
        return "⚠️ Couldn't run Claude. Check daemon logs."
    if category == "json_parse":
        return "⚠️ Got a malformed response from Claude. Check daemon logs."
    if category == "claude_error":
        return "⚠️ Claude reported an error. Try again."
    if category == "resume_missing":
        return "⚠️ Couldn't resume that session — it's no longer on disk. Try again to start a fresh one."
    return "⚠️ Reply unavailable. Check daemon logs."


def _run_permission_relay_retry(
    *,
    norm: str,
    redacted: str,
    chatdb_rowid: int,
    session_id: str,
    cfg,
    active_preset,
) -> None:
    """User approved a permission-relay request. Re-invoke claude with
    ``--permission-mode=acceptEdits`` and ``--resume <sid>`` so the
    previously-blocked edits can apply. A short follow-up prompt nudges
    the model to retry the action it was blocked on rather than starting
    over.

    Cost: a second claude call. Logged separately in audit.
    """
    if not session_id:
        # Defensive — pending intent had no session id. Tell the user.
        try:
            imessage_sender.send(
                imessage_sender.SendRequest(
                    handle=norm,
                    body="⚠️ Permission relay state is incomplete. Try the original request again.",
                ),
            )
        except imessage_sender.SendError:
            pass
        return

    retry_prompt = (
        "I've approved the permission request you flagged. "
        "Please proceed with the action(s) you were blocked on, "
        "then summarize what changed."
    )
    logger.info(
        "permission relay retry: resume %s for %s",
        session_id[:8], redacted,
    )
    try:
        result = claude_runner.run_claude(
            retry_prompt,
            trust_preset=active_preset,
            project_directory=cfg.project_directory,
            allowed_tools_addons=cfg.allowed_tools,
            timeout_seconds=cfg.per_call_timeout_seconds,
            claude_bin=cfg.claude_binary,
            resume_session_id=session_id,
            extra_context="",
            permission_relay_retry=True,
        )
    except claude_runner.RunnerConfigError as e:
        logger.error("permission relay retry runner config error: %s", e)
        try:
            imessage_sender.send(
                imessage_sender.SendRequest(
                    handle=norm,
                    body="⚠️ Couldn't run the retry. Check daemon logs.",
                ),
            )
        except imessage_sender.SendError:
            pass
        return

    cents = max(0, int(result.cost_usd * 100 + 0.999))
    if cents:
        state.add_cost_cents(cents)

    if result.success:
        if result.session_id:
            state.set_current_session(norm, result.session_id)
        reply_body = result.reply.strip() or "(claude returned an empty response)"
        detail = (
            f"permission-relay-retry ok dur={result.duration_ms}ms "
            f"cost_cents={cents} sid={(result.session_id or 'none')[:8]}"
        )
    else:
        reply_body = _user_facing_error(result.error_category)
        detail = (
            f"permission-relay-retry err category={result.error_category} "
            f"dur={result.duration_ms}ms"
        )
        logger.warning(
            "permission relay retry failed handle=%s category=%s raw=%r",
            redacted, result.error_category, result.error,
        )

    try:
        imessage_sender.send(
            imessage_sender.SendRequest(handle=norm, body=reply_body),
        )
        _record_self_send(norm, reply_body)
        state.audit(
            handle_redacted=redacted, direction="out", kind="reply",
            detail=detail,
            reply_bytes=len(reply_body.encode("utf-8")),
            chatdb_rowid=chatdb_rowid,
            cost_cents=cents,
            error_category=result.error_category,
        )
        _metrics["permission_relay_retry"] += 1
        _metrics["cost_cents"] += cents
    except imessage_sender.SendError as e:
        logger.error("permission relay retry send failed: %s", e)


def _handle_one(msg: imessage_reader.Message, cfg) -> None:
    """Process a single inbound message: decide, rate-limit, reply.

    Phase A: echo only. Phase B will replace the reply construction with a
    Claude call.

    This function NEVER advances the cursor. The caller is responsible for
    that — see main loop for ordering.
    """
    _metrics["msgs_in"] += 1
    norm = _normalize_for_allowlist(msg.sender_handle)
    redacted = imessage_sender._redact_handle(  # noqa: SLF001 — internal helper
        norm or msg.sender_handle
    )

    # Audit "received" first. Detail records WHY the message was accepted or
    # dropped, not the body content. In --debug mode, bodies are logged to
    # stderr only (NOT state.db) so they don't end up in backups.
    accept, reason = _decide(msg, cfg)
    state.audit(
        handle_redacted=redacted,
        direction="in",
        kind=("drop" if not accept else _classify(msg.body)),
        detail=reason,
        chatdb_rowid=msg.rowid,
    )
    if cfg.debug:
        logger.warning(
            "DEBUG: inbound body from %s (rowid=%d): %r",
            redacted,
            msg.rowid,
            msg.body[:200],
        )

    if not accept:
        _metrics["drops_" + reason] += 1
        return

    # Self-chat echo dedupe. When user messages themselves, iCloud sync
    # bounces our outbound reply back as is_from_me=0 on the Mac. Skip
    # rows whose body matches a reply we sent to this handle in the last
    # RECENT_SELF_SEND_TTL_SECONDS — otherwise we'd reply to our own
    # reply, ad infinitum (observed in the first live test).
    if _is_recent_self_send(norm, msg.body):
        _metrics["self_send_echoes_skipped"] += 1
        logger.info(
            "skipping self-send echo from %s (rowid=%d)",
            redacted, msg.rowid,
        )
        state.audit(
            handle_redacted=redacted,
            direction="in",
            kind="drop",
            detail="self-send-echo",
            chatdb_rowid=msg.rowid,
        )
        return

    # Rate-limit: reserve a slot atomically (handles TOCTOU at the SQL layer).
    granted, count = state.reserve_reply_slot(
        norm, cfg.reply_rate_limit_per_minute
    )
    if not granted:
        _metrics["rate_limit_hits"] += 1
        logger.warning(
            "rate-limit hit for %s (%d/%d in window)",
            redacted, count, cfg.reply_rate_limit_per_minute,
        )
        state.audit(
            handle_redacted=redacted,
            direction="out",
            kind="drop",
            detail="rate-limited",
            chatdb_rowid=msg.rowid,
        )
        return

    # --- Natural-language intent + confirmation flow ------------------
    #
    # If we have a pending confirmation for this handle (60s TTL),
    # interpret the body as yes/no/anything-else. Otherwise, run the
    # intent classifier on plain-text bodies; if it matches a
    # destructive intent, stash a pending confirmation; if it matches a
    # read-only intent, synthesize the equivalent /command and fall
    # through to the existing /command dispatch.

    body_for_dispatch = msg.body  # may be rewritten by intent flow

    pending = state.get_pending_intent(norm)
    if pending is not None:
        if intents.is_confirmation_yes(msg.body):
            # Special sentinel: permission-relay retry. Not a slash
            # command — runs the retry path with --permission-mode=
            # acceptEdits + --resume <session_id stored in extra_arg>.
            if pending.get("command") == "__permission_relay__":
                session_id_to_resume = pending.get("extra_arg") or ""
                state.clear_pending_intent(norm)
                _metrics["permission_relay_approved"] += 1
                _run_permission_relay_retry(
                    norm=norm,
                    redacted=redacted,
                    chatdb_rowid=msg.rowid,
                    session_id=session_id_to_resume,
                    cfg=cfg,
                    active_preset=trust_mod.resolve_trust(
                        trust_default=cfg.trust_default,
                        trust_per_alias=cfg.trust_per_alias,
                        active_alias=None,
                    ),
                )
                return
            # Normal pending intent: execute the stashed command by
            # rewriting the body and falling through to /command dispatch.
            extra = pending.get("extra_arg", "")
            body_for_dispatch = pending["command"]
            if extra:
                body_for_dispatch = body_for_dispatch + " " + extra
            state.clear_pending_intent(norm)
            _metrics["intent_confirmed"] += 1
        elif intents.is_confirmation_no(msg.body):
            state.clear_pending_intent(norm)
            # For permission relay, "no" means "skip the edit". The
            # original message's partial reply was never sent (we
            # intercepted it). Send a brief acknowledgment.
            cancel_reply = "Cancelled."
            if pending.get("command") == "__permission_relay__":
                cancel_reply = "Skipped. The edit wasn't applied."
                _metrics["permission_relay_declined"] += 1
            try:
                imessage_sender.send(
                    imessage_sender.SendRequest(handle=norm, body=cancel_reply),
                )
                _record_self_send(norm, cancel_reply)
                state.audit(
                    handle_redacted=redacted, direction="out", kind="reply",
                    detail="intent-cancelled",
                    chatdb_rowid=msg.rowid,
                    cost_cents=0,
                )
            except imessage_sender.SendError as e:
                logger.error("intent-cancel send failed: %s", e)
            return
        else:
            # Anything else: treat the pending as implicitly cancelled
            # and process this message normally.
            state.clear_pending_intent(norm)
            _metrics["intent_implicitly_cancelled"] += 1

    # If still no pending was matched, try classifying this body.
    if not commands_mod.is_command(body_for_dispatch):
        intent = intents.classify_intent(body_for_dispatch)
        if intent is not None:
            if intent.destructive:
                # Stash pending; reply with paraphrase; return.
                state.set_pending_intent(
                    norm, intent.command, intent.extra_arg or "",
                )
                _metrics["intent_pending_confirmation"] += 1
                try:
                    imessage_sender.send(
                        imessage_sender.SendRequest(
                            handle=norm, body=intent.paraphrase,
                        ),
                    )
                    _record_self_send(norm, intent.paraphrase)
                    state.audit(
                        handle_redacted=redacted, direction="out", kind="reply",
                        detail=f"intent-confirm-req:{intent.command}",
                        chatdb_rowid=msg.rowid,
                        cost_cents=0,
                    )
                except imessage_sender.SendError as e:
                    logger.error("intent paraphrase send failed: %s", e)
                return
            # Read-only intent: synthesize the slash command and let the
            # /command path execute it below.
            body_for_dispatch = intent.command
            if intent.extra_arg:
                body_for_dispatch = body_for_dispatch + " " + intent.extra_arg
            _metrics["intent_executed_readonly"] += 1

    # Command path: /-prefixed messages dispatch to commands.py instead
    # of claude. Commands are cheap (no LLM call, no cost), so they
    # don't run through the cost cap or claude_runner.
    #
    # ``body_for_dispatch`` may have been rewritten upstream by the
    # natural-language intent layer (e.g., "how's it going" became
    # "/status") — use it, not msg.body, for the dispatch.
    if commands_mod.is_command(body_for_dispatch):
        try:
            cmd_result = commands_mod.parse_and_dispatch(
                body_for_dispatch,
                handle=norm,
                state_dir=state.DEFAULT_STATE_DIR,
                aliases=cfg.session_aliases,
                cfg=cfg,
            )
        except Exception as e:
            logger.exception("command dispatch crashed: %s", e)
            state.audit(
                handle_redacted=redacted, direction="out", kind="drop",
                detail=f"cmd-error:{type(e).__name__}",
                chatdb_rowid=msg.rowid,
            )
            return

        if cmd_result.clear_session:
            state.set_current_session(norm, None)
        elif cmd_result.set_session_id is not None:
            state.set_current_session(norm, cmd_result.set_session_id)

        try:
            imessage_sender.send(
                imessage_sender.SendRequest(handle=norm, body=cmd_result.reply),
            )
            _record_self_send(norm, cmd_result.reply)
            _metrics["cmd_replies"] += 1
            state.audit(
                handle_redacted=redacted, direction="out", kind="reply",
                detail=f"cmd={body_for_dispatch.split()[0]}",
                reply_bytes=len(cmd_result.reply.encode("utf-8")),
                chatdb_rowid=msg.rowid,
                cost_cents=0,
            )
        except imessage_sender.SendError as e:
            _metrics["send_errors"] += 1
            logger.error("cmd send failed: %s", e)
            state.audit(
                handle_redacted=redacted, direction="out", kind="drop",
                detail=f"cmd-send-error:{type(e).__name__}",
                chatdb_rowid=msg.rowid,
            )

        # /halt — clean daemon exit after the reply is sent. Signal the
        # main loop via _running=False AND create a STOP file (belt and
        # suspenders — STOP file also signals any concurrent loop reader).
        if cmd_result.halt_after_send:
            global _running
            _running = False
            try:
                (state.DEFAULT_STATE_DIR / "STOP").write_text(
                    "halted via iMessage /halt command\n"
                )
            except OSError as e:
                logger.warning("could not create STOP file: %s", e)
            logger.warning("HALT requested via /halt — daemon will exit")
        return

    # PAUSE gate: applied ONLY to the claude-invocation path. Commands
    # were already dispatched above, so /resume, /status, /help work
    # while paused. Plain-text messages (non-commands) get a notice and
    # are dropped — they'd otherwise invoke claude.
    if _is_paused(state.DEFAULT_STATE_DIR):
        _metrics["paused_drops"] += 1
        logger.info("PAUSE active; dropping non-command message from %s", redacted)
        pause_reason = _read_pause_reason(state.DEFAULT_STATE_DIR)
        notice = (
            "⏸ Bridge paused — your message wasn't sent to Claude. "
            "Send /resume to restart."
        )
        if pause_reason:
            notice += f" (reason: {pause_reason})"
        try:
            imessage_sender.send(
                imessage_sender.SendRequest(handle=norm, body=notice),
            )
            _record_self_send(norm, notice)
        except imessage_sender.SendError:
            pass
        state.audit(
            handle_redacted=redacted, direction="out", kind="drop",
            detail="paused", chatdb_rowid=msg.rowid,
        )
        return

    # Daily cost cap check BEFORE invoking claude. If we're already over
    # the cap, refuse and tell the user. The cap is meant to be a defense
    # against a compromised contact burning the budget, so it's deliberate
    # that legitimate use can hit it too — the failure should be visible
    # rather than silent.
    if state.cost_over_cap(cfg.daily_cost_cap_usd):
        _metrics["daily_cap_hits"] += 1
        logger.warning(
            "daily cost cap reached ($%.2f) — refusing claude invocation",
            cfg.daily_cost_cap_usd,
        )
        cap_body = (
            f"⚠️ Daily cost cap reached (${cfg.daily_cost_cap_usd:.2f}). "
            "Resets at 00:00 UTC. Edit config.yaml to raise."
        )
        try:
            imessage_sender.send(
                imessage_sender.SendRequest(handle=norm, body=cap_body),
            )
            _record_self_send(norm, cap_body)
        except imessage_sender.SendError:
            pass
        state.audit(
            handle_redacted=redacted,
            direction="out",
            kind="drop",
            detail="daily-cap-reached",
            chatdb_rowid=msg.rowid,
        )
        return

    # Invoke claude in a per-call hermetic sandbox. claude_runner provisions
    # a fresh tempdir + empty-mcp.json for each call and tears them down
    # after. It enforces the safe-argv invariants (no
    # --dangerously-skip-permissions, no forbidden tools, no MCP-namespaced
    # tools, -- separator before prompt). It returns a structured result;
    # we never raise on Claude-side errors, just report.
    #
    # If the handle has a current session id set (from a prior /use, /pick,
    # or the most recent stateless invocation), resume that session — the
    # transcript context loads, but tool authority is still gated by
    # --disallowed-tools (resume doesn't grant new tool authority).
    resume_id = state.get_current_session(norm)

    # Stale-session pre-check: if the stored session id no longer exists
    # on disk (e.g., it was a hermetic-tempdir session from a previous
    # chat_only run, since cleaned up), claude --resume would exit 1
    # with "No conversation found." Clear the stale pointer and let this
    # call start fresh.
    #
    # This can also fire if Sam manually rotated ~/.claude/projects/, or
    # if a backup-restore of state.db references sessions no longer on
    # disk.
    if resume_id is not None:
        from . import session_discovery
        if session_discovery.find_by_id(resume_id) is None:
            logger.info(
                "session %s gone from disk; clearing per-handle pointer for %s",
                resume_id[:8], redacted,
            )
            state.set_current_session(norm, None)
            resume_id = None
            _metrics["stale_session_cleared"] += 1
    # Trust mode resolution. For now, no per-alias override (alias state
    # isn't tracked per-handle yet — that lands in chunk 4 with schema v3).
    # Default-only resolution gives the right preset for the common case.
    active_preset = trust_mod.resolve_trust(
        trust_default=cfg.trust_default,
        trust_per_alias=cfg.trust_per_alias,
        active_alias=None,
    )

    # Memory backend pulls curated context. NoneBackend (the default,
    # and what chat_only trust mode uses) returns empty — same behavior
    # as pre-memory. In coding/full modes with claude_md backend, this
    # injects CLAUDE.md + relevance-matched memory files into the
    # system prompt.
    global _last_memory_sources
    if _memory_backend is not None and active_preset.memory_backend != "none":
        mem_result = _memory_backend.context_for(msg.body)
        extra_context = mem_result.text
        _last_memory_sources = list(mem_result.sources)
    else:
        extra_context = ""
        _last_memory_sources = []

    try:
        result = claude_runner.run_claude(
            msg.body,
            trust_preset=active_preset,
            project_directory=cfg.project_directory,
            allowed_tools_addons=cfg.allowed_tools,
            timeout_seconds=cfg.per_call_timeout_seconds,
            claude_bin=cfg.claude_binary,
            resume_session_id=resume_id,
            extra_context=extra_context,
        )

        # Post-failure recovery for stale-session resume. claude_runner
        # detects the "No conversation found" stderr and reports
        # error_category="resume_missing". We clear the per-handle
        # pointer and retry the SAME message fresh, so the user sees
        # one reply (the fresh one), not two.
        if (not result.success
                and result.error_category == "resume_missing"
                and resume_id is not None):
            logger.info(
                "auto-recover: resume %s failed, retrying fresh for %s",
                resume_id[:8], redacted,
            )
            state.set_current_session(norm, None)
            _metrics["stale_session_recovered"] += 1
            result = claude_runner.run_claude(
                msg.body,
                trust_preset=active_preset,
                project_directory=cfg.project_directory,
                allowed_tools_addons=cfg.allowed_tools,
                timeout_seconds=cfg.per_call_timeout_seconds,
                claude_bin=cfg.claude_binary,
                resume_session_id=None,  # fresh
                extra_context=extra_context,
            )
    except claude_runner.RunnerConfigError as e:
        logger.error("runner config error: %s", e)
        result = claude_runner.ClaudeResult(
            success=False, reply="", session_id=None, cost_usd=0.0,
            duration_ms=0, error="runner config error",
            error_category="exec_error",
        )

    # Cost accounting always — even on error, claude may have charged us
    # for partial work. Convert to cents (round up partials).
    cents = max(0, int(result.cost_usd * 100 + 0.999))
    if cents:
        state.add_cost_cents(cents)

    # Per-call cost cap: if a single response somehow spent more than the
    # cap, suppress the reply (the spend already happened; we don't want
    # to send whatever the model produced — it might be the very thing
    # that ran up the bill).
    per_call_cap_cents = int(round(cfg.per_call_cost_cap_usd * 100))
    if cents > per_call_cap_cents:
        logger.error(
            "per-call cost cap exceeded: %d cents > %d cents",
            cents, per_call_cap_cents,
        )
        _metrics["per_call_cap_hits"] += 1
        state.audit(
            handle_redacted=redacted,
            direction="out",
            kind="drop",
            detail=f"per-call-cap dur={result.duration_ms}ms cents={cents}",
            chatdb_rowid=msg.rowid,
            cost_cents=cents,
        )
        per_call_cap_body = (
            "⚠️ Reply suppressed — that response cost "
            f"${result.cost_usd:.2f} (cap is "
            f"${cfg.per_call_cost_cap_usd:.2f}). Try a "
            "shorter prompt."
        )
        try:
            imessage_sender.send(
                imessage_sender.SendRequest(handle=norm, body=per_call_cap_body),
            )
            _record_self_send(norm, per_call_cap_body)
        except imessage_sender.SendError:
            pass
        return

    # Permission relay: claude reports permission_denials on a successful
    # call when the model tried (and was blocked from) sensitive-file
    # edits. The model continues, summarizes the partial outcome, and the
    # call exits 0. We intercept here: instead of sending the partial
    # reply, ask the user to approve the blocked operations. On yes, we
    # retry with --permission-mode=acceptEdits + --resume to apply.
    #
    # Only fires in coding/full trust modes. chat_only has no tools to
    # be blocked, so denials would be empty anyway.
    if (result.success
            and result.permission_denials
            and active_preset.name in ("coding", "full")
            and result.session_id):
        # Persist the session id first so the retry can resume it.
        state.set_current_session(norm, result.session_id)
        # Summarize the denials for the user. Each entry from claude is
        # typically {"tool_name": "Edit", "tool_input": {"file_path":
        # "..."}, ...} — extract the key fields without leaking the full
        # tool_input contents (which could be large).
        denial_lines = []
        for d in result.permission_denials[:5]:  # cap at 5 in the prompt
            if not isinstance(d, dict):
                continue
            tool = d.get("tool_name") or d.get("tool") or "?"
            ti = d.get("tool_input") or {}
            path = ""
            if isinstance(ti, dict):
                path = ti.get("file_path") or ti.get("path") or ""
            if path:
                # Trim to filename + immediate parent for readability
                try:
                    p = Path(path)
                    relative = "~/" + str(p.relative_to(Path.home()))
                except (ValueError, OSError):
                    relative = path
                denial_lines.append(f"  {tool} → {relative}")
            else:
                denial_lines.append(f"  {tool}")
        extra = ""
        if len(result.permission_denials) > 5:
            extra = f"\n  …and {len(result.permission_denials) - 5} more"
        paraphrase = (
            "🔒 Claude wanted to do these but was blocked by permission "
            "gates:\n"
            + "\n".join(denial_lines)
            + extra
            + "\n\nReply 'yes' to approve and retry, or 'no' to skip "
            "(claude's partial reply will be sent as-is)."
        )
        # Stash a relay-specific pending intent. The command field is a
        # sentinel; the daemon detects it on the next inbound and runs
        # the retry path rather than dispatching as a slash command.
        state.set_pending_intent(
            norm, command="__permission_relay__", extra_arg=result.session_id,
        )
        try:
            imessage_sender.send(
                imessage_sender.SendRequest(handle=norm, body=paraphrase),
            )
            _record_self_send(norm, paraphrase)
            _metrics["permission_relay_prompted"] += 1
            state.audit(
                handle_redacted=redacted, direction="out", kind="reply",
                detail=f"permission-relay-prompt count={len(result.permission_denials)}",
                reply_bytes=len(paraphrase.encode("utf-8")),
                chatdb_rowid=msg.rowid,
                cost_cents=cents,
            )
        except imessage_sender.SendError as e:
            logger.error("permission relay paraphrase send failed: %s", e)
            state.clear_pending_intent(norm)
        # Cost is still attributed to this call; the partial reply doesn't
        # get sent. The retry (on confirmation) will add its own cost.
        return

    # Circuit breaker: track consecutive failures and auto-PAUSE if we
    # cross the threshold. Resets to 0 on each success.
    if result.success:
        state.reset_claude_failures()
        # Persist the session id so the next inbound message continues
        # this thread instead of starting fresh. /new wipes it; /use and
        # /pick override it.
        if result.session_id:
            state.set_current_session(norm, result.session_id)
        reply_body = result.reply.strip() or "(claude returned an empty response)"
        kind = "reply"
        detail = (
            f"ok dur={result.duration_ms}ms "
            f"cost_cents={cents} "
            f"sid={(result.session_id or 'none')[:8]}"
        )
    else:
        failures = state.record_claude_failure()
        _metrics["claude_failures"] += 1
        # User-facing error is GENERIC. The actual error string (which may
        # contain file paths or internal info) is logged server-side only.
        reply_body = _user_facing_error(result.error_category)
        kind = "reply"
        # Audit ``detail`` MUST NOT carry the raw error string or the
        # consecutive-failure counter — both are server-side-only per
        # THREAT_MODEL S8 and SECURITY.md (state.db is documented as
        # not containing them). Round-4 adversarial finding.
        # The error_category column carries the structured signal a forensic
        # query needs; the full error + failure count go to logger only.
        logger.warning(
            "claude failure handle=%s category=%s consec=%d dur=%dms raw=%r",
            redacted, result.error_category, failures,
            result.duration_ms, result.error,
        )
        detail = (
            f"err category={result.error_category} "
            f"dur={result.duration_ms}ms"
        )
        if failures >= cfg.circuit_breaker_failures:
            logger.error(
                "circuit breaker tripped after %d consecutive failures — "
                "creating PAUSE file",
                failures,
            )
            state.trip_pause(
                reason=f"auto: {failures} consecutive claude failures "
                f"(category={result.error_category})",
            )

    try:
        imessage_sender.send(
            imessage_sender.SendRequest(handle=norm, body=reply_body),
            dry_run=False,
        )
        _record_self_send(norm, reply_body)
        _metrics["replies"] += 1
        _metrics["cost_cents"] += cents
        state.audit(
            handle_redacted=redacted,
            direction="out",
            kind=kind,
            detail=detail,
            reply_bytes=len(reply_body.encode("utf-8")),
            chatdb_rowid=msg.rowid,
            cost_cents=cents,
            error_category=result.error_category,
        )
    except imessage_sender.SendError as e:
        _metrics["send_errors"] += 1
        logger.error("send failed: %s", e)
        state.audit(
            handle_redacted=redacted,
            direction="out",
            kind="drop",
            detail=f"send-error:{type(e).__name__}",
            chatdb_rowid=msg.rowid,
            cost_cents=cents,
            error_category=result.error_category,
        )


# ---------------------------------------------------------------------------
# Kill-switch & heartbeat
# ---------------------------------------------------------------------------

def _is_paused(state_dir: Path) -> bool:
    return (state_dir / "PAUSE").exists()


def _read_pause_reason(state_dir: Path) -> str:
    """Return the first line of the PAUSE file (if present), else ''."""
    pause = state_dir / "PAUSE"
    try:
        text = pause.read_text(encoding="utf-8", errors="replace")
    except (OSError, FileNotFoundError):
        return ""
    return text.splitlines()[0].strip() if text else ""


def _stop_requested(state_dir: Path) -> bool:
    if (state_dir / "STOP").exists():
        logger.warning("STOP file present at %s — exiting cleanly", state_dir / "STOP")
        return True
    return False


def _heartbeat(
    *,
    state_dir: Optional[Path] = None,
    cursor: int = 0,
    cfg=None,
    paused: bool = False,
    stop_requested: bool = False,
) -> None:
    """Periodic summary log line + status.json sidecar.

    Captures and resets the metric counters; takes a snapshot in
    ``status.json`` so external monitors (``cimb-status``, shell scripts,
    cron-driven health checks) can see liveness without scraping logs.
    """
    snapshot = dict(_metrics)
    _metrics.clear()
    parts = " ".join(f"{k}={v}" for k, v in sorted(snapshot.items())) or "(idle)"
    logger.info("heartbeat: %s", parts)
    if state_dir is not None and cfg is not None:
        health.write_status(
            state_dir=state_dir,
            cursor=cursor,
            metrics=snapshot,
            daily_cost_cap_usd=cfg.daily_cost_cap_usd,
            paused=paused,
            stop_requested=stop_requested,
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="imessage-bridge")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--once", action="store_true",
                        help="poll one tick and exit (useful for testing)")
    parser.add_argument("--reset-cursor", action="store_true",
                        help="re-seed cursor at MAX(rowid); skips backlog. "
                             "Use this AFTER restoring an old state.db.")
    parser.add_argument(
        "--skip-selftest", action="store_true",
        help="DEV ONLY: skip the Bash-deny security selftest. Refused unless "
             "stdin is a tty (so it cannot land in a launchd plist or "
             "systemd unit by accident).",
    )
    args = parser.parse_args(argv)

    # Hint to preflight where the config came from (for perms check).
    os.environ["CIMB_CONFIG_PATH"] = str(args.config)

    try:
        cfg = config_mod.load(args.config)
    except (FileNotFoundError, ValueError) as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2

    _setup_logging(cfg.debug)
    _install_signal_handlers()
    state_dir = state.DEFAULT_STATE_DIR
    try:
        state.init_state_dir(state_dir)
    except (state.SchemaTooNew, state.SchemaMigrationMissing) as e:
        print(f"state.db schema error: {e}", file=sys.stderr)
        return 5

    try:
        _preflight(state_dir)
    except RuntimeError as e:
        logger.error("preflight failed: %s", e)
        return 3

    # Empirical self-test: spawn one claude -p and try to invoke Bash.
    # Refuse to run the bridge if Bash IS executable, regardless of what
    # our config flags say. This is the only way to verify the tool-deny
    # boundary still holds across Claude Code version changes — the
    # documented flag semantics drifted at least once already (see
    # adversarial round 3 findings).
    #
    # --skip-selftest is a DEV-ONLY shortcut. It's load-bearing-dangerous:
    # if it gets baked into a launchd plist or a systemd unit, the daemon
    # silently runs without the empirical Bash-deny verification. To
    # prevent that, we refuse the flag unless stdin is a controlling tty
    # — launchd/systemd run without one.
    if args.skip_selftest:
        if not sys.stdin.isatty():
            print(
                "--skip-selftest is only allowed when running interactively "
                "(stdin is a tty). Refusing to skip the security selftest "
                "in non-interactive mode.",
                file=sys.stderr,
            )
            return 6
        logger.warning(
            "⚠️ SELFTEST SKIPPED — DEV MODE — "
            "DO NOT USE IN PRODUCTION"
        )
    else:
        # Trust-mode-agnostic selftests run in EVERY mode. They verify the
        # defenses that survive into coding/full modes (allowlist gate +
        # argv-injection refusal). Costs nothing — no claude calls.
        logger.info("running selftest: allowlist + argv invariants…")
        try:
            claude_runner.selftest_allowlist_enforced(
                allowlist=cfg.allowlist,
                allow_group_chat_guids=cfg.allow_group_chat_guids,
            )
            claude_runner.selftest_argv_invariants()
        except claude_runner.SelfTestFailed as e:
            logger.error("SECURITY SELF-TEST FAILED: %s", e)
            return 4

        # Bash-denial selftest is chat_only-specific. In coding/full
        # modes Bash is legitimately enabled and the test would
        # (correctly) detect Bash executing, which is no longer a
        # failure. Skip it.
        if cfg.trust_default == "chat_only":
            logger.info("running selftest: verifying Bash denial under chat_only…")
            try:
                claude_runner.selftest_bash_denied(
                    claude_bin=cfg.claude_binary,
                    timeout_seconds=min(cfg.per_call_timeout_seconds, 60),
                )
            except claude_runner.SelfTestFailed as e:
                logger.error("SECURITY SELF-TEST FAILED: %s", e)
                return 4
            except FileNotFoundError as e:
                logger.error("selftest setup error (claude binary?): %s", e)
                return 4
            except Exception as e:
                logger.exception("selftest crashed: %s", e)
                return 4

    # Memory backend instantiation. NoneBackend if config says so OR if
    # the trust default is chat_only (chat_only NEVER loads memory
    # regardless of memory.backend setting — defense in depth).
    global _memory_backend
    if cfg.trust_default == "chat_only" or cfg.memory_backend == "none":
        _memory_backend = memory_mod.NoneBackend()
        logger.info("memory backend: none (trust=%s, configured=%s)",
                    cfg.trust_default, cfg.memory_backend)
    else:
        _memory_backend = memory_mod.build_backend(
            backend_name=cfg.memory_backend,
            claude_md_params=cfg.memory_claude_md,
            custom_params=cfg.memory_custom,
        )
        logger.info("memory backend: %s", cfg.memory_backend)

    logger.info(
        "starting bridge: project_dir=%s allowlist=%d entries debug=%s trust=%s",
        cfg.project_directory,
        len(cfg.allowlist),
        cfg.debug,
        cfg.trust_default,
    )

    # First-run or reset cursor seeding.
    cursor = state.get_cursor(CURSOR_NAME, default=-1)
    if cursor < 0 or args.reset_cursor:
        seed = imessage_reader.latest_rowid()
        logger.info("seeding cursor at MAX(rowid)=%d (reset=%s)",
                    seed, args.reset_cursor)
        state.set_cursor(CURSOR_NAME, seed, allow_regression=True)
        cursor = seed

    poll = cfg.poll_interval_seconds
    last_prune = time.time()
    last_heartbeat = time.time()

    while _running:
        if _stop_requested(state_dir):
            break

        # NOTE: We no longer short-circuit the whole loop when PAUSE is
        # present. _handle_one's claude-invocation path checks pause
        # state itself and refuses the claude call, but command-dispatch
        # still runs — so /resume, /status, /help can be sent while
        # paused. Without this, /resume would be impossible over iMessage
        # once the bridge tripped its own circuit breaker.
        try:
            new_messages = list(imessage_reader.fetch_new_messages(cursor))
        except Exception as e:
            logger.exception("fetch_new_messages failed: %s", e)
            new_messages = []

        for msg in new_messages:
            # ORDER: cursor advances BEFORE send. A crash mid-send loses one
            # reply (recoverable) rather than producing duplicates on retry.
            try:
                state.set_cursor(CURSOR_NAME, msg.rowid)
            except state.CursorRegression as e:
                logger.error("cursor regression refused for rowid=%d: %s",
                             msg.rowid, e)
                continue
            try:
                _handle_one(msg, cfg)
            except Exception as e:
                _metrics["handler_exceptions"] += 1
                logger.exception("handler error on rowid=%s: %s", msg.rowid, e)
            cursor = msg.rowid

        # Periodic rate-counter pruning + heartbeat.
        now = time.time()
        if now - last_prune > 600:
            state.prune_reply_counter()
            last_prune = now
            # Daily backup check piggybacks on the 10-minute prune tick.
            # run_if_due is cheap when not actually due.
            try:
                backups.run_if_due(state_dir)
            except Exception as e:
                logger.warning("backup check failed: %s", e)
        if now - last_heartbeat > HEARTBEAT_INTERVAL_SECONDS:
            _heartbeat(
                state_dir=state_dir,
                cursor=cursor,
                cfg=cfg,
                paused=_is_paused(state_dir),
                stop_requested=False,
            )
            last_heartbeat = now

        if args.once:
            break
        for _ in range(int(poll * 10)):
            if not _running:
                break
            time.sleep(0.1)

    _heartbeat(
        state_dir=state_dir, cursor=cursor, cfg=cfg,
        paused=_is_paused(state_dir),
        stop_requested=True,
    )
    logger.info("bridge stopped at cursor=%d", cursor)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
