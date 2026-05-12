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
import logging
import os
import shutil
import signal
import sys
import time
from collections import Counter
from pathlib import Path

from . import config as config_mod
from . import imessage_reader
from . import imessage_sender
from . import state

logger = logging.getLogger("imessage_bridge")

DEFAULT_CONFIG_PATH = Path.home() / ".claude-imessage-bridge" / "config.yaml"
CURSOR_NAME = "chatdb_last_rowid"
HEARTBEAT_INTERVAL_SECONDS = 300

_running = True
_metrics = Counter()


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
        )
        return

    snippet = msg.body[:200].replace("\n", " ")
    reply_body = f"Echo: {snippet}"
    if msg.body_truncated:
        reply_body += "\n(note: your message was truncated to 16KB before processing)"

    try:
        imessage_sender.send(
            imessage_sender.SendRequest(handle=norm, body=reply_body),
            dry_run=False,
        )
        _metrics["replies"] += 1
        state.audit(
            handle_redacted=redacted,
            direction="out",
            kind="reply",
            detail="echo",
            reply_bytes=len(reply_body.encode("utf-8")),
        )
    except imessage_sender.SendError as e:
        _metrics["send_errors"] += 1
        logger.error("send failed: %s", e)
        state.audit(
            handle_redacted=redacted,
            direction="out",
            kind="drop",
            detail=f"send-error:{type(e).__name__}",  # no raw message
        )


# ---------------------------------------------------------------------------
# Kill-switch & heartbeat
# ---------------------------------------------------------------------------

def _is_paused(state_dir: Path) -> bool:
    return (state_dir / "PAUSE").exists()


def _stop_requested(state_dir: Path) -> bool:
    if (state_dir / "STOP").exists():
        logger.warning("STOP file present at %s — exiting cleanly", state_dir / "STOP")
        return True
    return False


def _heartbeat() -> None:
    """Periodic summary log line. Captures the metric counters and resets."""
    snapshot = dict(_metrics)
    _metrics.clear()
    parts = " ".join(f"{k}={v}" for k, v in sorted(snapshot.items())) or "(idle)"
    logger.info("heartbeat: %s", parts)


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
    state.init_state_dir(state_dir)

    try:
        _preflight(state_dir)
    except RuntimeError as e:
        logger.error("preflight failed: %s", e)
        return 3

    logger.info(
        "starting bridge: project_dir=%s allowlist=%d entries debug=%s",
        cfg.project_directory,
        len(cfg.allowlist),
        cfg.debug,
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

        if _is_paused(state_dir):
            logger.info("PAUSE file present, idling")
            time.sleep(poll)
            continue

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
        if now - last_heartbeat > HEARTBEAT_INTERVAL_SECONDS:
            _heartbeat()
            last_heartbeat = now

        if args.once:
            break
        for _ in range(int(poll * 10)):
            if not _running:
                break
            time.sleep(0.1)

    _heartbeat()
    logger.info("bridge stopped at cursor=%d", cursor)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
