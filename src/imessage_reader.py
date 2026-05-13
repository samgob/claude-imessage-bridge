"""Read new iMessages from ~/Library/Messages/chat.db.

Security model (see docs/THREAT_MODEL.md S1):

- SQLite opened with ``?mode=ro`` only — NOT ``immutable=1``. The chat.db
  file is written to continuously by Apple's imagent process; the
  ``immutable`` flag tells SQLite the file won't change and would cause
  stale-page reads.
- Only ``handle.service = 'iMessage'`` rows are returned. SMS rows are
  dropped at the SQL layer; caller-ID on SMS is trivially spoofable, so
  honoring them would defeat any phone-number allowlist entry.
- Hard cap on body length we extract (``MAX_BODY_BYTES``).
- ``attributedBody`` (binary plist) parsed with stdlib ``plistlib`` only;
  on parse failure we fall back to the ``text`` column and log a warning.
- Group chats are flagged but not delivered to callers in v0 unless the
  caller opts in by GUID (the caller does its own allowlist check).
- Tapbacks / reactions / message edits-as-separate-rows are filtered out
  by ``associated_message_guid`` and ``associated_message_type``.

We do not parse attachments in v0. The attachment table is documented in
the threat model as a future concern.
"""

from __future__ import annotations

import logging
import plistlib
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Final, Iterator, Optional

logger = logging.getLogger(__name__)

DEFAULT_CHATDB: Final = Path.home() / "Library" / "Messages" / "chat.db"

# Cap on body length we'll extract. Bodies above this are truncated; the
# truncation is recorded on the Message so a caller can decide whether to
# treat the truncation as suspicious.
MAX_BODY_BYTES: Final = 16 * 1024

# Hard cap on the attributedBody binary plist size we'll hand to plistlib.
# Above this we refuse to parse and fall back to the text column. Caps DoS
# via pathological plist structure and limits the time/memory a single
# malicious row can consume.
MAX_ATTRIBUTED_BODY_BYTES: Final = 256 * 1024

# Apple's "Mac absolute time" epoch: 2001-01-01 00:00:00 UTC.
# message.date is nanoseconds since this epoch (modern macOS) OR seconds
# (very old rows). We disambiguate by magnitude.
_APPLE_EPOCH_OFFSET: Final = 978307200  # Unix seconds at 2001-01-01 UTC


def _apple_date_to_iso(value: int) -> str:
    """Convert chat.db's message.date int to ISO-8601 UTC."""
    if value is None:
        return ""
    # Heuristic: rows after ~2014 use nanoseconds; values are huge.
    # Threshold of 1e12 separates the two scales (post-2001 seconds vs ns).
    if value > 10**12:
        seconds = value / 1_000_000_000
    else:
        seconds = float(value)
    unix = seconds + _APPLE_EPOCH_OFFSET
    return (
        datetime.fromtimestamp(unix, tz=timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )


@dataclass(frozen=True)
class Message:
    """One inbound iMessage we want to consider routing."""

    rowid: int
    chat_guid: str            # the conversation (1:1 or group)
    is_group: bool            # True if chat.style indicates a group
    sender_handle: str        # raw from chat.db (caller normalizes)
    timestamp_iso: str        # UTC ISO-8601
    body: str                 # capped at MAX_BODY_BYTES, BiDi NOT yet stripped
    body_truncated: bool      # True if body was longer than the cap
    parse_warning: Optional[str] = None  # set when attributedBody parse failed


def _extract_attributed_body_text(blob: bytes) -> Optional[str]:
    """Best-effort extraction of the text payload from an attributedBody blob.

    **v0 policy is intentionally conservative.** The heuristic of "first
    non-boilerplate string in $objects" can be tricked by attacker-controlled
    fields (sender display name, contact card text, link-preview titles,
    attachment filenames). Until we have a vetted parser that reads only
    the NSAttributedString text field at a known archive path, we treat
    attributedBody as untrusted decoration and prefer the ``text`` column.

    Returns None in nearly all cases; callers fall back to ``text``. We
    still attempt a parse for *empty-text + plain-attributed* rows since
    that's the modern case where the body lives only in attributedBody
    (no enrichment, no preview) — but we require the plist to look like a
    "boring" attributed string (no class types beyond NSAttributedString).

    Any exception during parsing is caught and logged as a warning; we
    NEVER let a malformed blob crash the daemon.
    """
    if not blob:
        return None
    if len(blob) > MAX_ATTRIBUTED_BODY_BYTES:
        logger.warning(
            "attributedBody too large (%d bytes); skipping parse",
            len(blob),
        )
        return None
    try:
        archive = plistlib.loads(blob)
    except Exception as e:
        logger.warning("attributedBody plist parse failed: %s", e)
        return None

    if not isinstance(archive, dict):
        return None
    objs = archive.get("$objects")
    if not isinstance(objs, list):
        return None

    # Allowed wrapper class names — anything else means this archive carries
    # rich content (mentions, contacts, link previews) and we can't safely
    # pick "the body" without risking attacker-controlled fields.
    boring_classes = {
        "NSString", "NSMutableString",
        "NSAttributedString", "NSMutableAttributedString",
        "NSConcreteAttributedString",
        "NSDictionary", "NSMutableDictionary",
    }
    skip = boring_classes | {"$null"}

    # Find class entries by walking $class refs; if ANY $class refers to
    # something outside boring_classes (e.g., URL, ContactCard), bail out.
    for item in objs:
        if isinstance(item, dict) and "$classname" in item:
            cname = item.get("$classname")
            if isinstance(cname, str) and cname not in boring_classes:
                logger.debug(
                    "attributedBody contains non-boring class %r; skipping",
                    cname,
                )
                return None

    # Among the remaining strings, the first non-skip one with length > 0
    # is our best guess. Cap how many we inspect to bound DoS.
    inspected = 0
    for item in objs:
        inspected += 1
        if inspected > 1000:
            logger.warning("attributedBody $objects too long; skipping")
            return None
        if isinstance(item, str) and item not in skip and item.strip():
            return item
    return None


def _connect(chatdb: Path) -> sqlite3.Connection:
    """Open chat.db read-only without the immutable flag.

    See threat model S1: ``immutable=1`` is unsafe here because chat.db
    is actively written by imagent. We use ``mode=ro`` only.
    """
    uri = f"file:{chatdb}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=5.0)
    conn.row_factory = sqlite3.Row
    return conn


# SQL: select recent inbound iMessage-service rows above last_rowid.
# Filters applied at the SQL layer (defense in depth):
#   m.is_from_me = 0                 — inbound only
#   h.service = 'iMessage'           — drop SMS (caller-ID spoofable)
#   m.associated_message_guid IS NULL — drop tapbacks/reactions
#   m.is_emote = 0                   — drop expressive-effect-only
#   m.item_type = 0                  — type 0 is "regular message"; skip
#                                       participant-add/leave/etc. events
#   m.balloon_bundle_id IS NULL      — drop Apple Pay, Polls, Digital Touch,
#                                       Animoji, third-party iMessage apps —
#                                       their attributedBody contains app
#                                       metadata, not a user message
#   m.cache_has_attachments = 0      — v0 doesn't parse attachments; the
#                                       text column for these often contains
#                                       only U+FFFC OBJECT REPLACEMENT chars
_FETCH_SQL: Final = """
SELECT
    m.ROWID                AS rowid,
    c.guid                 AS chat_guid,
    c.style                AS chat_style,
    h.id                   AS sender_handle,
    m.date                 AS apple_date,
    m.text                 AS text_col,
    m.attributedBody       AS attributed_body
FROM message AS m
JOIN chat_message_join AS cmj ON cmj.message_id = m.ROWID
JOIN chat              AS c   ON c.ROWID       = cmj.chat_id
LEFT JOIN handle       AS h   ON h.ROWID       = m.handle_id
WHERE m.ROWID > ?
  AND m.is_from_me = 0
  AND h.service = 'iMessage'
  AND m.associated_message_guid IS NULL
  AND COALESCE(m.is_emote, 0) = 0
  AND COALESCE(m.item_type, 0) = 0
  AND m.balloon_bundle_id IS NULL
  AND COALESCE(m.cache_has_attachments, 0) = 0
ORDER BY m.ROWID ASC
LIMIT ?
"""


def fetch_new_messages(
    last_rowid: int,
    *,
    chatdb: Path = DEFAULT_CHATDB,
    limit: int = 100,
) -> Iterator[Message]:
    """Yield new messages with ROWID > last_rowid.

    Bounded by ``limit`` per call so a backlog can't OOM us in one tick.
    The daemon calls this in a loop until the result is empty, advancing
    last_rowid each round.
    """
    if not chatdb.exists():
        logger.warning("chat.db not found at %s — Full Disk Access?", chatdb)
        return

    with _connect(chatdb) as conn:
        rows = conn.execute(_FETCH_SQL, (last_rowid, limit)).fetchall()

    for row in rows:
        body, truncated, warning = _row_body(row)
        # Skip rows with no body content. iMessage may have e.g. sticker
        # rows where both text and attributedBody yield nothing useful.
        if not body.strip():
            continue
        sender = row["sender_handle"]
        if not sender:
            # Shouldn't happen for iMessage-service rows, but defensively skip.
            continue
        yield Message(
            rowid=int(row["rowid"]),
            chat_guid=row["chat_guid"] or "",
            is_group=(row["chat_style"] == 43),  # 43 = group, 45 = 1:1 in chat.db
            sender_handle=str(sender),
            timestamp_iso=_apple_date_to_iso(row["apple_date"]),
            body=body,
            body_truncated=truncated,
            parse_warning=warning,
        )


def _row_body(row: sqlite3.Row) -> tuple[str, bool, Optional[str]]:
    """Extract message body text, with cap + parse-warning bookkeeping."""
    text_col = row["text_col"]
    attributed = row["attributed_body"]
    warning: Optional[str] = None
    body: str = ""

    if isinstance(text_col, str) and text_col.strip():
        body = text_col
    elif attributed is not None:
        extracted = _extract_attributed_body_text(attributed)
        if extracted is not None:
            body = extracted
        else:
            warning = "attributedBody parse failed; no fallback text"
    else:
        # No usable body.
        return ("", False, None)

    encoded = body.encode("utf-8")
    if len(encoded) <= MAX_BODY_BYTES:
        return (body, False, warning)
    # Truncate on a UTF-8 boundary.
    cut = MAX_BODY_BYTES
    while cut > 0 and (encoded[cut] & 0xC0) == 0x80:
        cut -= 1
    truncated = encoded[:cut].decode("utf-8", errors="ignore")
    return (truncated, True, warning)


def latest_rowid(chatdb: Path = DEFAULT_CHATDB) -> int:
    """Return the highest message.ROWID currently in the database, or 0.

    Useful at first startup to skip historical messages — the daemon's
    cursor begins from "everything from now on" rather than replaying
    every iMessage ever received.
    """
    if not chatdb.exists():
        return 0
    with _connect(chatdb) as conn:
        row = conn.execute("SELECT MAX(ROWID) AS m FROM message").fetchone()
    return int(row["m"] or 0)
