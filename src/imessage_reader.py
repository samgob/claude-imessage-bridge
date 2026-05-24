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

Cursor-advance semantics: every SQL row returned MUST yield a Message,
even when we have no usable body or no sender. The daemon advances the
chat.db cursor only for rows the iterator emits — silently `continue`ing
on a skip causes the daemon to re-read the same rows on every 3s poll
forever (and re-emit any warnings they trigger). Rows we can't process
are yielded with sender_handle="<empty-skip>" so the daemon's allowlist
gate drops them as invalid-handle-format, audits the drop, and advances
past them.
"""

from __future__ import annotations

import logging
import plistlib
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Final, Iterator, Optional

from . import imessage_sender

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

# Max attachments per message we'll surface. Bounds prompt growth and
# protects against pathological group-shared albums.
MAX_ATTACHMENTS_PER_MESSAGE: Final = 5

# Allowed root for attachment paths. Apple stores all iMessage attachments
# under this prefix; any "filename" in chat.db that resolves outside this
# tree is rejected as a path-traversal attempt (defense in depth — a
# write-cap'd chat.db field shouldn't be attacker-controllable, but the
# cost of the check is one stat).
_ATTACHMENT_ROOT: Final = Path.home() / "Library" / "Messages" / "Attachments"

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
    has_attachment: bool = False  # row had cache_has_attachments=1 in chat.db
    # Local filesystem paths of attachment files. Vetted by
    # _resolve_attachment_paths to live under ~/Library/Messages/Attachments/.
    # Capped by MAX_ATTACHMENTS_PER_MESSAGE; non-existent files are dropped.
    attachment_paths: tuple = ()  # tuple[str, ...] — frozen dataclass


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
        # DEBUG, not WARNING. Modern macOS iMessage rows frequently carry
        # attributedBody payloads in formats plistlib can't decode (typedstream
        # archive, NSKeyedArchiver variants), and we always have a fallback
        # path (text column, or yield-as-skip so the daemon advances cursor).
        # WARNING-level here caused log floods on benign skipped rows.
        logger.debug("attributedBody plist parse failed: %s", e)
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


def _resolve_attachment_paths(
    conn: sqlite3.Connection, message_rowid: int,
) -> tuple:
    """Look up attachment file paths for ``message_rowid``.

    Returns a tuple of absolute path strings, capped at
    MAX_ATTACHMENTS_PER_MESSAGE. Paths that don't resolve under
    _ATTACHMENT_ROOT, or that don't exist on disk, are dropped.
    """
    rows = conn.execute(
        "SELECT a.filename "
        "FROM attachment AS a "
        "JOIN message_attachment_join AS maj "
        "  ON maj.attachment_id = a.ROWID "
        "WHERE maj.message_id = ? "
        "ORDER BY a.ROWID ASC "
        "LIMIT ?",
        (message_rowid, MAX_ATTACHMENTS_PER_MESSAGE),
    ).fetchall()
    out: list = []
    for r in rows:
        filename = r["filename"]
        if not isinstance(filename, str) or not filename:
            continue
        try:
            p = Path(filename).expanduser().resolve(strict=False)
        except (OSError, RuntimeError):
            continue
        # Defense in depth: must resolve under Apple's attachment root.
        try:
            p.relative_to(_ATTACHMENT_ROOT.resolve())
        except ValueError:
            logger.debug(
                "attachment path %r outside %s — dropping",
                filename, _ATTACHMENT_ROOT,
            )
            continue
        if not p.is_file():
            logger.debug("attachment file missing at %s — dropping", p)
            continue
        out.append(str(p))
    return tuple(out)


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
# NOTE on attachments: we no longer drop attachment-bearing rows at SQL.
# Doing so meant images sent to the bridge produced ZERO response — bad UX
# (Sam reported this 2026-05-17). Instead we:
#   (a) surface the row with has_attachment=True
#   (b) strip U+FFFC OBJECT REPLACEMENT chars from the body, so a caption
#       (e.g. "look at this <image>") comes through as plain text
#   (c) let the daemon decide: if there's a caption, process it as text;
#       if image-only, send a polite "images aren't supported yet" ack.
# We still do NOT parse the attachment payload — the threat model's
# "no attachment parsing in v0" constraint holds.
_FETCH_SQL: Final = """
SELECT
    m.ROWID                AS rowid,
    c.guid                 AS chat_guid,
    c.style                AS chat_style,
    h.id                   AS sender_handle,
    m.date                 AS apple_date,
    m.text                 AS text_col,
    m.attributedBody       AS attributed_body,
    COALESCE(m.cache_has_attachments, 0) AS has_attachment
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
            sender = row["sender_handle"]
            has_attachment = bool(row["has_attachment"])
            # Image/attachment caption text in chat.db is wrapped around
            # U+FFFC (OBJECT REPLACEMENT). Strip those so a real caption
            # survives and an image-only message becomes an empty body.
            if has_attachment and body:
                body = body.replace("￼", "").strip()
            # Resolve attachment file paths (vetted against ATTACHMENT_ROOT
            # and existence-checked). Empty tuple if none survive.
            attachment_paths: tuple = ()
            if has_attachment:
                attachment_paths = _resolve_attachment_paths(
                    conn, int(row["rowid"]),
                )
            # Cursor-advance-on-skip: yield as empty-skip when there's
            # nothing actionable. Three skip conditions:
            #   1. No sender (defensive)
            #   2. No body AND no attachment marker — nothing to respond to
            #   3. has_attachment=True BUT no resolved paths AND no caption —
            #      almost always an iCloud sync artifact (link previews,
            #      audio-message metadata, delayed echo of an earlier
            #      outbound). Sam saw spontaneous "📎 try resending" acks
            #      fire hours after any real message activity (2026-05-19).
            #      We silently advance the cursor instead of pestering the
            #      user. If a real image was just slow to download, the
            #      user re-sends — that's the right cost/UX tradeoff.
            no_actionable_content = (
                (not body.strip())
                and (not has_attachment or not attachment_paths)
            )
            if (not sender) or no_actionable_content:
                yield Message(
                    rowid=int(row["rowid"]),
                    chat_guid=row["chat_guid"] or "",
                    is_group=(row["chat_style"] == 43),
                    sender_handle="<empty-skip>",
                    timestamp_iso=_apple_date_to_iso(row["apple_date"]),
                    body="",
                    body_truncated=False,
                    parse_warning=warning,
                    # Clear has_attachment on skip-yields so a downstream
                    # consumer that ignores sender_handle can't accidentally
                    # hit the attachment branch.
                    has_attachment=False,
                    attachment_paths=(),
                )
                continue
            yield Message(
                rowid=int(row["rowid"]),
                chat_guid=row["chat_guid"] or "",
                is_group=(row["chat_style"] == 43),  # 43 group, 45 1:1
                sender_handle=str(sender),
                timestamp_iso=_apple_date_to_iso(row["apple_date"]),
                body=body,
                body_truncated=truncated,
                parse_warning=warning,
                has_attachment=has_attachment,
                attachment_paths=attachment_paths,
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

    # Strip BiDi format chars, zero-width chars, and C0/C1 controls
    # from inbound bodies. Without this, a sender could embed
    # invisible chars that make "what's logged" differ from "what the
    # model sees" differ from "what the recipient renders" — a
    # forensics gap and (with prompt injection) a real attack surface.
    # The outbound sender already does this; keep both sides aligned.
    body = imessage_sender.strip_display_attacks(body)

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
