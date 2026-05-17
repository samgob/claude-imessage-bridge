"""Tests for chat.db ingestion.

These tests build a synthetic chat.db with the columns the reader queries
and verify:
  - SMS rows are filtered out (handle.service != 'iMessage')
  - is_from_me=1 rows are filtered out (outbound)
  - tapbacks / reactions / balloon-bundle / attachment rows are filtered out
  - Bodies above MAX_BODY_BYTES are truncated on a UTF-8 boundary
  - attributedBody parser refuses oversized blobs and rich-class archives
  - The Apple-epoch nanosecond -> ISO date conversion is correct
"""

from __future__ import annotations

import plistlib
import sqlite3
from pathlib import Path


from src import imessage_reader


# --- Schema helper ------------------------------------------------------

_CHATDB_SCHEMA = """
CREATE TABLE handle (
    ROWID INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT,
    service TEXT
);
CREATE TABLE chat (
    ROWID INTEGER PRIMARY KEY AUTOINCREMENT,
    guid TEXT,
    style INTEGER
);
CREATE TABLE message (
    ROWID INTEGER PRIMARY KEY AUTOINCREMENT,
    handle_id INTEGER,
    date INTEGER,
    text TEXT,
    attributedBody BLOB,
    is_from_me INTEGER DEFAULT 0,
    associated_message_guid TEXT,
    is_emote INTEGER DEFAULT 0,
    item_type INTEGER DEFAULT 0,
    balloon_bundle_id TEXT,
    cache_has_attachments INTEGER DEFAULT 0
);
CREATE TABLE chat_message_join (
    chat_id INTEGER,
    message_id INTEGER
);
CREATE TABLE attachment (
    ROWID INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT,
    mime_type TEXT
);
CREATE TABLE message_attachment_join (
    message_id INTEGER,
    attachment_id INTEGER
);
"""


def _make_chatdb(tmp_path: Path) -> Path:
    db = tmp_path / "fake_chat.db"
    conn = sqlite3.connect(str(db))
    conn.executescript(_CHATDB_SCHEMA)
    conn.commit()
    conn.close()
    return db


def _insert_message(
    db: Path,
    *,
    rowid: int,
    handle: str,
    service: str = "iMessage",
    chat_guid: str = "chat-1",
    chat_style: int = 45,  # 1:1
    text: str | None = "hello",
    attributed: bytes | None = None,
    is_from_me: int = 0,
    associated_message_guid: str | None = None,
    is_emote: int = 0,
    item_type: int = 0,
    balloon_bundle_id: str | None = None,
    cache_has_attachments: int = 0,
    date_ns: int = 700000000_000_000_000,  # ~2023 in Apple-ns
) -> None:
    conn = sqlite3.connect(str(db))
    try:
        # ensure handle exists
        h = conn.execute("SELECT ROWID FROM handle WHERE id = ?", (handle,)).fetchone()
        if h is None:
            conn.execute(
                "INSERT INTO handle (id, service) VALUES (?, ?)",
                (handle, service),
            )
            h_rowid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        else:
            h_rowid = h[0]
            conn.execute("UPDATE handle SET service = ? WHERE ROWID = ?",
                         (service, h_rowid))
        # ensure chat exists
        c = conn.execute("SELECT ROWID FROM chat WHERE guid = ?", (chat_guid,)).fetchone()
        if c is None:
            conn.execute(
                "INSERT INTO chat (guid, style) VALUES (?, ?)",
                (chat_guid, chat_style),
            )
            c_rowid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        else:
            c_rowid = c[0]
        conn.execute(
            "INSERT INTO message (ROWID, handle_id, date, text, attributedBody, "
            "is_from_me, associated_message_guid, is_emote, item_type, "
            "balloon_bundle_id, cache_has_attachments) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (rowid, h_rowid, date_ns, text, attributed, is_from_me,
             associated_message_guid, is_emote, item_type, balloon_bundle_id,
             cache_has_attachments),
        )
        conn.execute(
            "INSERT INTO chat_message_join (chat_id, message_id) VALUES (?, ?)",
            (c_rowid, rowid),
        )
        conn.commit()
    finally:
        conn.close()


def _insert_attachment(
    db: Path, *, message_rowid: int, filename: str, mime_type: str = "image/jpeg",
) -> int:
    """Insert an attachment row and join it to ``message_rowid``. Returns
    the new attachment ROWID."""
    conn = sqlite3.connect(str(db))
    try:
        conn.execute(
            "INSERT INTO attachment (filename, mime_type) VALUES (?, ?)",
            (filename, mime_type),
        )
        attach_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute(
            "INSERT INTO message_attachment_join "
            "(message_id, attachment_id) VALUES (?, ?)",
            (message_rowid, attach_id),
        )
        conn.commit()
        return attach_id
    finally:
        conn.close()


# --- SQL-layer filters -------------------------------------------------

def test_reader_returns_imessage_inbound(tmp_path: Path):
    db = _make_chatdb(tmp_path)
    _insert_message(db, rowid=1, handle="+15551234567", text="hello")
    msgs = list(imessage_reader.fetch_new_messages(0, chatdb=db))
    assert len(msgs) == 1
    assert msgs[0].rowid == 1
    assert msgs[0].body == "hello"
    assert msgs[0].sender_handle == "+15551234567"


def test_reader_filters_sms_rows(tmp_path: Path):
    db = _make_chatdb(tmp_path)
    _insert_message(db, rowid=1, handle="+15559999999", service="SMS", text="spoof")
    _insert_message(db, rowid=2, handle="+15551234567", service="iMessage", text="real")
    msgs = list(imessage_reader.fetch_new_messages(0, chatdb=db))
    assert [m.body for m in msgs] == ["real"]


def test_reader_filters_outbound(tmp_path: Path):
    db = _make_chatdb(tmp_path)
    _insert_message(db, rowid=1, handle="+15551234567", text="from me", is_from_me=1)
    _insert_message(db, rowid=2, handle="+15551234567", text="from them", is_from_me=0)
    msgs = list(imessage_reader.fetch_new_messages(0, chatdb=db))
    assert [m.body for m in msgs] == ["from them"]


def test_reader_filters_tapbacks(tmp_path: Path):
    db = _make_chatdb(tmp_path)
    _insert_message(
        db, rowid=1, handle="+15551234567", text="reaction",
        associated_message_guid="some-guid",
    )
    msgs = list(imessage_reader.fetch_new_messages(0, chatdb=db))
    assert msgs == []


def test_reader_filters_balloon_apps(tmp_path: Path):
    db = _make_chatdb(tmp_path)
    _insert_message(
        db, rowid=1, handle="+15551234567", text="pay",
        balloon_bundle_id="com.apple.messages.MSMessageExtensionBalloonPlugin:0000000000:com.apple.PassbookUIService.PeerPaymentMessagesExtension",
    )
    msgs = list(imessage_reader.fetch_new_messages(0, chatdb=db))
    assert msgs == []


def test_reader_surfaces_image_only_with_attachment_flag(tmp_path: Path):
    """Image-only rows used to be dropped at SQL — Sam got NO response when
    he sent images (reported 2026-05-17). Now they're surfaced with
    has_attachment=True and an empty body so the daemon can ack them.
    """
    db = _make_chatdb(tmp_path)
    _insert_message(
        db, rowid=1, handle="+15551234567", text="￼",  # OBJECT REPLACEMENT only
        cache_has_attachments=1,
    )
    msgs = list(imessage_reader.fetch_new_messages(0, chatdb=db))
    assert len(msgs) == 1
    assert msgs[0].has_attachment is True
    assert msgs[0].body == ""  # U+FFFC stripped → empty
    assert msgs[0].sender_handle == "+15551234567"


def test_reader_image_with_caption_strips_object_replacement(tmp_path: Path):
    """Image + caption: the caption text survives, U+FFFC is stripped."""
    db = _make_chatdb(tmp_path)
    _insert_message(
        db, rowid=1, handle="+15551234567",
        text="￼look at this screenshot",  # OBJECT REPL + caption
        cache_has_attachments=1,
    )
    msgs = list(imessage_reader.fetch_new_messages(0, chatdb=db))
    assert len(msgs) == 1
    assert msgs[0].has_attachment is True
    assert msgs[0].body == "look at this screenshot"


def test_reader_no_attachment_flag_for_text_only(tmp_path: Path):
    db = _make_chatdb(tmp_path)
    _insert_message(db, rowid=1, handle="+15551234567", text="hi")
    msgs = list(imessage_reader.fetch_new_messages(0, chatdb=db))
    assert msgs[0].has_attachment is False


def test_reader_filters_participant_events(tmp_path: Path):
    db = _make_chatdb(tmp_path)
    _insert_message(
        db, rowid=1, handle="+15551234567", text="X added Y",
        item_type=3,  # participant-add
    )
    msgs = list(imessage_reader.fetch_new_messages(0, chatdb=db))
    assert msgs == []


def test_reader_respects_last_rowid(tmp_path: Path):
    db = _make_chatdb(tmp_path)
    for i in range(1, 6):
        _insert_message(db, rowid=i, handle="+15551234567", text=f"msg{i}")
    msgs = list(imessage_reader.fetch_new_messages(3, chatdb=db))
    assert [m.rowid for m in msgs] == [4, 5]


# --- Body extraction / truncation --------------------------------------

def test_reader_truncates_oversized_body(tmp_path: Path):
    db = _make_chatdb(tmp_path)
    big = "A" * (imessage_reader.MAX_BODY_BYTES + 500)
    _insert_message(db, rowid=1, handle="+15551234567", text=big)
    msgs = list(imessage_reader.fetch_new_messages(0, chatdb=db))
    assert len(msgs) == 1
    assert len(msgs[0].body.encode("utf-8")) <= imessage_reader.MAX_BODY_BYTES
    assert msgs[0].body_truncated is True


def test_reader_yields_empty_body_as_skip_sentinel(tmp_path: Path):
    """Empty-body rows are yielded with sentinel sender so the daemon's
    cursor advances past them. Without this, the daemon would re-read
    the same unparseable rows on every poll forever.
    """
    db = _make_chatdb(tmp_path)
    _insert_message(db, rowid=1, handle="+15551234567", text="   ", attributed=None)
    msgs = list(imessage_reader.fetch_new_messages(0, chatdb=db))
    assert len(msgs) == 1
    assert msgs[0].rowid == 1
    assert msgs[0].sender_handle == "<empty-skip>"
    assert msgs[0].body == ""


def test_reader_falls_back_to_attributed_body(tmp_path: Path):
    db = _make_chatdb(tmp_path)
    # Build a minimal NSAttributedString-like archive
    archive = {
        "$objects": ["$null", "real message text"],
        "$top": {},
        "$version": 100000,
        "$archiver": "NSKeyedArchiver",
    }
    blob = plistlib.dumps(archive, fmt=plistlib.FMT_BINARY)
    _insert_message(
        db, rowid=1, handle="+15551234567",
        text=None, attributed=blob,
    )
    msgs = list(imessage_reader.fetch_new_messages(0, chatdb=db))
    assert len(msgs) == 1
    assert msgs[0].body == "real message text"


def test_reader_refuses_oversized_attributed_body(tmp_path: Path):
    db = _make_chatdb(tmp_path)
    too_big = b"\x00" * (imessage_reader.MAX_ATTRIBUTED_BODY_BYTES + 16)
    _insert_message(
        db, rowid=1, handle="+15551234567",
        text=None, attributed=too_big,
    )
    msgs = list(imessage_reader.fetch_new_messages(0, chatdb=db))
    # No usable body — row yielded with skip sentinel so cursor advances.
    assert len(msgs) == 1
    assert msgs[0].sender_handle == "<empty-skip>"
    assert msgs[0].body == ""


def test_reader_refuses_rich_classes_in_attributed_body(tmp_path: Path):
    db = _make_chatdb(tmp_path)
    # Archive contains a URL class — must be refused (rich content).
    archive = {
        "$objects": [
            "$null",
            "would-be body",
            {"$classname": "NSURL", "$classes": ["NSURL", "NSObject"]},
        ],
        "$top": {},
        "$version": 100000,
        "$archiver": "NSKeyedArchiver",
    }
    blob = plistlib.dumps(archive, fmt=plistlib.FMT_BINARY)
    _insert_message(
        db, rowid=1, handle="+15551234567",
        text=None, attributed=blob,
    )
    msgs = list(imessage_reader.fetch_new_messages(0, chatdb=db))
    # Parser refused; row yielded as empty-skip so cursor advances.
    assert len(msgs) == 1
    assert msgs[0].sender_handle == "<empty-skip>"
    assert msgs[0].body == ""


def test_reader_malformed_attributed_body_does_not_crash(tmp_path: Path):
    db = _make_chatdb(tmp_path)
    _insert_message(
        db, rowid=1, handle="+15551234567",
        text="visible text", attributed=b"\x00not a plist",
    )
    # The text column is preferred; malformed attributedBody is silently ignored.
    msgs = list(imessage_reader.fetch_new_messages(0, chatdb=db))
    assert len(msgs) == 1
    assert msgs[0].body == "visible text"


def test_reader_unparseable_attributed_body_empty_text_yields_skip(tmp_path: Path):
    """Regression: 2026-05-15 loop. Rows with unparseable attributedBody +
    empty text MUST yield (as empty-skip) so the daemon advances cursor.
    Previously the iterator silently `continue`d, causing the daemon to
    re-read the same rows every 3s and flood the log with warnings.
    """
    db = _make_chatdb(tmp_path)
    _insert_message(
        db, rowid=1, handle="+15551234567",
        text=None, attributed=b"\x00not a plist",
    )
    msgs = list(imessage_reader.fetch_new_messages(0, chatdb=db))
    assert len(msgs) == 1
    assert msgs[0].rowid == 1
    assert msgs[0].sender_handle == "<empty-skip>"
    assert msgs[0].body == ""


# --- Group chat flag ---------------------------------------------------

def test_reader_flags_group_chats(tmp_path: Path):
    db = _make_chatdb(tmp_path)
    _insert_message(
        db, rowid=1, handle="+15551234567",
        chat_guid="g-1", chat_style=43, text="hi all",
    )
    msgs = list(imessage_reader.fetch_new_messages(0, chatdb=db))
    assert len(msgs) == 1
    assert msgs[0].is_group is True


def test_reader_one_to_one_not_group(tmp_path: Path):
    db = _make_chatdb(tmp_path)
    _insert_message(
        db, rowid=1, handle="+15551234567",
        chat_guid="d-1", chat_style=45, text="hi",
    )
    msgs = list(imessage_reader.fetch_new_messages(0, chatdb=db))
    assert msgs[0].is_group is False


# --- Apple date conversion ---------------------------------------------

def test_apple_date_to_iso_nanoseconds():
    # 2024-01-15 00:00:00 UTC = Unix 1705276800 → Apple ns = (1705276800 - 978307200) * 1e9
    apple_ns = (1705276800 - 978307200) * 10**9
    iso = imessage_reader._apple_date_to_iso(apple_ns)
    assert iso == "2024-01-15T00:00:00Z"


def test_apple_date_to_iso_seconds_path():
    # Older rows: seconds since Apple epoch
    apple_s = 1705276800 - 978307200
    iso = imessage_reader._apple_date_to_iso(apple_s)
    assert iso == "2024-01-15T00:00:00Z"


# --- latest_rowid ------------------------------------------------------

def test_latest_rowid_returns_max(tmp_path: Path):
    db = _make_chatdb(tmp_path)
    _insert_message(db, rowid=1, handle="+15551234567")
    _insert_message(db, rowid=42, handle="+15551234567")
    assert imessage_reader.latest_rowid(chatdb=db) == 42


def test_latest_rowid_empty_db(tmp_path: Path):
    db = _make_chatdb(tmp_path)
    assert imessage_reader.latest_rowid(chatdb=db) == 0


def test_latest_rowid_missing_db(tmp_path: Path):
    assert imessage_reader.latest_rowid(chatdb=tmp_path / "nope.db") == 0


# --- Attachment path resolution ----------------------------------------

def test_attachment_path_surfaced_when_file_exists(tmp_path: Path, monkeypatch):
    """Image rows should surface the on-disk file path so the daemon can
    hand it to claude (so claude can Read it). Apple stores attachments
    under ~/Library/Messages/Attachments/...; we point _ATTACHMENT_ROOT
    at a tmp dir for the test."""
    db = _make_chatdb(tmp_path)
    fake_root = tmp_path / "Attachments"
    fake_root.mkdir()
    img = fake_root / "ab/12"
    img.mkdir(parents=True)
    img_path = img / "IMG_0001.jpeg"
    img_path.write_bytes(b"\xff\xd8\xff\xe0fakejpg")
    monkeypatch.setattr(imessage_reader, "_ATTACHMENT_ROOT", fake_root)

    _insert_message(
        db, rowid=1, handle="+15551234567", text="￼",
        cache_has_attachments=1,
    )
    _insert_attachment(db, message_rowid=1, filename=str(img_path))

    msgs = list(imessage_reader.fetch_new_messages(0, chatdb=db))
    assert len(msgs) == 1
    assert msgs[0].has_attachment is True
    assert msgs[0].attachment_paths == (str(img_path),)


def test_attachment_path_outside_root_rejected(tmp_path: Path, monkeypatch):
    """Path-traversal defense: a chat.db filename that resolves outside
    the attachment root is dropped (defense in depth; chat.db is
    user-writable so a malicious row could in theory craft this)."""
    db = _make_chatdb(tmp_path)
    fake_root = tmp_path / "Attachments"
    fake_root.mkdir()
    monkeypatch.setattr(imessage_reader, "_ATTACHMENT_ROOT", fake_root)

    # Create a file OUTSIDE the attachment root.
    bad = tmp_path / "elsewhere.jpeg"
    bad.write_bytes(b"x")

    _insert_message(
        db, rowid=1, handle="+15551234567", text="￼",
        cache_has_attachments=1,
    )
    _insert_attachment(db, message_rowid=1, filename=str(bad))

    msgs = list(imessage_reader.fetch_new_messages(0, chatdb=db))
    assert len(msgs) == 1
    assert msgs[0].attachment_paths == ()  # rejected


def test_attachment_path_missing_file_dropped(tmp_path: Path, monkeypatch):
    """If chat.db references a path but the file doesn't exist yet (e.g.
    iCloud download still in flight), drop the entry rather than feed
    claude a stale path."""
    db = _make_chatdb(tmp_path)
    fake_root = tmp_path / "Attachments"
    fake_root.mkdir()
    monkeypatch.setattr(imessage_reader, "_ATTACHMENT_ROOT", fake_root)

    _insert_message(
        db, rowid=1, handle="+15551234567", text="￼",
        cache_has_attachments=1,
    )
    _insert_attachment(
        db, message_rowid=1, filename=str(fake_root / "ghost.jpeg"),
    )

    msgs = list(imessage_reader.fetch_new_messages(0, chatdb=db))
    assert len(msgs) == 1
    assert msgs[0].attachment_paths == ()


def test_attachment_path_count_capped(tmp_path: Path, monkeypatch):
    """We only surface up to MAX_ATTACHMENTS_PER_MESSAGE paths per message."""
    db = _make_chatdb(tmp_path)
    fake_root = tmp_path / "Attachments"
    fake_root.mkdir()
    monkeypatch.setattr(imessage_reader, "_ATTACHMENT_ROOT", fake_root)

    _insert_message(
        db, rowid=1, handle="+15551234567", text="￼",
        cache_has_attachments=1,
    )
    # Insert more than the cap
    over_cap = imessage_reader.MAX_ATTACHMENTS_PER_MESSAGE + 3
    for i in range(over_cap):
        p = fake_root / f"img_{i}.jpeg"
        p.write_bytes(b"x")
        _insert_attachment(db, message_rowid=1, filename=str(p))

    msgs = list(imessage_reader.fetch_new_messages(0, chatdb=db))
    assert len(msgs) == 1
    assert len(msgs[0].attachment_paths) == imessage_reader.MAX_ATTACHMENTS_PER_MESSAGE


def test_text_only_message_has_empty_attachment_paths(tmp_path: Path):
    db = _make_chatdb(tmp_path)
    _insert_message(db, rowid=1, handle="+15551234567", text="hello")
    msgs = list(imessage_reader.fetch_new_messages(0, chatdb=db))
    assert msgs[0].attachment_paths == ()
