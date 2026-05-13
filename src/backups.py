"""Nightly state.db rotation.

The cursor-regression guard in state.set_cursor exists precisely so a
restored backup of state.db can't replay messages. That guard is
theoretical without actual backups. This module schedules a daily
snapshot at 4am local time:

  ~/.claude-imessage-bridge/backups/state-YYYYMMDD.db        (recent)
  ~/.claude-imessage-bridge/backups/state-YYYYMMDD.db.gz     (older)

Rotation policy:
  - One backup per UTC day (idempotent — re-running the same day is a
    no-op if today's file already exists).
  - Backups older than 3 days are gzip-compressed.
  - Backups older than 14 days are deleted.
  - Backup file mode: 0o600 (state.db carries audit history).
  - Backup directory mode: 0o700.

Backup mechanism: SQLite ``BEGIN IMMEDIATE`` lock + ``shutil.copy2`` of
the underlying file. This is safe even while the daemon is writing —
SQLite serializes writes inside the BEGIN IMMEDIATE transaction.

The daemon calls ``run_if_due`` once per main-loop tick. The function
short-circuits cheaply on the vast majority of ticks (date check only).
"""

from __future__ import annotations

import datetime as _dt
import gzip
import logging
import os
import shutil
import sqlite3
from pathlib import Path

logger = logging.getLogger(__name__)

# When to run, in local-time hour. 4am is the default Sam-conventional
# off-peak hour. Configurable later if needed.
BACKUP_HOUR_LOCAL: int = 4

# Compress backups older than this many days.
COMPRESS_AFTER_DAYS: int = 3

# Delete backups older than this many days. (Includes the .db.gz files.)
RETAIN_DAYS: int = 14

BACKUP_DIR_NAME = "backups"


def _today_local() -> _dt.date:
    return _dt.datetime.now().date()


def _backup_filename_for(date: _dt.date) -> str:
    return f"state-{date.strftime('%Y%m%d')}.db"


def _ensure_backup_dir(state_dir: Path) -> Path:
    d = state_dir / BACKUP_DIR_NAME
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    return d


def _is_backup_filename(name: str) -> bool:
    """Identify state-YYYYMMDD.db or state-YYYYMMDD.db.gz files only.

    Conservative pattern so we never act on operator-placed files in
    the backups dir.
    """
    if not name.startswith("state-"):
        return False
    if not (name.endswith(".db") or name.endswith(".db.gz")):
        return False
    return True


def _parse_backup_date(name: str) -> _dt.date | None:
    """Extract the date from a backup filename. None if unparseable."""
    if not _is_backup_filename(name):
        return None
    # state-YYYYMMDD.db[.gz] → strip prefix + suffix, parse middle
    body = name[len("state-"):]
    if body.endswith(".db.gz"):
        body = body[:-len(".db.gz")]
    elif body.endswith(".db"):
        body = body[:-len(".db")]
    try:
        return _dt.datetime.strptime(body, "%Y%m%d").date()
    except ValueError:
        return None


def _snapshot_db(state_db: Path, dest: Path) -> None:
    """Copy state.db to dest while holding a SQLite write lock.

    BEGIN IMMEDIATE blocks any concurrent writer (which means a daemon
    write during the copy is delayed by exactly the copy duration —
    milliseconds for a typical state.db). After the lock the file is
    safe to copy.
    """
    conn = sqlite3.connect(str(state_db), timeout=10.0)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            # shutil.copy2 preserves mtime/atime so the backup's
            # filesystem date is accurate (we still parse the date from
            # the filename — this is for ls-readability).
            shutil.copy2(state_db, dest)
        finally:
            conn.rollback()  # release the lock (we wrote nothing)
    finally:
        conn.close()
    try:
        os.chmod(dest, 0o600)
    except OSError:
        pass


def _compress(path: Path) -> Path:
    """Gzip ``path`` in place; return the new .gz path. The original is
    removed only after the .gz is successfully written."""
    gz_path = Path(str(path) + ".gz")
    with path.open("rb") as src, gzip.open(gz_path, "wb", compresslevel=6) as dst:
        shutil.copyfileobj(src, dst)
    try:
        os.chmod(gz_path, 0o600)
    except OSError:
        pass
    path.unlink()
    return gz_path


def _prune_and_compress(backup_dir: Path, today: _dt.date) -> tuple[int, int]:
    """Apply retention + compression policy. Returns ``(compressed, deleted)``."""
    compressed = 0
    deleted = 0
    try:
        entries = list(backup_dir.iterdir())
    except OSError:
        return (0, 0)
    for entry in entries:
        if not entry.is_file():
            continue
        date = _parse_backup_date(entry.name)
        if date is None:
            continue
        age_days = (today - date).days
        if age_days < 0:
            # Future-dated backup? Operator weirdness; leave alone.
            continue
        if age_days > RETAIN_DAYS:
            try:
                entry.unlink()
                deleted += 1
            except OSError as e:
                logger.warning("could not delete old backup %s: %s", entry, e)
            continue
        if age_days >= COMPRESS_AFTER_DAYS and entry.suffix == ".db":
            try:
                _compress(entry)
                compressed += 1
            except OSError as e:
                logger.warning("could not compress backup %s: %s", entry, e)
    return (compressed, deleted)


# Track the last backup we wrote so we don't re-stat the dir on every
# tick. ``None`` means "haven't checked yet this run."
_last_backup_date: _dt.date | None = None


def run_if_due(state_dir: Path) -> bool:
    """Run a backup if it's past BACKUP_HOUR_LOCAL local time and we
    haven't backed up today yet. Returns True if a backup happened.

    Cheap on most ticks: a single ``datetime.now()`` + dict check.
    """
    global _last_backup_date
    now = _dt.datetime.now()
    today = now.date()

    if _last_backup_date == today:
        return False
    if now.hour < BACKUP_HOUR_LOCAL:
        return False

    state_db = state_dir / "state.db"
    if not state_db.is_file():
        return False

    backup_dir = _ensure_backup_dir(state_dir)
    target = backup_dir / _backup_filename_for(today)

    # Idempotent: if today's backup already exists (e.g., daemon
    # restarted after running), respect it.
    target_gz = Path(str(target) + ".gz")
    if target.exists() or target_gz.exists():
        _last_backup_date = today
        return False

    try:
        _snapshot_db(state_db, target)
        logger.info("backup written: %s", target)
    except (OSError, sqlite3.Error) as e:
        logger.warning("backup failed: %s", e)
        return False

    compressed, deleted = _prune_and_compress(backup_dir, today)
    if compressed or deleted:
        logger.info(
            "backup rotation: compressed=%d deleted=%d", compressed, deleted,
        )

    _last_backup_date = today
    return True
