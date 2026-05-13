"""Tests for nightly state.db backup rotation.

Patches ``datetime.datetime.now`` to drive the time-based logic
deterministically rather than wall-clock waiting.
"""

from __future__ import annotations

import datetime as _dt
import gzip
from pathlib import Path


from src import backups, state


# --- Helpers -------------------------------------------------------------

class _FakeDT:
    """Pin datetime.now() to a fixed value for testing."""

    def __init__(self, fixed: _dt.datetime):
        self._fixed = fixed

    def install(self, monkeypatch):
        real_dt = _dt.datetime

        class _Patched(real_dt):
            @classmethod
            def now(cls, tz=None):
                if tz is not None:
                    return self._fixed.replace(tzinfo=tz)
                return self._fixed

        monkeypatch.setattr(backups, "_dt", _dt)
        monkeypatch.setattr(_dt, "datetime", _Patched)


def _reset_module_state():
    backups._last_backup_date = None


# --- _parse_backup_date ---------------------------------------------------

def test_parse_backup_filename_db():
    assert backups._parse_backup_date("state-20260512.db") == _dt.date(2026, 5, 12)


def test_parse_backup_filename_gz():
    assert backups._parse_backup_date("state-20260512.db.gz") == _dt.date(2026, 5, 12)


def test_parse_backup_filename_rejects_unrelated():
    assert backups._parse_backup_date("state.db") is None
    assert backups._parse_backup_date("backup.db") is None
    assert backups._parse_backup_date("state-bogus.db") is None
    assert backups._parse_backup_date("random.txt") is None


# --- run_if_due -----------------------------------------------------------

def test_run_if_due_skips_before_backup_hour(state_dir: Path, monkeypatch):
    _reset_module_state()
    state.init_state_dir(state_dir)
    fixed = _dt.datetime(2026, 5, 13, 3, 30, 0)  # 3:30am, before 4am
    _FakeDT(fixed).install(monkeypatch)

    ran = backups.run_if_due(state_dir)
    assert ran is False
    assert not (state_dir / backups.BACKUP_DIR_NAME).exists() or \
        len(list((state_dir / backups.BACKUP_DIR_NAME).iterdir())) == 0


def test_run_if_due_creates_backup_after_hour(state_dir: Path, monkeypatch):
    _reset_module_state()
    state.init_state_dir(state_dir)
    fixed = _dt.datetime(2026, 5, 13, 4, 5, 0)  # 4:05am
    _FakeDT(fixed).install(monkeypatch)

    ran = backups.run_if_due(state_dir)
    assert ran is True
    backup_dir = state_dir / backups.BACKUP_DIR_NAME
    expected = backup_dir / "state-20260513.db"
    assert expected.exists()
    mode = expected.stat().st_mode & 0o777
    assert mode == 0o600


def test_run_if_due_idempotent_same_day(state_dir: Path, monkeypatch):
    _reset_module_state()
    state.init_state_dir(state_dir)
    fixed = _dt.datetime(2026, 5, 13, 4, 5, 0)
    _FakeDT(fixed).install(monkeypatch)

    backups.run_if_due(state_dir)
    second = backups.run_if_due(state_dir)
    assert second is False  # second call is a no-op


def test_run_if_due_skips_if_today_file_already_exists(state_dir: Path, monkeypatch):
    _reset_module_state()
    state.init_state_dir(state_dir)
    fixed = _dt.datetime(2026, 5, 13, 4, 5, 0)
    _FakeDT(fixed).install(monkeypatch)
    # Pre-create today's backup file (e.g., as if daemon was restarted).
    backup_dir = state_dir / backups.BACKUP_DIR_NAME
    backup_dir.mkdir()
    (backup_dir / "state-20260513.db").write_bytes(b"existing")

    ran = backups.run_if_due(state_dir)
    assert ran is False  # respects existing file
    # And the file should be untouched.
    assert (backup_dir / "state-20260513.db").read_bytes() == b"existing"


def test_run_if_due_missing_state_db_is_noop(state_dir: Path, monkeypatch):
    """If state.db doesn't exist yet, backup runs are a no-op (not an error)."""
    _reset_module_state()
    # Do NOT init_state_dir — no state.db on disk.
    fixed = _dt.datetime(2026, 5, 13, 4, 5, 0)
    _FakeDT(fixed).install(monkeypatch)
    ran = backups.run_if_due(state_dir)
    assert ran is False


# --- compression + retention --------------------------------------------

def test_compress_older_backups(state_dir: Path, monkeypatch):
    """Backups older than 3 days get gzipped."""
    _reset_module_state()
    state.init_state_dir(state_dir)
    backup_dir = state_dir / backups.BACKUP_DIR_NAME
    backup_dir.mkdir()

    # 5 days ago: should get compressed.
    old_path = backup_dir / "state-20260508.db"
    old_path.write_bytes(b"old backup content")
    # 1 day ago: should NOT be compressed.
    recent_path = backup_dir / "state-20260512.db"
    recent_path.write_bytes(b"recent backup content")

    fixed = _dt.datetime(2026, 5, 13, 4, 5, 0)
    _FakeDT(fixed).install(monkeypatch)

    backups.run_if_due(state_dir)

    # Old should now be .gz; recent should still be .db.
    assert not old_path.exists()
    assert (backup_dir / "state-20260508.db.gz").exists()
    assert recent_path.exists()

    # Gzip should decompress to the original bytes.
    with gzip.open(backup_dir / "state-20260508.db.gz", "rb") as f:
        assert f.read() == b"old backup content"


def test_retention_deletes_old_backups(state_dir: Path, monkeypatch):
    """Backups older than 14 days are deleted."""
    _reset_module_state()
    state.init_state_dir(state_dir)
    backup_dir = state_dir / backups.BACKUP_DIR_NAME
    backup_dir.mkdir()

    # 20 days ago — past retention.
    very_old = backup_dir / "state-20260423.db.gz"
    very_old.write_bytes(b"compressed old content")
    # 10 days ago — within retention.
    in_window = backup_dir / "state-20260503.db.gz"
    in_window.write_bytes(b"compressed in window")

    fixed = _dt.datetime(2026, 5, 13, 4, 5, 0)
    _FakeDT(fixed).install(monkeypatch)

    backups.run_if_due(state_dir)

    assert not very_old.exists()  # deleted
    assert in_window.exists()  # retained


def test_unrelated_files_in_backup_dir_left_alone(state_dir: Path, monkeypatch):
    """Operator-placed files in backups/ that don't match the
    state-YYYYMMDD.db pattern must NOT be touched by retention."""
    _reset_module_state()
    state.init_state_dir(state_dir)
    backup_dir = state_dir / backups.BACKUP_DIR_NAME
    backup_dir.mkdir()
    other = backup_dir / "README.txt"
    other.write_text("don't delete me")

    fixed = _dt.datetime(2026, 5, 13, 4, 5, 0)
    _FakeDT(fixed).install(monkeypatch)

    backups.run_if_due(state_dir)
    assert other.exists()
    assert other.read_text() == "don't delete me"
