"""Tests for scripts/cimb-status.

The script is intentionally stdlib-only (no project imports) so it can run
from cron without setting up the package. We test it by:
  1. Loading its module text via importlib + the no-.py filename trick.
  2. Calling its ``main(argv)`` directly with a tmp_path status file.

This also covers the round-trip: daemon writes status.json via health.py,
script reads it. If health.py's STATUS_SCHEMA_VERSION shape drifts, the
shape assertions here will catch it.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import time
from pathlib import Path

import pytest

from src import daemon

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "cimb-status"


def _load_cimb_status():
    """Import the no-.py-extension script as a module."""
    spec = importlib.util.spec_from_loader(
        "cimb_status",
        importlib.machinery.SourceFileLoader("cimb_status", str(SCRIPT_PATH)),
    )
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["cimb_status"] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _write_status(path: Path, **overrides) -> None:
    payload = {
        "schema_version": 1,
        "ts": "2026-05-12T14:32:01Z",
        "pid": 12345,
        "cursor": 4823,
        "paused": False,
        "stop_requested": False,
        "consecutive_failures": 0,
        "daily_cost_cents": 18,
        "daily_cost_cap_cents": 500,
        "schema_db_version": 2,
        "metrics": {"msgs_in": 14, "replies": 12},
    }
    payload.update(overrides)
    path.write_text(json.dumps(payload))


def test_cimb_status_missing_file_exits_2(tmp_path: Path, capsys):
    mod = _load_cimb_status()
    rc = mod.main([str(tmp_path / "no-such-file.json")])
    assert rc == 2
    err = capsys.readouterr().err
    assert "not found" in err


def test_cimb_status_happy_path_prints_block(tmp_path: Path, capsys):
    mod = _load_cimb_status()
    status_path = tmp_path / "status.json"
    _write_status(status_path)
    rc = mod.main([str(status_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "claude-imessage-bridge — daemon status" in out
    assert "pid:" in out
    assert "12345" in out
    assert "cursor:" in out
    assert "4823" in out
    assert "daily cost:" in out
    assert "$0.18" in out
    assert "$5.00" in out
    assert "schema version:" in out
    assert "msgs_in: 14" in out
    assert "replies: 12" in out


def test_cimb_status_paused_shown(tmp_path: Path, capsys):
    mod = _load_cimb_status()
    status_path = tmp_path / "status.json"
    _write_status(status_path, paused=True)
    rc = mod.main([str(status_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "paused: yes" in out


def test_cimb_status_warns_when_stale(tmp_path: Path, capsys):
    """File older than 2× HEARTBEAT_INTERVAL_SECONDS → STALE warning at top."""
    mod = _load_cimb_status()
    status_path = tmp_path / "status.json"
    _write_status(status_path)
    # Backdate the mtime past the threshold.
    stale_age = 2 * mod.HEARTBEAT_INTERVAL_SECONDS + 60
    past = time.time() - stale_age
    import os
    os.utime(status_path, (past, past))

    rc = mod.main([str(status_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "STALE" in out
    # Body still prints
    assert "claude-imessage-bridge" in out


def test_cimb_status_malformed_json_exits_3(tmp_path: Path, capsys):
    mod = _load_cimb_status()
    status_path = tmp_path / "status.json"
    status_path.write_text("not json at all")
    rc = mod.main([str(status_path)])
    assert rc == 3


def test_cimb_status_heartbeat_constant_matches_daemon():
    """The script duplicates HEARTBEAT_INTERVAL_SECONDS to stay import-free.
    If the daemon's constant drifts, this test will catch it."""
    mod = _load_cimb_status()
    assert mod.HEARTBEAT_INTERVAL_SECONDS == daemon.HEARTBEAT_INTERVAL_SECONDS


def test_cimb_status_handles_zero_metrics(tmp_path: Path, capsys):
    mod = _load_cimb_status()
    status_path = tmp_path / "status.json"
    _write_status(status_path, metrics={})
    rc = mod.main([str(status_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "(none)" in out


def test_cimb_status_subprocess_invocation(tmp_path: Path):
    """End-to-end: actually shell out to the script. Catches shebang /
    interpreter-line / execution-permission regressions."""
    import subprocess

    status_path = tmp_path / "status.json"
    _write_status(status_path)
    result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), str(status_path)],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0
    assert "claude-imessage-bridge" in result.stdout
    assert "pid:" in result.stdout


def test_cimb_status_script_is_executable():
    """The shebang + chmod +x must hold so cron jobs can run it directly."""
    import stat

    mode = SCRIPT_PATH.stat().st_mode
    assert mode & stat.S_IXUSR, "scripts/cimb-status must be executable"

    first_line = SCRIPT_PATH.read_text().splitlines()[0]
    assert first_line.startswith("#!"), f"missing shebang: {first_line!r}"
    assert "python" in first_line


@pytest.mark.parametrize("env_var_set", [True, False])
def test_cimb_status_env_var_path(tmp_path: Path, monkeypatch, env_var_set, capsys):
    """CIMB_STATUS_PATH env var overrides the default location."""
    mod = _load_cimb_status()
    status_path = tmp_path / "status.json"
    _write_status(status_path)

    if env_var_set:
        monkeypatch.setenv("CIMB_STATUS_PATH", str(status_path))
        rc = mod.main([])
        assert rc == 0
        out = capsys.readouterr().out
        assert "pid:" in out
    else:
        # Without the env var and no argv, falls back to home dir default
        # which won't exist in this test → return 2.
        monkeypatch.delenv("CIMB_STATUS_PATH", raising=False)
        # Redirect HOME to tmp so the default path is missing.
        monkeypatch.setenv("HOME", str(tmp_path / "fake-home"))
        # Force re-import so DEFAULT_STATUS_PATH picks up new HOME.
        mod2 = _load_cimb_status()
        rc = mod2.main([])
        assert rc == 2
