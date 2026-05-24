"""Tests for the status.json health sidecar.

Stability guarantees:
  - Atomic write (reader never sees a partial file).
  - Schema version stamped so a future cimb-status CLI can detect breaks.
  - File mode 0o600 (status carries cursor + cost + paused — not secret
    but not for other local users either).
"""

from __future__ import annotations

import json
from pathlib import Path


from src import health, state


def test_write_status_creates_file(state_dir: Path):
    state.init_state_dir(state_dir)
    out = health.write_status(
        state_dir=state_dir,
        cursor=42,
        metrics={"msgs_in": 3},
        daily_cost_cap_usd=5.0,
        paused=False,
        stop_requested=False,
    )
    assert out.exists()
    assert out.name == health.STATUS_FILENAME


def test_write_status_schema_shape(state_dir: Path):
    state.init_state_dir(state_dir)
    out = health.write_status(
        state_dir=state_dir,
        cursor=100,
        metrics={"replies": 5, "drops_sender-not-allowlisted": 2},
        daily_cost_cap_usd=5.00,
        paused=False,
        stop_requested=False,
    )
    data = json.loads(out.read_text())
    assert data["schema_version"] == health.STATUS_SCHEMA_VERSION
    assert data["cursor"] == 100
    assert data["paused"] is False
    assert data["stop_requested"] is False
    assert data["daily_cost_cap_cents"] == 500
    assert data["daily_cost_cents"] == 0
    assert data["consecutive_failures"] == 0
    assert data["schema_db_version"] == state.SCHEMA_VERSION
    assert data["metrics"] == {"replies": 5, "drops_sender-not-allowlisted": 2}
    assert "ts" in data
    assert "pid" in data


def test_write_status_reflects_consecutive_failures(state_dir: Path):
    state.init_state_dir(state_dir)
    state.record_claude_failure(state_dir=state_dir)
    state.record_claude_failure(state_dir=state_dir)
    out = health.write_status(
        state_dir=state_dir,
        cursor=0,
        metrics={},
        daily_cost_cap_usd=5.0,
        paused=False,
        stop_requested=False,
    )
    data = json.loads(out.read_text())
    assert data["consecutive_failures"] == 2


def test_write_status_reflects_paused_flag(state_dir: Path):
    state.init_state_dir(state_dir)
    out = health.write_status(
        state_dir=state_dir,
        cursor=0,
        metrics={},
        daily_cost_cap_usd=5.0,
        paused=True,
        stop_requested=False,
    )
    data = json.loads(out.read_text())
    assert data["paused"] is True


def test_write_status_tight_perms(state_dir: Path):
    state.init_state_dir(state_dir)
    out = health.write_status(
        state_dir=state_dir,
        cursor=0,
        metrics={},
        daily_cost_cap_usd=5.0,
        paused=False,
        stop_requested=False,
    )
    mode = out.stat().st_mode & 0o777
    assert mode == 0o600


def test_write_status_atomic_overwrite(state_dir: Path):
    """Repeated writes must overwrite atomically — no leftover tmp files."""
    state.init_state_dir(state_dir)
    for cursor in range(1, 6):
        health.write_status(
            state_dir=state_dir,
            cursor=cursor,
            metrics={"i": cursor},
            daily_cost_cap_usd=5.0,
            paused=False,
            stop_requested=False,
        )
    # Only one status.json should exist; no .status.*.tmp lying around.
    files = {p.name for p in state_dir.iterdir()}
    assert "status.json" in files
    tmps = [n for n in files if n.startswith(".status.") and n.endswith(".tmp")]
    assert tmps == []
    data = json.loads((state_dir / "status.json").read_text())
    assert data["cursor"] == 5


def test_status_v1_locked_key_set(state_dir: Path):
    """Lock the v1 schema key set. Any future change to the JSON shape
    that doesn't bump STATUS_SCHEMA_VERSION will fail this test."""
    state.init_state_dir(state_dir)
    out = health.write_status(
        state_dir=state_dir,
        cursor=0,
        metrics={},
        daily_cost_cap_usd=5.0,
        paused=False,
        stop_requested=False,
    )
    data = json.loads(out.read_text())
    expected_v1_keys = {
        "schema_version",
        "ts",
        "pid",
        "cursor",
        "paused",
        "stop_requested",
        "consecutive_failures",
        "daily_cost_cents",
        "daily_cost_cap_cents",
        "schema_db_version",
        "metrics",
    }
    assert set(data.keys()) == expected_v1_keys, (
        "status.json schema changed — bump STATUS_SCHEMA_VERSION and update "
        "this test together. New keys: "
        f"{sorted(set(data.keys()) - expected_v1_keys)}; removed: "
        f"{sorted(expected_v1_keys - set(data.keys()))}."
    )


def test_write_status_uses_cost_cap_cents(state_dir: Path):
    """Cost cap is stored as integer cents to match daily_cost accounting."""
    state.init_state_dir(state_dir)
    state.add_cost_cents(123, state_dir=state_dir)
    out = health.write_status(
        state_dir=state_dir,
        cursor=0,
        metrics={},
        daily_cost_cap_usd=7.50,
        paused=False,
        stop_requested=False,
    )
    data = json.loads(out.read_text())
    assert data["daily_cost_cap_cents"] == 750
    assert data["daily_cost_cents"] == 123
