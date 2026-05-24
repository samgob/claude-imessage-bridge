"""Health-status sidecar — writes ``status.json`` next to state.db.

The daemon emits a single JSON file at every heartbeat tick that captures
its current liveness state. The format is intended for a future
``cimb-status`` CLI and for shell snippets (``jq '.paused'``) — schema
stability matters more than completeness.

Atomic-write semantics: write to ``status.json.tmp`` first, then rename.
A reader that hits us mid-write either sees the previous full file or
the new full file, never a partial buffer.

Versioned schema so the consumer can detect breakage:

  {
    "schema_version": 1,
    "ts": "2026-05-12T14:32:01Z",
    "pid": 12345,
    "cursor": 4823,
    "paused": false,
    "stop_requested": false,
    "consecutive_failures": 0,
    "daily_cost_cents": 17,
    "daily_cost_cap_cents": 500,
    "schema_db_version": 1,
    "metrics": {"msgs_in": 4, "replies": 4, ...}
  }
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from . import state

logger = logging.getLogger(__name__)

# Bump on any breaking change to the JSON shape.
STATUS_SCHEMA_VERSION: int = 1

STATUS_FILENAME = "status.json"


def write_status(
    *,
    state_dir: Path,
    cursor: int,
    metrics: Dict[str, int],
    daily_cost_cap_usd: float,
    paused: bool,
    stop_requested: bool,
) -> Path:
    """Write the status sidecar atomically. Returns the resulting path.

    Failures (disk full, perms, etc.) are caught and logged — the daemon
    keeps running even if the sidecar can't be written.
    """
    status_path = state_dir / STATUS_FILENAME
    try:
        payload: Dict[str, Any] = {
            "schema_version": STATUS_SCHEMA_VERSION,
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "pid": os.getpid(),
            "cursor": int(cursor),
            "paused": bool(paused),
            "stop_requested": bool(stop_requested),
            "consecutive_failures": state.get_consecutive_failures(state_dir=state_dir),
            "daily_cost_cents": state.today_cost_cents(state_dir=state_dir),
            "daily_cost_cap_cents": int(round(daily_cost_cap_usd * 100)),
            "schema_db_version": state.SCHEMA_VERSION,
            "metrics": dict(metrics),
        }
        body = json.dumps(payload, sort_keys=True, indent=2) + "\n"

        # Atomic write: tempfile in the same dir (rename works) + os.replace.
        # ``delete=False`` so we can close+chmod+rename without the file
        # vanishing in our hands.
        fd, tmp = tempfile.mkstemp(
            prefix=".status.",
            suffix=".tmp",
            dir=str(state_dir),
        )
        # Track whether the rename completed; if not, the tmp file is
        # garbage and we should remove it. Using ``try/finally`` here
        # (not ``except OSError`` as the prior implementation did) means
        # MemoryError, KeyboardInterrupt, or any other non-OSError
        # exception during the write also triggers cleanup, avoiding
        # leftover ``.status.*.tmp`` orphans across daemon restarts.
        renamed = False
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(body)
            os.chmod(tmp, 0o600)
            os.replace(tmp, str(status_path))
            renamed = True
        finally:
            if not renamed:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
    except OSError as e:
        logger.warning("could not write status.json: %s", e)
    return status_path
