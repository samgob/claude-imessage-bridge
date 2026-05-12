"""Shared pytest fixtures for claude-imessage-bridge tests.

The bridge writes state to ``~/.claude-imessage-bridge/`` by default. Tests
must NEVER touch that directory — they get a fresh tmp_path-backed state_dir.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest


# Make ``src`` importable as a package without installing the project.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


@pytest.fixture
def state_dir(tmp_path: Path) -> Path:
    """A per-test state directory. Real init runs against this path."""
    d = tmp_path / "state"
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    return d


@pytest.fixture
def fake_claude_binary(tmp_path: Path) -> Path:
    """A regular-file mock of /usr/local/bin/claude with safe perms.

    Tests that need ``_validate_claude_binary`` to pass can point at this.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True)
    os.chmod(bin_dir, 0o755)
    binary = bin_dir / "claude"
    binary.write_text("#!/bin/sh\necho '{}'\n")
    os.chmod(binary, 0o755)
    return binary
