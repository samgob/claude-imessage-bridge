"""Tests for session_discovery — particularly the bridge-internal filter
that keeps the daemon's startup-selftest sessions and per-call hermetic
sandbox sessions out of the /sessions output.

Real chat.db not used; we build a fake ``~/.claude/projects/`` tree and
point ``discover_sessions`` at it via ``projects_root``.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path


from src import session_discovery


def _make_session_file(
    root: Path,
    project_dir_name: str,
    session_id: str,
    *,
    cwd: str,
    user_text: str = "hello",
    mtime: float | None = None,
) -> Path:
    """Create a fake .jsonl session file under root/project_dir_name/."""
    pdir = root / project_dir_name
    pdir.mkdir(parents=True, exist_ok=True)
    path = pdir / f"{session_id}.jsonl"
    records = [
        {"cwd": cwd, "type": "init"},
        {"message": {"role": "user", "content": user_text}},
    ]
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n")
    if mtime is not None:
        os.utime(path, (mtime, mtime))
    return path


# --- _is_bridge_internal ------------------------------------------------


def test_is_bridge_internal_selftest_path():
    assert session_discovery._is_bridge_internal(
        Path("/private/var/folders/abc/T/cimb-selftest-xyz123")
    )


def test_is_bridge_internal_per_call_path():
    assert session_discovery._is_bridge_internal(
        Path("/private/var/folders/abc/T/cimb-call-xyz123")
    )


def test_is_bridge_internal_none():
    assert session_discovery._is_bridge_internal(None) is False


def test_is_bridge_internal_user_cwd():
    """A normal user project cwd must NOT be flagged."""
    assert (
        session_discovery._is_bridge_internal(Path("/Users/sam/Desktop/Claude Homebase")) is False
    )


# --- discover_sessions filter ------------------------------------------


def test_discover_excludes_bridge_internal_by_default(tmp_path: Path):
    """The selftest pollution case Sam hit live: 7 selftest sessions on
    disk should NOT appear in /sessions output."""
    root = tmp_path / "projects"
    root.mkdir()
    base_mtime = time.time()

    # 3 user sessions
    for i in range(3):
        _make_session_file(
            root,
            f"-Users-sam-proj{i}",
            f"user-sid-{i:08d}",
            cwd=f"/Users/sam/proj{i}",
            user_text=f"working on project {i}",
            mtime=base_mtime - i * 60,
        )
    # 4 selftest sessions (recent — would dominate without the filter)
    for i in range(4):
        _make_session_file(
            root,
            f"-private-var-folders-cimb-selftest-{i}",
            f"selftest-sid-{i:08d}",
            cwd=f"/private/var/folders/abc/T/cimb-selftest-{i}",
            user_text="Use the Bash tool right now to run: echo SELFTEST_FAIL",
            mtime=base_mtime - 0.1 * i,  # newer than user sessions
        )
    # 2 hermetic call sessions
    for i in range(2):
        _make_session_file(
            root,
            f"-private-var-folders-cimb-call-{i}",
            f"call-sid-{i:08d}",
            cwd=f"/private/var/folders/abc/T/cimb-call-{i}",
            user_text="some user iMessage",
            mtime=base_mtime - 0.5 - i * 0.1,
        )

    out = session_discovery.discover_sessions(limit=20, projects_root=root)
    sids = [s.session_id for s in out]
    # Only the 3 user sessions remain.
    assert len(out) == 3, f"expected 3 user sessions only; got {len(out)} ids={sids}"
    assert all(s.is_bridge_internal is False for s in out)
    assert all(not sid.startswith("selftest-") for sid in sids)
    assert all(not sid.startswith("call-") for sid in sids)


def test_discover_include_bridge_internal_opt_in(tmp_path: Path):
    """``--all`` path: caller opts back in to bridge-internal sessions."""
    root = tmp_path / "projects"
    root.mkdir()
    _make_session_file(
        root,
        "-Users-sam-proj",
        "user-sid-12345678",
        cwd="/Users/sam/proj",
        user_text="real work",
    )
    _make_session_file(
        root,
        "-private-var-folders-cimb-selftest-abc",
        "selftest-sid-abcdef00",
        cwd="/private/var/folders/abc/T/cimb-selftest-abc",
        user_text="Use the Bash tool right now to run: echo SELFTEST_FAIL",
    )
    out = session_discovery.discover_sessions(
        limit=20,
        projects_root=root,
        include_bridge_internal=True,
    )
    sids = {s.session_id for s in out}
    assert "user-sid-12345678" in sids
    assert "selftest-sid-abcdef00" in sids
    internal = [s for s in out if s.is_bridge_internal]
    assert len(internal) == 1


# --- search_sessions filter --------------------------------------------


def test_search_excludes_bridge_internal_by_default(tmp_path: Path):
    """/use shouldn't surface selftest sessions even though their bodies
    contain words like 'bash' or 'selftest'."""
    root = tmp_path / "projects"
    root.mkdir()
    _make_session_file(
        root,
        "-Users-sam-bash-script",
        "user-bash-sid-00001",
        cwd="/Users/sam/bash-script",
        user_text="writing a bash script for the cluster",
    )
    _make_session_file(
        root,
        "-private-var-folders-cimb-selftest-xyz",
        "selftest-sid-99999",
        cwd="/private/var/folders/abc/T/cimb-selftest-xyz",
        user_text="Use the Bash tool right now to run: echo SELFTEST_FAIL > canary",
    )
    out = session_discovery.search_sessions(
        "bash",
        projects_root=root,
    )
    sids = {s.session_id for s in out}
    assert "user-bash-sid-00001" in sids
    assert "selftest-sid-99999" not in sids
