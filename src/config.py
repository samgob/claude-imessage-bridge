"""Configuration loading + validation.

Config lives at ``~/.claude-imessage-bridge/config.yaml`` (NOT in repo).
A sample is checked in at ``config.example.yaml``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

import yaml

from .imessage_sender import validate_handle, HandleError

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Config:
    project_directory: Path
    allowlist: List[str]                 # normalized handles
    allow_group_chat_guids: List[str]    # opt-in groups only
    allowed_tools: List[str]
    forbidden_tools: List[str]
    poll_interval_seconds: float
    reply_rate_limit_per_minute: int
    daily_cost_cap_usd: float
    debug: bool

    @property
    def allowlist_set(self) -> set:
        return set(self.allowlist)


_DEFAULT_ALLOWED_TOOLS: List[str] = ["Read", "Grep", "Glob", "LS"]
_DEFAULT_FORBIDDEN_TOOLS: List[str] = [
    "Bash", "Write", "Edit", "MultiEdit", "NotebookEdit",
    # Intentionally excluded from default allowed:
    "WebFetch", "WebSearch", "Skill",
]


def load(path: Path) -> Config:
    """Load + validate config. Raises on any structural error."""
    if not path.exists():
        raise FileNotFoundError(
            f"Config not found at {path}. "
            f"Copy config.example.yaml and fill in your handles."
        )
    raw = yaml.safe_load(path.read_text())
    if not isinstance(raw, dict):
        raise ValueError("config.yaml must be a YAML mapping at the top level")

    project_dir = Path(raw["project_directory"]).expanduser()
    if not project_dir.is_absolute():
        raise ValueError("project_directory must be an absolute path")
    if not project_dir.exists():
        raise ValueError(f"project_directory {project_dir} does not exist")

    raw_allowlist = raw.get("allowlist") or []
    if not isinstance(raw_allowlist, list) or not raw_allowlist:
        raise ValueError("allowlist must be a non-empty list")
    allowlist: List[str] = []
    for entry in raw_allowlist:
        if not isinstance(entry, str):
            raise ValueError(f"allowlist entries must be strings, got {type(entry).__name__}")
        try:
            allowlist.append(validate_handle(entry))
        except HandleError as e:
            raise ValueError(f"allowlist entry rejected: {entry!r} ({e})")

    group_guids = raw.get("allow_group_chat_guids") or []
    if not isinstance(group_guids, list):
        raise ValueError("allow_group_chat_guids must be a list")

    allowed = raw.get("allowed_tools", _DEFAULT_ALLOWED_TOOLS)
    forbidden = raw.get("forbidden_tools", _DEFAULT_FORBIDDEN_TOOLS)
    # Belt-and-suspenders: ensure no overlap between allowed and forbidden.
    overlap = set(allowed) & set(forbidden)
    if overlap:
        raise ValueError(
            f"tools appear in both allowed and forbidden lists: {sorted(overlap)}"
        )

    poll = float(raw.get("poll_interval_seconds", 3.0))
    if poll < 1.0:
        raise ValueError("poll_interval_seconds must be >= 1.0")

    rate = int(raw.get("reply_rate_limit_per_minute", 10))
    if rate < 1 or rate > 60:
        raise ValueError("reply_rate_limit_per_minute must be in [1, 60]")

    cost = float(raw.get("daily_cost_cap_usd", 5.0))
    if cost <= 0:
        raise ValueError("daily_cost_cap_usd must be > 0")

    debug = bool(raw.get("debug", False))

    return Config(
        project_directory=project_dir,
        allowlist=allowlist,
        allow_group_chat_guids=list(group_guids),
        allowed_tools=list(allowed),
        forbidden_tools=list(forbidden),
        poll_interval_seconds=poll,
        reply_rate_limit_per_minute=rate,
        daily_cost_cap_usd=cost,
        debug=debug,
    )
