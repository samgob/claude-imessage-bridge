"""Configuration loading + validation.

Config lives at ``~/.claude-imessage-bridge/config.yaml`` (NOT in repo).
A sample is checked in at ``config.example.yaml``.

Phase A→B preconditions enforced here (per solver review #9):

- ``allowed_tools`` MUST be explicitly declared in the YAML. No implicit
  defaults — silent defaults are exactly the failure mode the solver
  flagged ("user thinks they're locked down but inherited a permissive
  default").
- ``allowed_tools`` MUST NOT include any of ``claude_runner.HARD_FORBIDDEN_TOOLS``
  (Bash, Write, Edit, WebFetch, WebSearch, Skill, etc.).
- ``allowed_tools`` MUST NOT include MCP-namespaced tools (``mcp__*``).
- ``daily_cost_cap_usd`` must be positive (no infinite budget).
- ``claude_binary`` must exist on disk.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import List

import yaml

from .claude_runner import DEFAULT_CLAUDE_BIN, HARD_FORBIDDEN_TOOLS
from .imessage_sender import HandleError, validate_handle

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Config:
    project_directory: Path
    allowlist: List[str]                 # normalized handles
    allow_group_chat_guids: List[str]    # opt-in groups only
    allowed_tools: List[str]             # may be empty (= text-only chat)
    forbidden_tools: List[str]
    poll_interval_seconds: float
    reply_rate_limit_per_minute: int
    daily_cost_cap_usd: float
    per_call_cost_cap_usd: float
    per_call_max_turns: int
    per_call_timeout_seconds: int
    circuit_breaker_failures: int        # consecutive failures -> auto-PAUSE
    claude_binary: str
    debug: bool

    @property
    def allowlist_set(self) -> set:
        return set(self.allowlist)


def _validate_claude_binary(path: str) -> None:
    """Refuse a claude binary whose resolved target is suspicious.

    Defends against an attacker who can write to ``/usr/local/bin/``
    swapping ``claude`` for their own binary (or a symlink chain that
    eventually points to an attacker-owned file).

    Policy:
      - Resolve the symlink chain (Homebrew normally installs
        ``/usr/local/bin/claude`` as a symlink to a Cellar path).
      - Resolved target must exist, be a regular file.
      - Owner must be root or the current user.
      - File must not be group- or world-writable.
      - Parent directory of the resolved file must not be
        group- or world-writable.
      - EACH directory in the symlink chain must also not be
        group- or world-writable (so an attacker can't swap a
        link mid-chain).
    """
    if not path:
        raise ValueError("claude_binary is empty")
    p = Path(path)
    if not p.exists():
        raise ValueError(
            f"claude_binary {path!r} does not exist. Install Claude Code "
            "or set claude_binary in config.yaml to the right path."
        )
    try:
        resolved = p.resolve(strict=True)
        st = resolved.stat()
    except (OSError, FileNotFoundError) as e:
        raise ValueError(f"claude_binary {path!r}: {e}")
    if not resolved.is_file():
        raise ValueError(f"claude_binary {path!r}: not a regular file")
    current_uid = os.getuid()
    if st.st_uid not in (0, current_uid):
        raise ValueError(
            f"claude_binary {path!r} (resolved to {resolved}) is owned by "
            f"uid {st.st_uid}; refusing (must be root or this user, "
            f"uid={current_uid})"
        )
    if st.st_mode & 0o022:
        raise ValueError(
            f"claude_binary {resolved} is group- or world-writable "
            f"(mode={oct(st.st_mode & 0o777)}); refusing"
        )
    # Walk every directory we traversed (input path's parent + resolved's
    # parent) and refuse if any is g+w / o+w.
    for d in {p.parent, resolved.parent}:
        try:
            dst = d.stat()
        except OSError as e:
            raise ValueError(
                f"could not stat directory {d} in claude_binary path: {e}"
            )
        if dst.st_mode & 0o022:
            raise ValueError(
                f"directory {d} on claude_binary path is group/world-writable "
                f"(mode={oct(dst.st_mode & 0o777)}); refusing"
            )


def _validate_tools(allowed: List[str], forbidden: List[str]) -> None:
    """Enforce Phase A→B preconditions on the tool lists.

    Empty allowed_tools list is OK — that maps to ``--tools ""`` which
    disables all tools (pure text chat). This is the recommended default
    given that any filesystem-reading tool can be coerced via prompt
    injection into echoing arbitrary file contents back over iMessage
    (see THREAT_MODEL.md adversarial review round 2, finding C3).
    """
    bad = HARD_FORBIDDEN_TOOLS & set(allowed)
    if bad:
        raise ValueError(
            f"allowed_tools includes hard-forbidden tools: {sorted(bad)}. "
            "These are blocked at the runner level regardless of config; "
            "remove them or the daemon will refuse to start."
        )
    mcp = [t for t in allowed if t.startswith("mcp__")]
    if mcp:
        raise ValueError(
            f"allowed_tools includes MCP-namespaced tools: {sorted(mcp)}. "
            "The bridge cannot vet MCP tool capabilities (they can wrap "
            "Bash, send messages, etc.); refuse."
        )
    overlap = set(allowed) & set(forbidden)
    if overlap:
        raise ValueError(
            f"tools appear in both allowed_tools and forbidden_tools: "
            f"{sorted(overlap)}"
        )


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
            raise ValueError(
                f"allowlist entries must be strings, got {type(entry).__name__}"
            )
        try:
            allowlist.append(validate_handle(entry))
        except HandleError as e:
            raise ValueError(f"allowlist entry rejected: {entry!r} ({e})")

    group_guids = raw.get("allow_group_chat_guids") or []
    if not isinstance(group_guids, list):
        raise ValueError("allow_group_chat_guids must be a list")

    # PHASE A→B PRECONDITION: tools key must be present (may be empty list).
    if "allowed_tools" not in raw:
        raise ValueError(
            "config.yaml is missing the 'allowed_tools' key. Set it to "
            "an explicit list (use [] for text-only chat, no tools). See "
            "config.example.yaml."
        )
    allowed = raw["allowed_tools"]
    forbidden = raw.get("forbidden_tools", [])
    if not isinstance(allowed, list) or not isinstance(forbidden, list):
        raise ValueError("allowed_tools and forbidden_tools must be lists")
    _validate_tools(allowed, forbidden)

    poll = float(raw.get("poll_interval_seconds", 3.0))
    if poll < 1.0:
        raise ValueError("poll_interval_seconds must be >= 1.0")

    rate = int(raw.get("reply_rate_limit_per_minute", 10))
    if rate < 1 or rate > 60:
        raise ValueError("reply_rate_limit_per_minute must be in [1, 60]")

    cost = float(raw.get("daily_cost_cap_usd", 5.0))
    if cost <= 0:
        raise ValueError("daily_cost_cap_usd must be > 0")

    per_call_cap = float(raw.get("per_call_cost_cap_usd", 0.50))
    if per_call_cap <= 0:
        raise ValueError("per_call_cost_cap_usd must be > 0")
    if per_call_cap > cost:
        raise ValueError(
            f"per_call_cost_cap_usd ({per_call_cap}) must be <= "
            f"daily_cost_cap_usd ({cost})"
        )

    max_turns = int(raw.get("per_call_max_turns", 1))
    if max_turns < 1 or max_turns > 20:
        raise ValueError("per_call_max_turns must be in [1, 20]")

    timeout = int(raw.get("per_call_timeout_seconds", 90))
    if timeout < 10 or timeout > 600:
        raise ValueError("per_call_timeout_seconds must be in [10, 600]")

    breaker = int(raw.get("circuit_breaker_failures", 5))
    if breaker < 2 or breaker > 100:
        raise ValueError("circuit_breaker_failures must be in [2, 100]")

    claude_bin = str(raw.get("claude_binary", DEFAULT_CLAUDE_BIN))
    _validate_claude_binary(claude_bin)

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
        per_call_cost_cap_usd=per_call_cap,
        per_call_max_turns=max_turns,
        per_call_timeout_seconds=timeout,
        circuit_breaker_failures=breaker,
        claude_binary=claude_bin,
        debug=debug,
    )
