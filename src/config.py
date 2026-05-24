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
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from .claude_runner import DEFAULT_CLAUDE_BIN, HARD_FORBIDDEN_TOOLS
from .imessage_sender import HandleError, validate_handle

logger = logging.getLogger(__name__)


# Session-alias key/value validation regexes.
_ALIAS_KEY_RE = re.compile(r"^[a-z0-9_-]{1,32}$")
_ALIAS_UUID_RE = re.compile(r"^[a-f0-9-]{8,40}$")


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
    # name → session UUID. Always resolved to a flat dict-of-str regardless
    # of whether the YAML input was a string or a {id: <uuid>} mapping.
    session_aliases: Dict[str, str] = field(default_factory=dict)
    # Trust mode infrastructure. ``trust_default`` is the preset name to
    # apply when no alias is active or the active alias has no override.
    # ``trust_per_alias`` maps alias names to preset names. Both default
    # to "chat_only" — the safe OSS posture. Operators who want full
    # Claude Code in iMessage flip ``trust_default: full`` in their own
    # config.yaml.
    trust_default: str = "chat_only"
    trust_per_alias: Dict[str, str] = field(default_factory=dict)
    # Memory backend infrastructure (orthogonal to trust mode but
    # typically scales with it). ``memory_backend`` is one of
    # 'none' | 'claude_md' | 'custom'. Concrete backend params live in
    # the per-backend nested dicts; the dataclass keeps them as plain
    # dicts to avoid the per-backend explosion at this layer.
    memory_backend: str = "none"
    memory_claude_md: Dict[str, object] = field(default_factory=dict)
    memory_custom: Dict[str, object] = field(default_factory=dict)
    # File paths claude must NOT silently edit, even when accept_edits is
    # enabled (trust=full/coding). Edits to any of these paths trigger
    # the existing permission-relay flow so the user explicitly approves.
    # Default: just CLAUDE.md, which is too foundational to mutate
    # without a human in the loop. Operators can add more (e.g.
    # ~/.claude/settings.json) per their threat model.
    protected_files: List[str] = field(
        default_factory=lambda: ["~/.claude/CLAUDE.md"]
    )
    # Optional path overrides for offline audio transcription via
    # whisper.cpp. When unset, the bridge:
    #   - looks for `whisper-cli` or `main` on PATH;
    #   - looks for the model at ~/whisper.cpp/models/ggml-base.en.bin.
    # Missing either → audio messages get a setup-hint reply instead of
    # confused silence. Neither path is required for image-only use.
    whisper_binary: Optional[str] = None
    whisper_model_path: Optional[str] = None

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


def _parse_session_aliases(raw: dict) -> Dict[str, str]:
    """Parse the optional ``session_aliases`` block.

    Accepted value shapes per entry:
      - Plain string: ``wesco: 4fe39c70-21d7-...``
      - Mapping with ``id`` key: ``wesco: {id: 4fe39c70-..., profile: foo}``
        (the mapping form is forward-compatible with later additions
        like ``profile``; we currently only read ``id``).

    Returns a flat ``{name: uuid}`` dict. Names are case-folded to lower
    so ``/use Wesco`` and ``/use wesco`` resolve identically.

    Raises ``ValueError`` on:
      - non-dict top-level value
      - bad key (must match ^[a-z0-9_-]{1,32}$, post-casefold)
      - mapping value missing the ``id`` field
      - id that doesn't look like a session UUID (^[a-f0-9-]{8,40}$)
    """
    raw_aliases = raw.get("session_aliases") or {}
    if not isinstance(raw_aliases, dict):
        raise ValueError("session_aliases must be a mapping (name → uuid)")

    parsed: Dict[str, str] = {}
    for name, value in raw_aliases.items():
        if not isinstance(name, str):
            raise ValueError(
                f"session_aliases keys must be strings, got {type(name).__name__}"
            )
        key = name.lower()
        if not _ALIAS_KEY_RE.match(key):
            raise ValueError(
                f"session_aliases key {name!r} invalid; must match "
                "^[a-z0-9_-]{1,32}$ (case-insensitive)"
            )

        if isinstance(value, str):
            uuid_str = value
        elif isinstance(value, dict):
            if "id" not in value:
                raise ValueError(
                    f"session_aliases[{name!r}] is a mapping but has no 'id' field"
                )
            uuid_raw = value["id"]
            if not isinstance(uuid_raw, str):
                raise ValueError(
                    f"session_aliases[{name!r}].id must be a string, got "
                    f"{type(uuid_raw).__name__}"
                )
            uuid_str = uuid_raw
        else:
            raise ValueError(
                f"session_aliases[{name!r}] must be a string UUID or a "
                f"mapping with an 'id' field; got {type(value).__name__}"
            )

        if not _ALIAS_UUID_RE.match(uuid_str):
            raise ValueError(
                f"session_aliases[{name!r}] value {uuid_str!r} doesn't look "
                "like a session UUID (expected ^[a-f0-9-]{8,40}$)"
            )
        if key in parsed:
            raise ValueError(
                f"session_aliases has duplicate key {key!r} (after "
                "case-folding) — names must be unique"
            )
        parsed[key] = uuid_str

    return parsed


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

    # Default $1.00. Was $0.50 — too tight for image-augmented prompts:
    # a Read on a phone-resolution image is ~1500 vision tokens, and the
    # memory backend's system-prompt context (CLAUDE.md + references)
    # can be 20-40K tokens, so a single image-with-context call routinely
    # lands $0.30-0.70. $1.00 gives headroom without weakening the daily
    # cap (still bounded by daily_cost_cap_usd, default $5).
    per_call_cap = float(raw.get("per_call_cost_cap_usd", 1.00))
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

    session_aliases = _parse_session_aliases(raw)
    trust_default, trust_per_alias = _parse_trust(raw, session_aliases)
    memory_backend, memory_claude_md, memory_custom = _parse_memory(raw)

    # protected_files: edits to these specific paths still require user
    # confirmation via the permission-relay flow, even when accept_edits
    # is on. Default is just CLAUDE.md (see dataclass default).
    raw_protected = raw.get("protected_files")
    if raw_protected is None:
        protected_files = ["~/.claude/CLAUDE.md"]
    elif not isinstance(raw_protected, list) or not all(
        isinstance(p, str) for p in raw_protected
    ):
        raise ValueError("protected_files must be a list of strings")
    else:
        protected_files = list(raw_protected)

    # Optional whisper.cpp paths. Both default to None — the
    # audio_transcribe module falls back to PATH lookup + ~/whisper.cpp
    # model location when these are unset.
    whisper_binary = raw.get("whisper_binary")
    if whisper_binary is not None and not isinstance(whisper_binary, str):
        raise ValueError("whisper_binary must be a string (or omitted)")
    whisper_model_path = raw.get("whisper_model_path")
    if whisper_model_path is not None and not isinstance(whisper_model_path, str):
        raise ValueError("whisper_model_path must be a string (or omitted)")

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
        session_aliases=session_aliases,
        trust_default=trust_default,
        trust_per_alias=trust_per_alias,
        memory_backend=memory_backend,
        memory_claude_md=memory_claude_md,
        memory_custom=memory_custom,
        protected_files=protected_files,
        whisper_binary=whisper_binary,
        whisper_model_path=whisper_model_path,
    )


# --- Trust mode parsing --------------------------------------------------

_VALID_TRUST_PRESETS = frozenset({"chat_only", "coding", "full"})


def _parse_trust(
    raw: dict, session_aliases: Dict[str, str]
) -> tuple[str, Dict[str, str]]:
    """Parse the top-level ``trust:`` block.

    Returns ``(default, per_alias)``. Both default to safe values
    (``"chat_only"`` and ``{}``) so config files that don't mention trust
    keep the hermetic-by-default posture they had before this feature
    landed.

    Validates: ``default`` and every ``per_alias`` value must name a
    registered preset. Every ``per_alias`` key must already exist in
    ``session_aliases`` (otherwise the override is dead config).
    """
    block = raw.get("trust") or {}
    if not isinstance(block, dict):
        raise ValueError("trust must be a YAML mapping (or omitted entirely)")

    default = str(block.get("default", "chat_only"))
    if default not in _VALID_TRUST_PRESETS:
        raise ValueError(
            f"trust.default must be one of {sorted(_VALID_TRUST_PRESETS)}, "
            f"got {default!r}"
        )

    raw_per_alias = block.get("per_alias") or {}
    if not isinstance(raw_per_alias, dict):
        raise ValueError("trust.per_alias must be a YAML mapping")
    per_alias: Dict[str, str] = {}
    for alias_key, preset_name in raw_per_alias.items():
        if not isinstance(alias_key, str) or not isinstance(preset_name, str):
            raise ValueError(
                "trust.per_alias entries must be string→string mappings"
            )
        if alias_key not in session_aliases:
            raise ValueError(
                f"trust.per_alias key {alias_key!r} is not a defined "
                f"session alias (known: {sorted(session_aliases)})"
            )
        if preset_name not in _VALID_TRUST_PRESETS:
            raise ValueError(
                f"trust.per_alias[{alias_key!r}] preset {preset_name!r} is "
                f"not one of {sorted(_VALID_TRUST_PRESETS)}"
            )
        per_alias[alias_key] = preset_name

    return default, per_alias


# --- Memory backend parsing ----------------------------------------------

_VALID_MEMORY_BACKENDS = frozenset({"none", "claude_md", "custom"})


def _parse_memory(raw: dict) -> tuple[str, Dict[str, object], Dict[str, object]]:
    """Parse the top-level ``memory:`` block.

    Returns ``(backend_name, claude_md_params, custom_params)``. Backend
    defaults to ``'none'`` (current hermetic behavior; backward-compat).
    """
    block = raw.get("memory") or {}
    if not isinstance(block, dict):
        raise ValueError("memory must be a YAML mapping (or omitted entirely)")

    backend = str(block.get("backend", "none"))
    if backend not in _VALID_MEMORY_BACKENDS:
        raise ValueError(
            f"memory.backend must be one of {sorted(_VALID_MEMORY_BACKENDS)}, "
            f"got {backend!r}"
        )

    claude_md_block = block.get("claude_md") or {}
    if not isinstance(claude_md_block, dict):
        raise ValueError("memory.claude_md must be a YAML mapping")
    # Normalize the params; the backend module validates them deeper.
    claude_md_params: Dict[str, object] = {
        "root": str(claude_md_block.get("root", "~/.claude/CLAUDE.md")),
        "follow_references": bool(claude_md_block.get("follow_references", True)),
        "max_bytes": int(claude_md_block.get("max_bytes", 32768)),
        "exclude": list(claude_md_block.get("exclude", [])),
    }
    max_bytes_val = claude_md_params["max_bytes"]
    if not isinstance(max_bytes_val, int):  # defensive; set above
        raise ValueError("memory.claude_md.max_bytes must be an integer")
    if max_bytes_val < 1024 or max_bytes_val > 256 * 1024:
        raise ValueError(
            "memory.claude_md.max_bytes must be in [1024, 262144]"
        )

    custom_block = block.get("custom") or {}
    if not isinstance(custom_block, dict):
        raise ValueError("memory.custom must be a YAML mapping")
    custom_params: Dict[str, object] = {
        "script": str(custom_block.get("script", "")),
        "timeout_seconds": int(custom_block.get("timeout_seconds", 5)),
    }
    if backend == "custom":
        script = custom_params["script"]
        if not isinstance(script, str) or not script:
            raise ValueError("memory.custom.script is required when backend=custom")
        # Existence + executability is checked at startup, not config-load,
        # so the operator can edit the script after first config-load.

    return backend, claude_md_params, custom_params
