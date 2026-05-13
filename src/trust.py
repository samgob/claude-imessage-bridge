"""Trust presets — three named modes for invoking ``claude -p``.

The bridge serves three audiences with different threat models:

- **chat_only** — strangers in the allowlist, or shared-with-family setups.
  Hermetic invocation: tempdir cwd, empty MCP config, ``--max-turns 1``,
  full ``HARD_DISALLOWED`` deny list. No memory backend. This is the
  current default and the safe OSS default.

- **coding** — filesystem-aware Claude without network. Real
  ``project_directory`` cwd (CLAUDE.md loads), empty MCP config,
  WebFetch/WebSearch/mcp__* denied, ``--max-turns 10``, claude_md memory
  backend. For "ask me about my codebase from the train" use cases where
  network egress is unnecessary.

- **full** — Claude Code reached via iMessage. Real cwd, real MCP config,
  denies only ``AskUserQuestion`` (technically non-functional in
  non-interactive mode), ``--max-turns 20``, claude_md memory backend.
  For solo operators with a tight allowlist who want the same Claude
  Code they have at their laptop.

Trust mode is a CONFIG-LEVEL setting. It can NEVER be switched by inbound
message content — that would create a security boundary that depends on
classification of attacker-controlled input. The threat model addition for
the trust-mode framework requires this to be one-way: chat_only is the
floor; escalating to coding/full requires editing config.yaml and
restarting the daemon.

Per-alias overrides exist (``trust.per_alias: {family: chat_only}``) but
still resolve at config-load time, not message-time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import FrozenSet, Optional

# Imported here so the presets can reference HARD_DISALLOWED directly.
# Keep this module low-dependency — only claude_runner constants.
from . import claude_runner


# --- Preset definition ----------------------------------------------------

@dataclass(frozen=True)
class TrustPreset:
    """How to invoke ``claude -p`` for one inbound message.

    Every preset must be one of the three named values; new presets are
    not added at runtime (the security model requires static, named,
    configurable-only-via-yaml presets).
    """

    name: str                          # 'chat_only' | 'coding' | 'full'

    # Where the claude child process runs.
    #   'hermetic_tempdir' — fresh tempfile.TemporaryDirectory per call.
    #     CLAUDE.md, settings.json, .mcp.json in user dirs do NOT load.
    #   'project_directory' — the cfg.project_directory path.
    #     CLAUDE.md and the user's local .claude/ context DO load.
    cwd_mode: str

    # How the MCP config is provided.
    #   'empty' — write a fresh ``{"mcpServers":{}}`` file with
    #     O_NOFOLLOW|O_EXCL into the sandbox tempdir. No MCP servers
    #     spawn. ``--strict-mcp-config`` enforces this.
    #   'inherit' — pass the user's existing MCP config path via
    #     ``--mcp-config``. Real MCP servers spawn with their normal
    #     permissions (Gmail OAuth, Slack tokens, etc.).
    mcp_config_mode: str

    # Path to the user's MCP config for ``inherit`` mode. Defaults to
    # ``~/.claude/.mcp.json`` if None. Ignored when ``mcp_config_mode``
    # is ``'empty'``.
    mcp_config_path: Optional[str]

    # Tools forced into ``--disallowed-tools``. Anything the user adds
    # via ``allowed_tools_addons`` is removed from this set per-call.
    disallowed_tools: FrozenSet[str]

    # ``--max-turns N`` cap on per-call agent loop length.
    max_turns: int

    # Which memory backend feeds context into the prompt.
    #   'none'        — no memory injection.
    #   'claude_md'   — load CLAUDE.md + lazy reference matches.
    #   'custom'      — operator-provided script.
    # 'obsidian' is reserved but not implemented in the initial cut.
    memory_backend: str

    # Optional extra system-prompt text. ``None`` means no
    # ``--append-system-prompt`` flag at all (let Claude Code defaults
    # apply). The chat_only preset uses the legacy BRIDGE_SYSTEM_PROMPT
    # text; coding/full pass None and rely on the model knowing it
    # already.
    extra_system_prompt: Optional[str]

    # Extra environment variables to pass through to the child process
    # ON TOP OF the base allowlist (PATH/HOME/USER/LANG/LC_ALL +
    # ANTHROPIC_API_KEY/CLAUDE_CODE_OAUTH_TOKEN). Trust modes that need
    # MCP server credentials add things like ``GH_TOKEN``, ``GITHUB_TOKEN``,
    # ``MCP_*`` prefix matches.
    extra_env_passthrough: FrozenSet[str] = field(default_factory=frozenset)


# --- The three named presets ----------------------------------------------

# Sets used by coding mode. coding mode keeps filesystem read/write available
# (the user explicitly chose it for code work) but denies network egress and
# MCP-namespaced tools (the empty MCP config also kills MCPs, but
# defense-in-depth).
_CODING_FILESYSTEM_TOOLS: FrozenSet[str] = frozenset({
    "Bash", "Read", "Write", "Edit", "MultiEdit", "NotebookEdit",
    "Grep", "Glob", "LS", "NotebookRead",
})


PRESET_CHAT_ONLY: TrustPreset = TrustPreset(
    name="chat_only",
    cwd_mode="hermetic_tempdir",
    mcp_config_mode="empty",
    mcp_config_path=None,
    disallowed_tools=claude_runner.HARD_DISALLOWED,
    max_turns=1,
    memory_backend="none",
    extra_system_prompt=claude_runner.BRIDGE_SYSTEM_PROMPT,
    extra_env_passthrough=frozenset(),
)


PRESET_CODING: TrustPreset = TrustPreset(
    name="coding",
    cwd_mode="project_directory",
    mcp_config_mode="empty",
    mcp_config_path=None,
    # Start with the full HARD_DISALLOWED, but remove the filesystem tools
    # the user explicitly opted into by choosing coding mode. The result
    # still denies network egress, scheduling, agents, and MCP introspection.
    disallowed_tools=claude_runner.HARD_DISALLOWED - _CODING_FILESYSTEM_TOOLS,
    max_turns=10,
    memory_backend="claude_md",
    extra_system_prompt=None,
    extra_env_passthrough=frozenset({"GH_TOKEN", "GITHUB_TOKEN"}),
)


PRESET_FULL: TrustPreset = TrustPreset(
    name="full",
    cwd_mode="project_directory",
    mcp_config_mode="inherit",
    mcp_config_path=None,  # resolved at invocation time
    # Full Claude Code in iMessage. Deny only tools that are nonsensical in
    # non-interactive mode. ``AskUserQuestion`` would hang the daemon
    # waiting for an answer that can't arrive over iMessage's one-shot
    # turn boundary.
    disallowed_tools=frozenset({"AskUserQuestion"}),
    max_turns=20,
    memory_backend="claude_md",
    extra_system_prompt=None,
    # MCP-prefixed env vars (Anthropic-provided OAuth tokens etc.) are
    # passed through pattern-matched at scrub time; here we list the
    # commonly-named singletons.
    extra_env_passthrough=frozenset({
        "GH_TOKEN", "GITHUB_TOKEN",
        # Claude Code's official MCP servers use these:
        "GOOGLE_OAUTH_CLIENT_ID", "GOOGLE_OAUTH_CLIENT_SECRET",
        "SLACK_USER_TOKEN", "SLACK_BOT_TOKEN",
    }),
)


# --- Resolution -----------------------------------------------------------

_PRESETS_BY_NAME = {
    "chat_only": PRESET_CHAT_ONLY,
    "coding": PRESET_CODING,
    "full": PRESET_FULL,
}


class UnknownTrustPreset(ValueError):
    """Config referenced a trust preset by name that isn't registered."""


def get_preset(name: str) -> TrustPreset:
    """Look up a preset by canonical name. Raises ``UnknownTrustPreset``."""
    if name not in _PRESETS_BY_NAME:
        raise UnknownTrustPreset(
            f"trust preset {name!r} is not one of "
            f"{sorted(_PRESETS_BY_NAME)}"
        )
    return _PRESETS_BY_NAME[name]


def resolve_trust(
    *,
    trust_default: str,
    trust_per_alias: dict,
    active_alias: Optional[str],
) -> TrustPreset:
    """Return the active TrustPreset for a given alias context.

    The per-alias override wins if the alias is set AND has an explicit
    mapping. Otherwise the default applies. Both are validated through
    ``get_preset``; an unknown name raises ``UnknownTrustPreset`` (caller
    is expected to have validated at config-load time, so this is a
    defense-in-depth check).
    """
    if active_alias and active_alias in trust_per_alias:
        return get_preset(trust_per_alias[active_alias])
    return get_preset(trust_default)


# --- Argv-flag denylist (cross-cutting; not preset-specific) -------------
#
# Even in ``full`` trust mode, a few argv tokens disable Claude Code's own
# permission system entirely. Allowing those in argv would let an operator
# (or a future regression) bypass not just the bridge's gates but Claude
# Code's own. These are NEVER allowed in any preset.
#
# Imported here so ``_assert_safe_argv`` has a single source of truth.

FORBIDDEN_ARGV_FLAGS: FrozenSet[str] = claude_runner.ARGV_DENYLIST
