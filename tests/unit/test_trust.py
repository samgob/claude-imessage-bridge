"""Tests for the trust-preset infrastructure (`src/trust.py`).

The three named presets (chat_only, coding, full) gate every invocation
of ``claude -p``. Resolution by name + per-alias override is the only
public API; presets themselves are immutable module constants.
"""

from __future__ import annotations

import pytest

from src import trust, claude_runner


# --- Named presets exist with the expected shape ------------------------


def test_chat_only_preset_shape():
    p = trust.PRESET_CHAT_ONLY
    assert p.name == "chat_only"
    assert p.cwd_mode == "hermetic_tempdir"
    assert p.mcp_config_mode == "empty"
    # HARD_DISALLOWED is the load-bearing deny list in this mode.
    assert p.disallowed_tools == claude_runner.HARD_DISALLOWED
    assert p.max_turns == 1
    assert p.memory_backend == "none"
    # Anti-fabrication system prompt is essential when no tools are
    # available — without it the model fabricates tool calls.
    assert p.extra_system_prompt is not None
    assert "NO tools" in p.extra_system_prompt


def test_coding_preset_shape():
    p = trust.PRESET_CODING
    assert p.name == "coding"
    assert p.cwd_mode == "project_directory"
    assert p.mcp_config_mode == "empty"
    # Filesystem tools available (chose coding mode).
    assert "Bash" not in p.disallowed_tools
    assert "Read" not in p.disallowed_tools
    assert "Write" not in p.disallowed_tools
    assert "Edit" not in p.disallowed_tools
    assert "Grep" not in p.disallowed_tools
    # Network and agents stay denied.
    assert "WebFetch" in p.disallowed_tools
    assert "WebSearch" in p.disallowed_tools
    assert "Skill" in p.disallowed_tools
    assert "Agent" in p.disallowed_tools
    assert p.max_turns == 10
    assert p.memory_backend == "claude_md"


def test_full_preset_shape():
    p = trust.PRESET_FULL
    assert p.name == "full"
    assert p.cwd_mode == "project_directory"
    assert p.mcp_config_mode == "inherit"
    # Only AskUserQuestion is denied — everything else is the user's
    # call. This is the "Claude Code in iMessage" posture.
    assert p.disallowed_tools == frozenset({"AskUserQuestion"})
    # Bash, Read, Write, Skill, MCPs, etc. all allowed.
    for tool in ["Bash", "Read", "Write", "Skill", "Agent", "WebFetch"]:
        assert tool not in p.disallowed_tools, f"{tool} must be available in full trust mode"
    assert p.max_turns == 20
    assert p.memory_backend == "claude_md"


def test_preset_disallowed_tools_are_frozen():
    """``disallowed_tools`` must be frozen so a mutation can't escape the
    intended scope of one preset to another."""
    for preset in (trust.PRESET_CHAT_ONLY, trust.PRESET_CODING, trust.PRESET_FULL):
        assert isinstance(preset.disallowed_tools, frozenset)


def test_coding_and_full_carry_resume_scope_prompt():
    """Regression: 2026-05-24. Session resume brings prior augmented
    prompts into the transcript ("The user sent file X..."). Without a
    scoping system prompt, the model can read past-tense attachments as
    present-tense in the new turn ("I see the screenshot — already
    logged" — referencing yesterday's screenshot as if just shared)."""
    from src import claude_runner

    for p in (trust.PRESET_CODING, trust.PRESET_FULL):
        assert (
            p.extra_system_prompt == claude_runner.BRIDGE_RESUME_SCOPE_PROMPT
        ), f"{p.name} preset must carry the resume-scope clarifier"
        # The clarifier must mention the time-scope to actually do its job.
        assert "current" in p.extra_system_prompt.lower()
        assert (
            "past" in p.extra_system_prompt.lower()
            or "historical" in p.extra_system_prompt.lower()
            or "earlier" in p.extra_system_prompt.lower()
        )


# --- get_preset -----------------------------------------------------------


@pytest.mark.parametrize(
    "name,expected",
    [
        ("chat_only", trust.PRESET_CHAT_ONLY),
        ("coding", trust.PRESET_CODING),
        ("full", trust.PRESET_FULL),
    ],
)
def test_get_preset_known_names(name, expected):
    assert trust.get_preset(name) is expected


def test_get_preset_unknown_raises():
    with pytest.raises(trust.UnknownTrustPreset):
        trust.get_preset("nonsense")


def test_get_preset_case_sensitive():
    """Preset names are case-sensitive; ``Chat_Only`` is not a match.

    This is deliberate — config validation should be strict about names
    so an operator typo causes a loud config-load failure, not a silent
    fallback.
    """
    with pytest.raises(trust.UnknownTrustPreset):
        trust.get_preset("Chat_Only")


# --- resolve_trust --------------------------------------------------------


def test_resolve_trust_default_no_alias():
    p = trust.resolve_trust(
        trust_default="chat_only",
        trust_per_alias={},
        active_alias=None,
    )
    assert p is trust.PRESET_CHAT_ONLY


def test_resolve_trust_default_alias_with_no_override():
    p = trust.resolve_trust(
        trust_default="full",
        trust_per_alias={},
        active_alias="myproject",
    )
    assert p is trust.PRESET_FULL


def test_resolve_trust_per_alias_override():
    p = trust.resolve_trust(
        trust_default="full",
        trust_per_alias={"family": "chat_only"},
        active_alias="family",
    )
    assert p is trust.PRESET_CHAT_ONLY


def test_resolve_trust_per_alias_misses_when_alias_none():
    """When no alias is active, per_alias overrides MUST NOT fire."""
    p = trust.resolve_trust(
        trust_default="full",
        trust_per_alias={"family": "chat_only"},
        active_alias=None,
    )
    assert p is trust.PRESET_FULL


def test_resolve_trust_per_alias_unknown_alias():
    """An active alias that has no per-alias entry uses the default."""
    p = trust.resolve_trust(
        trust_default="full",
        trust_per_alias={"family": "chat_only"},
        active_alias="not_in_per_alias",
    )
    assert p is trust.PRESET_FULL


def test_resolve_trust_unknown_default_name_raises():
    """Defense-in-depth: even if config-load missed validation, the
    runtime resolver refuses unknown names rather than silently
    falling through to a safe default."""
    with pytest.raises(trust.UnknownTrustPreset):
        trust.resolve_trust(
            trust_default="invalid_preset",
            trust_per_alias={},
            active_alias=None,
        )


# --- Cross-cutting argv denylist -----------------------------------------


def test_forbidden_argv_flags_exposed():
    """``FORBIDDEN_ARGV_FLAGS`` mirrors ``claude_runner.ARGV_DENYLIST`` so
    ``_assert_safe_argv`` has a single source of truth."""
    assert trust.FORBIDDEN_ARGV_FLAGS == claude_runner.ARGV_DENYLIST
    # Sanity: key dangerous flags ARE in the denylist.
    assert "--dangerously-skip-permissions" in trust.FORBIDDEN_ARGV_FLAGS
    assert "--bypass-permissions" in trust.FORBIDDEN_ARGV_FLAGS
