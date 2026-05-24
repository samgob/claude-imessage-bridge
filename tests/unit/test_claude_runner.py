"""Security-boundary tests for ``claude_runner``.

This module is the security boundary. The argv we send to ``claude -p``
determines whether tool denial, hermetic invocation, anti-fabrication, and
the -- prompt separator are actually in force. These tests verify the
invariants WITHOUT spawning real claude — we patch subprocess.Popen and
capture argv directly.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from src import claude_runner, trust


# --- _validate_tool_list / HARD_FORBIDDEN_TOOLS --------------------------


def test_validate_tool_list_accepts_empty():
    claude_runner._validate_tool_list([])  # must not raise


def test_validate_tool_list_accepts_read_only_tools():
    # Read isn't in HARD_FORBIDDEN_TOOLS — config could opt into it.
    claude_runner._validate_tool_list(["Read"])  # must not raise


def test_validate_tool_list_rejects_bash():
    with pytest.raises(claude_runner.RunnerConfigError):
        claude_runner._validate_tool_list(["Bash"])


def test_validate_tool_list_rejects_skill():
    # Skill can transitively re-enable denied tools.
    with pytest.raises(claude_runner.RunnerConfigError):
        claude_runner._validate_tool_list(["Skill"])


def test_validate_tool_list_rejects_mcp_namespaced():
    with pytest.raises(claude_runner.RunnerConfigError) as ei:
        claude_runner._validate_tool_list(["mcp__personal__send_message"])
    assert "MCP-namespaced" in str(ei.value)


# --- _assert_safe_argv ---------------------------------------------------


def test_assert_safe_argv_rejects_dangerously_skip_permissions():
    argv = ["/usr/local/bin/claude", "-p", "--dangerously-skip-permissions"]
    with pytest.raises(claude_runner.RunnerConfigError):
        claude_runner._assert_safe_argv(argv)


def test_assert_safe_argv_rejects_value_form():
    # --dangerously-skip-permissions=true should be denied even though it's
    # a prefix-form variant.
    argv = ["/usr/local/bin/claude", "-p", "--dangerously-skip-permissions=true"]
    with pytest.raises(claude_runner.RunnerConfigError):
        claude_runner._assert_safe_argv(argv)


def test_assert_safe_argv_rejects_permission_mode_bypass():
    argv = ["/usr/local/bin/claude", "-p", "--permission-mode=bypassPermissions"]
    with pytest.raises(claude_runner.RunnerConfigError):
        claude_runner._assert_safe_argv(argv)


def test_assert_safe_argv_accepts_normal_argv():
    argv = [
        "/usr/local/bin/claude",
        "-p",
        "--output-format",
        "json",
        "--strict-mcp-config",
        "--disallowed-tools",
        "Bash,Write",
        "--",
        "hello",
    ]
    claude_runner._assert_safe_argv(argv)  # must not raise


def test_assert_safe_argv_rejects_non_string():
    with pytest.raises(claude_runner.RunnerConfigError):
        claude_runner._assert_safe_argv(["claude", 42])  # type: ignore[list-item]


def test_assert_safe_argv_rejects_missing_double_dash():
    """argv MUST contain '--' before the prompt. Without it, a prompt
    that starts with '--' could be reparsed as an additional flag by
    claude's CLI parser. Defense in depth — code always builds with
    '--', this check catches future regressions."""
    argv = [
        "/usr/local/bin/claude",
        "-p",
        "--output-format",
        "json",
        "hello",  # prompt, but no '--' before it
    ]
    with pytest.raises(claude_runner.RunnerConfigError, match="'--' separator"):
        claude_runner._assert_safe_argv(argv)


def test_assert_safe_argv_rejects_double_dash_not_at_end():
    """'--' must immediately precede exactly ONE positional argument
    (the prompt). A '--' followed by more flags / positionals is
    structurally wrong."""
    argv = [
        "/usr/local/bin/claude",
        "-p",
        "--",
        "hello",
        "extra",  # extra positional after the prompt
    ]
    with pytest.raises(claude_runner.RunnerConfigError, match="immediately precede"):
        claude_runner._assert_safe_argv(argv)


def test_assert_safe_argv_rejects_trailing_double_dash():
    """'--' at the very end (no prompt after) is also wrong."""
    argv = [
        "/usr/local/bin/claude",
        "-p",
        "--output-format",
        "json",
        "--",
    ]
    with pytest.raises(claude_runner.RunnerConfigError, match="immediately precede"):
        claude_runner._assert_safe_argv(argv)


# --- _scrubbed_env -------------------------------------------------------


def test_scrubbed_env_only_allowlisted_keys(monkeypatch):
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setenv("HOME", "/Users/x")
    monkeypatch.setenv("LANG", "en_US.UTF-8")
    monkeypatch.setenv("SECRET_TOKEN", "leak-me")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA-leak")
    monkeypatch.setenv("TMPDIR", "/tmp/attacker")
    env = claude_runner._scrubbed_env()
    assert env["PATH"] == "/usr/bin"
    assert env["HOME"] == "/Users/x"
    assert env["LANG"] == "en_US.UTF-8"
    assert "SECRET_TOKEN" not in env
    assert "AWS_ACCESS_KEY_ID" not in env
    assert "TMPDIR" not in env  # specifically must NOT inherit


def test_scrubbed_env_sets_default_path_if_missing(monkeypatch):
    monkeypatch.delenv("PATH", raising=False)
    env = claude_runner._scrubbed_env()
    assert "PATH" in env
    assert "/usr/bin" in env["PATH"]


def test_scrubbed_env_passes_oauth_token(monkeypatch):
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "tok-xxx")
    env = claude_runner._scrubbed_env()
    assert env.get("CLAUDE_CODE_OAUTH_TOKEN") == "tok-xxx"


# --- _write_empty_mcp_safe ----------------------------------------------


def test_write_empty_mcp_safe_creates_file_with_tight_perms(tmp_path: Path):
    target = tmp_path / "empty-mcp.json"
    claude_runner._write_empty_mcp_safe(target)
    assert target.exists()
    assert target.read_text().strip() == '{"mcpServers":{}}'
    mode = target.stat().st_mode & 0o777
    assert mode == 0o600


def test_write_empty_mcp_safe_refuses_existing_path(tmp_path: Path):
    target = tmp_path / "empty-mcp.json"
    target.write_text("attacker-payload")
    with pytest.raises(OSError):  # O_EXCL fails if path exists
        claude_runner._write_empty_mcp_safe(target)


def test_write_empty_mcp_safe_refuses_symlink(tmp_path: Path):
    target_real = tmp_path / "victim.txt"
    target_real.write_text("DO NOT OVERWRITE")
    link = tmp_path / "empty-mcp.json"
    os.symlink(target_real, link)
    with pytest.raises(OSError):  # O_NOFOLLOW + O_EXCL refuse
        claude_runner._write_empty_mcp_safe(link)
    # Verify the symlink target was NOT overwritten.
    assert target_real.read_text() == "DO NOT OVERWRITE"


# --- run_claude argv shape (with mocked Popen) --------------------------


class _FakeProc:
    """Minimal subprocess.Popen substitute for argv-capture tests."""

    def __init__(self, stdout_json: dict, returncode: int = 0):
        self._stdout = json.dumps(stdout_json).encode()
        self._stderr = b""
        self.returncode = returncode
        self.pid = 0
        self.exited = True

    def communicate(self, timeout=None):
        return self._stdout, self._stderr

    def poll(self):
        return self.returncode


@pytest.fixture
def captured_argv(monkeypatch, fake_claude_binary):
    """Run ``run_claude`` against a mocked Popen and return the argv used."""
    holder = {}

    def fake_popen(argv, **kwargs):
        holder["argv"] = list(argv)
        holder["kwargs"] = kwargs
        return _FakeProc({"result": "hi", "session_id": "abc-123", "total_cost_usd": 0.005})

    monkeypatch.setattr(claude_runner.subprocess, "Popen", fake_popen)
    return holder


def test_run_claude_argv_includes_strict_mcp_and_disallow(captured_argv, fake_claude_binary):
    result = claude_runner.run_claude(
        "hello",
        trust_preset=trust.PRESET_CHAT_ONLY,
        project_directory=Path("/tmp"),
        allowed_tools_addons=[],
        claude_bin=str(fake_claude_binary),
    )
    assert result.success
    argv = captured_argv["argv"]
    assert "--strict-mcp-config" in argv
    assert "--disallowed-tools" in argv
    di_value = argv[argv.index("--disallowed-tools") + 1]
    # Must include Bash and Skill; comma-separated single arg form.
    assert "Bash" in di_value.split(",")
    assert "Skill" in di_value.split(",")
    assert "WebFetch" in di_value.split(",")


def test_run_claude_argv_has_double_dash_separator(captured_argv, fake_claude_binary):
    claude_runner.run_claude(
        "hello --not-a-flag",
        trust_preset=trust.PRESET_CHAT_ONLY,
        project_directory=Path("/tmp"),
        allowed_tools_addons=[],
        claude_bin=str(fake_claude_binary),
    )
    argv = captured_argv["argv"]
    # The -- must be the LAST flag before the positional prompt.
    assert argv[-2] == "--"
    assert argv[-1] == "hello --not-a-flag"


def test_run_claude_argv_appends_resume_when_session_given(captured_argv, fake_claude_binary):
    sid = "8859efe4-1234-4abc-9def-abcdef012345"
    claude_runner.run_claude(
        "hello",
        trust_preset=trust.PRESET_CHAT_ONLY,
        project_directory=Path("/tmp"),
        allowed_tools_addons=[],
        claude_bin=str(fake_claude_binary),
        resume_session_id=sid,
    )
    argv = captured_argv["argv"]
    assert "--resume" in argv
    assert argv[argv.index("--resume") + 1] == sid


# --- session_id format validator -----------------------------------------


def test_validate_session_id_accepts_uuid():
    sid = "8859efe4-1234-5678-9abc-def012345678"
    assert claude_runner._validate_session_id(sid) == sid


def test_validate_session_id_lowercases_input():
    assert (
        claude_runner._validate_session_id("8859EFE4-1234-5678-9ABC-DEF012345678")
        == "8859efe4-1234-5678-9abc-def012345678"
    )


def test_validate_session_id_strips_whitespace():
    assert (
        claude_runner._validate_session_id("  8859efe4-1234-5678-9abc-def012345678  ")
        == "8859efe4-1234-5678-9abc-def012345678"
    )


def test_validate_session_id_rejects_flag_lookalike():
    """Defense-in-depth: a session_id starting with `--` could be
    interpreted as an additional flag by some downstream parser. The
    UUID-shape regex blocks this entire class of input."""
    with pytest.raises(claude_runner.RunnerConfigError, match="UUID shape"):
        claude_runner._validate_session_id("--dangerous-flag")


def test_validate_session_id_rejects_path_traversal():
    """Same defense covers path-traversal characters."""
    with pytest.raises(claude_runner.RunnerConfigError):
        claude_runner._validate_session_id("../../../etc/passwd")


def test_validate_session_id_rejects_shell_meta():
    for evil in (";rm -rf /", "`whoami`", "$(echo)", "&& curl"):
        with pytest.raises(claude_runner.RunnerConfigError):
            claude_runner._validate_session_id(evil)


def test_validate_session_id_rejects_empty():
    with pytest.raises(claude_runner.RunnerConfigError):
        claude_runner._validate_session_id("")


def test_validate_session_id_rejects_non_string():
    with pytest.raises(claude_runner.RunnerConfigError):
        claude_runner._validate_session_id(None)  # type: ignore[arg-type]


def test_run_claude_rejects_malformed_resume_session_id(
    captured_argv,
    fake_claude_binary,
):
    """The argv-build path validates session_id — a malformed value
    raises RunnerConfigError instead of being inserted into argv."""
    with pytest.raises(claude_runner.RunnerConfigError, match="UUID shape"):
        claude_runner.run_claude(
            "hello",
            trust_preset=trust.PRESET_CHAT_ONLY,
            project_directory=Path("/tmp"),
            allowed_tools_addons=[],
            claude_bin=str(fake_claude_binary),
            resume_session_id="not-a-uuid",
        )


def test_run_claude_argv_no_resume_when_session_none(captured_argv, fake_claude_binary):
    claude_runner.run_claude(
        "hello",
        trust_preset=trust.PRESET_CHAT_ONLY,
        project_directory=Path("/tmp"),
        allowed_tools_addons=[],
        claude_bin=str(fake_claude_binary),
        resume_session_id=None,
    )
    assert "--resume" not in captured_argv["argv"]


def test_run_claude_argv_max_turns_from_preset(captured_argv, fake_claude_binary):
    """Max turns is now a property of the TrustPreset, not a runtime arg."""
    # chat_only preset is max_turns=1
    claude_runner.run_claude(
        "hello",
        trust_preset=trust.PRESET_CHAT_ONLY,
        project_directory=Path("/tmp"),
        allowed_tools_addons=[],
        claude_bin=str(fake_claude_binary),
    )
    argv = captured_argv["argv"]
    assert "--max-turns" in argv
    assert argv[argv.index("--max-turns") + 1] == "1"


def test_run_claude_argv_max_turns_full_preset(captured_argv, fake_claude_binary):
    """Full preset's max_turns=20 must appear in argv."""
    claude_runner.run_claude(
        "hello",
        trust_preset=trust.PRESET_FULL,
        project_directory=Path("/tmp"),
        allowed_tools_addons=[],
        claude_bin=str(fake_claude_binary),
    )
    argv = captured_argv["argv"]
    assert argv[argv.index("--max-turns") + 1] == "20"


def test_run_claude_argv_includes_anti_fabrication_prompt(captured_argv, fake_claude_binary):
    claude_runner.run_claude(
        "hello",
        trust_preset=trust.PRESET_CHAT_ONLY,
        project_directory=Path("/tmp"),
        allowed_tools_addons=[],
        claude_bin=str(fake_claude_binary),
    )
    argv = captured_argv["argv"]
    assert "--append-system-prompt" in argv
    prompt = argv[argv.index("--append-system-prompt") + 1]
    # Sanity-check the system prompt: it must tell the model it has no tools
    # AND not to fabricate tool calls. Both phrases are load-bearing.
    assert "NO tools" in prompt
    assert "Do NOT fabricate tool calls" in prompt


def test_run_claude_argv_allowed_tools_filters_disallow(captured_argv, fake_claude_binary):
    """If the user opts into Read, it must NOT appear in --disallowed-tools."""
    claude_runner.run_claude(
        "hello",
        trust_preset=trust.PRESET_CHAT_ONLY,
        project_directory=Path("/tmp"),
        allowed_tools_addons=["Read"],
        claude_bin=str(fake_claude_binary),
    )
    argv = captured_argv["argv"]
    di_value = argv[argv.index("--disallowed-tools") + 1]
    allow_value = argv[argv.index("--allowed-tools") + 1]
    assert "Read" not in di_value.split(",")
    assert "Read" in allow_value.split(",")
    # But Bash must still be denied.
    assert "Bash" in di_value.split(",")


def test_run_claude_argv_no_dangerous_flags(captured_argv, fake_claude_binary):
    claude_runner.run_claude(
        "hello",
        trust_preset=trust.PRESET_CHAT_ONLY,
        project_directory=Path("/tmp"),
        allowed_tools_addons=[],
        claude_bin=str(fake_claude_binary),
    )
    argv = captured_argv["argv"]
    for bad in claude_runner.ARGV_DENYLIST:
        assert bad not in argv


def test_run_claude_argv_mcp_config_in_sandbox(captured_argv, fake_claude_binary):
    claude_runner.run_claude(
        "hello",
        trust_preset=trust.PRESET_CHAT_ONLY,
        project_directory=Path("/tmp"),
        allowed_tools_addons=[],
        claude_bin=str(fake_claude_binary),
    )
    argv = captured_argv["argv"]
    assert "--mcp-config" in argv
    mcp_path = argv[argv.index("--mcp-config") + 1]
    # Must be in a tempdir named cimb-call-*, not in user's home.
    assert "cimb-call-" in mcp_path
    assert "/empty-mcp.json" in mcp_path


def test_run_claude_argv_cwd_is_sandbox(captured_argv, fake_claude_binary):
    claude_runner.run_claude(
        "hello",
        trust_preset=trust.PRESET_CHAT_ONLY,
        project_directory=Path("/tmp"),
        allowed_tools_addons=[],
        claude_bin=str(fake_claude_binary),
    )
    cwd = captured_argv["kwargs"]["cwd"]
    # cwd must be the per-call sandbox tempdir, NOT user's project_directory
    # or the bridge state dir. The dir won't exist anymore by the time we
    # inspect (TemporaryDirectory cleanup), but the path string must match.
    assert "cimb-call-" in cwd


def test_run_claude_spawns_with_new_session(captured_argv, fake_claude_binary):
    """``start_new_session=True`` is required for process-group kill."""
    claude_runner.run_claude(
        "hello",
        trust_preset=trust.PRESET_CHAT_ONLY,
        project_directory=Path("/tmp"),
        allowed_tools_addons=[],
        claude_bin=str(fake_claude_binary),
    )
    assert captured_argv["kwargs"]["start_new_session"] is True


def test_run_claude_rejects_forbidden_tool_in_allowed_list(fake_claude_binary):
    with pytest.raises(claude_runner.RunnerConfigError):
        claude_runner.run_claude(
            "hello",
            trust_preset=trust.PRESET_CHAT_ONLY,
            project_directory=Path("/tmp"),
            allowed_tools_addons=["Bash"],
            claude_bin=str(fake_claude_binary),
        )


def test_run_claude_rejects_missing_binary(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        claude_runner.run_claude(
            "hello",
            trust_preset=trust.PRESET_CHAT_ONLY,
            project_directory=Path("/tmp"),
            allowed_tools_addons=[],
            claude_bin=str(tmp_path / "nope"),
        )


def test_run_claude_caps_prompt_length(monkeypatch, fake_claude_binary):
    holder = {}

    def fake_popen(argv, **kwargs):
        holder["argv"] = argv
        return _FakeProc({"result": "ok", "session_id": "x", "total_cost_usd": 0.0})

    monkeypatch.setattr(claude_runner.subprocess, "Popen", fake_popen)
    # 64 KB prompt — well over the 32 KB cap
    big_prompt = "A" * (64 * 1024)
    claude_runner.run_claude(
        big_prompt,
        trust_preset=trust.PRESET_CHAT_ONLY,
        project_directory=Path("/tmp"),
        allowed_tools_addons=[],
        claude_bin=str(fake_claude_binary),
    )
    sent = holder["argv"][-1]
    assert len(sent.encode("utf-8")) <= claude_runner.MAX_PROMPT_BYTES


# --- run_claude result parsing ------------------------------------------


def test_run_claude_returns_session_id_and_cost(monkeypatch, fake_claude_binary):
    monkeypatch.setattr(
        claude_runner.subprocess,
        "Popen",
        lambda argv, **kw: _FakeProc(
            {
                "result": "hello!",
                "session_id": "sess-12345",
                "total_cost_usd": 0.0432,
            }
        ),
    )
    r = claude_runner.run_claude(
        "hi",
        trust_preset=trust.PRESET_CHAT_ONLY,
        project_directory=Path("/tmp"),
        allowed_tools_addons=[],
        claude_bin=str(fake_claude_binary),
    )
    assert r.success
    assert r.reply == "hello!"
    assert r.session_id == "sess-12345"
    assert r.cost_usd == pytest.approx(0.0432)
    assert r.error_category is None


def test_run_claude_handles_is_error_response(monkeypatch, fake_claude_binary):
    monkeypatch.setattr(
        claude_runner.subprocess,
        "Popen",
        lambda argv, **kw: _FakeProc({"is_error": True, "subtype": "rate_limit"}),
    )
    r = claude_runner.run_claude(
        "hi",
        trust_preset=trust.PRESET_CHAT_ONLY,
        project_directory=Path("/tmp"),
        allowed_tools_addons=[],
        claude_bin=str(fake_claude_binary),
    )
    assert not r.success
    assert r.error_category == "claude_error"
    assert "rate_limit" in (r.error or "")


def test_run_claude_handles_non_zero_exit(monkeypatch, fake_claude_binary):
    proc = _FakeProc({}, returncode=2)
    proc._stdout = b""
    proc._stderr = b"some internal error path /Users/x/.claude/oops"
    monkeypatch.setattr(
        claude_runner.subprocess,
        "Popen",
        lambda argv, **kw: proc,
    )
    r = claude_runner.run_claude(
        "hi",
        trust_preset=trust.PRESET_CHAT_ONLY,
        project_directory=Path("/tmp"),
        allowed_tools_addons=[],
        claude_bin=str(fake_claude_binary),
    )
    assert not r.success
    assert r.error_category == "exec_error"
    # Critically: error string must NOT leak the stderr internals.
    assert "/Users/x/.claude" not in (r.error or "")


def test_run_claude_detects_stale_session_resume(monkeypatch, fake_claude_binary):
    """Claude exits 1 with 'No conversation found' when --resume points at
    a session that's not on disk. The runner detects this specific stderr
    and returns error_category='resume_missing' so the daemon can clear
    the stale pointer and retry fresh."""
    proc = _FakeProc({}, returncode=1)
    proc._stdout = b""
    proc._stderr = (
        b"No conversation found with session ID: " b"eff33daf-1ae1-422a-b291-9cd8bac21c8d\n"
    )
    monkeypatch.setattr(
        claude_runner.subprocess,
        "Popen",
        lambda argv, **kw: proc,
    )
    r = claude_runner.run_claude(
        "hi",
        trust_preset=trust.PRESET_CHAT_ONLY,
        project_directory=Path("/tmp"),
        allowed_tools_addons=[],
        claude_bin=str(fake_claude_binary),
        resume_session_id="eff33daf-1ae1-422a-b291-9cd8bac21c8d",
    )
    assert not r.success
    assert r.error_category == "resume_missing"
    # The stale id is acknowledged in the error string (prefix only,
    # not the full id — we don't leak the session id externally).
    assert "eff33daf" in (r.error or "")


def test_run_claude_extracts_permission_denials(monkeypatch, fake_claude_binary):
    """When claude reports permission_denials in its JSON, the runner
    extracts them into ClaudeResult so the daemon can act."""
    monkeypatch.setattr(
        claude_runner.subprocess,
        "Popen",
        lambda argv, **kw: _FakeProc(
            {
                "result": "I tried to edit CLAUDE.md but was blocked.",
                "session_id": "sess-abc",
                "total_cost_usd": 0.05,
                "permission_denials": [
                    {
                        "tool_name": "Edit",
                        "tool_input": {"file_path": "/Users/sam/.claude/CLAUDE.md"},
                    },
                ],
                "is_error": False,
            }
        ),
    )
    r = claude_runner.run_claude(
        "update memory",
        trust_preset=trust.PRESET_FULL,
        project_directory=Path("/tmp"),
        allowed_tools_addons=[],
        claude_bin=str(fake_claude_binary),
    )
    assert r.success
    assert len(r.permission_denials) == 1
    assert r.permission_denials[0]["tool_name"] == "Edit"


def test_run_claude_empty_permission_denials_default(monkeypatch, fake_claude_binary):
    """A normal success with no denials reports an empty list (not None)."""
    monkeypatch.setattr(
        claude_runner.subprocess,
        "Popen",
        lambda argv, **kw: _FakeProc(
            {
                "result": "ok",
                "session_id": "sess-abc",
                "total_cost_usd": 0.01,
            }
        ),
    )
    r = claude_runner.run_claude(
        "hi",
        trust_preset=trust.PRESET_CHAT_ONLY,
        project_directory=Path("/tmp"),
        allowed_tools_addons=[],
        claude_bin=str(fake_claude_binary),
    )
    assert r.success
    assert r.permission_denials == []


def test_run_claude_permission_relay_retry_passes_acceptEdits(monkeypatch, fake_claude_binary):
    """When permission_relay_retry=True, argv includes
    --permission-mode=acceptEdits and the safety check accepts it."""
    holder = {}

    def fake_popen(argv, **kwargs):
        holder["argv"] = list(argv)
        return _FakeProc({"result": "applied", "session_id": "x", "total_cost_usd": 0.02})

    monkeypatch.setattr(claude_runner.subprocess, "Popen", fake_popen)
    r = claude_runner.run_claude(
        "please proceed",
        trust_preset=trust.PRESET_FULL,
        project_directory=Path("/tmp"),
        allowed_tools_addons=[],
        claude_bin=str(fake_claude_binary),
        permission_relay_retry=True,
    )
    assert r.success
    assert "--permission-mode=acceptEdits" in holder["argv"]


def test_run_claude_default_call_rejects_acceptEdits_in_argv():
    """Plain _assert_safe_argv (no override) refuses
    --permission-mode=acceptEdits. The relay path opts in explicitly;
    a regression accidentally adding it elsewhere is still blocked."""
    argv = ["/usr/local/bin/claude", "-p", "--permission-mode=acceptEdits"]
    with pytest.raises(claude_runner.RunnerConfigError):
        claude_runner._assert_safe_argv(argv)


def test_run_claude_assert_safe_argv_with_acceptEdits_override():
    """When the caller passes allow_overrides containing the token,
    it's accepted."""
    argv = ["/usr/local/bin/claude", "-p", "--permission-mode=acceptEdits", "--", "x"]
    claude_runner._assert_safe_argv(
        argv,
        allow_overrides=frozenset({"--permission-mode=acceptEdits"}),
    )  # must not raise


def test_run_claude_accept_edits_passes_acceptEdits_flag(monkeypatch, fake_claude_binary):
    """accept_edits=True is the default-mode equivalent of permission_relay_retry:
    routine edits go through without round-tripping to the user for approval."""
    holder = {}

    def fake_popen(argv, **kwargs):
        holder["argv"] = list(argv)
        return _FakeProc({"result": "done", "session_id": "x", "total_cost_usd": 0.0})

    monkeypatch.setattr(claude_runner.subprocess, "Popen", fake_popen)
    claude_runner.run_claude(
        "edit the health log",
        trust_preset=trust.PRESET_FULL,
        project_directory=Path("/tmp"),
        allowed_tools_addons=[],
        claude_bin=str(fake_claude_binary),
        accept_edits=True,
    )
    assert "--permission-mode=acceptEdits" in holder["argv"]


def test_run_claude_accept_edits_with_protected_files_emits_deny_settings(
    monkeypatch, fake_claude_binary
):
    """protected_files becomes permissions.deny rules in inline --settings JSON.
    CLAUDE.md edits should require explicit approval (relay flow) even though
    everything else is acceptEdits-auto-accepted."""
    import json

    holder = {}

    def fake_popen(argv, **kwargs):
        holder["argv"] = list(argv)
        return _FakeProc({"result": "done", "session_id": "x", "total_cost_usd": 0.0})

    monkeypatch.setattr(claude_runner.subprocess, "Popen", fake_popen)
    claude_runner.run_claude(
        "edit something",
        trust_preset=trust.PRESET_FULL,
        project_directory=Path("/tmp"),
        allowed_tools_addons=[],
        claude_bin=str(fake_claude_binary),
        accept_edits=True,
        protected_files=["~/.claude/CLAUDE.md"],
    )
    argv = holder["argv"]
    assert "--settings" in argv
    settings_json = argv[argv.index("--settings") + 1]
    parsed = json.loads(settings_json)
    deny = parsed["permissions"]["deny"]
    expanded = str(Path("~/.claude/CLAUDE.md").expanduser())
    assert f"Edit({expanded})" in deny
    assert f"Write({expanded})" in deny
    assert f"MultiEdit({expanded})" in deny


def test_run_claude_relay_retry_omits_deny_rules(monkeypatch, fake_claude_binary):
    """On the permission-relay retry path the user has already approved the
    edit — the deny rules must NOT be passed, otherwise the approved edit
    would still be blocked."""
    holder = {}

    def fake_popen(argv, **kwargs):
        holder["argv"] = list(argv)
        return _FakeProc({"result": "applied", "session_id": "x", "total_cost_usd": 0.0})

    monkeypatch.setattr(claude_runner.subprocess, "Popen", fake_popen)
    claude_runner.run_claude(
        "please proceed",
        trust_preset=trust.PRESET_FULL,
        project_directory=Path("/tmp"),
        allowed_tools_addons=[],
        claude_bin=str(fake_claude_binary),
        permission_relay_retry=True,
        # Caller (daemon) might still pass these, but retry must drop them:
        accept_edits=True,
        protected_files=["~/.claude/CLAUDE.md"],
    )
    argv = holder["argv"]
    assert "--permission-mode=acceptEdits" in argv
    # No --settings JSON on the retry path — the approved edit must apply.
    assert "--settings" not in argv


def test_run_claude_no_accept_edits_default(monkeypatch, fake_claude_binary):
    """Without accept_edits=True, no --permission-mode=acceptEdits in argv —
    backward compat for chat_only/coding test scenarios that don't pass it."""
    holder = {}

    def fake_popen(argv, **kwargs):
        holder["argv"] = list(argv)
        return _FakeProc({"result": "ok", "session_id": "x", "total_cost_usd": 0.0})

    monkeypatch.setattr(claude_runner.subprocess, "Popen", fake_popen)
    claude_runner.run_claude(
        "hi",
        trust_preset=trust.PRESET_CHAT_ONLY,
        project_directory=Path("/tmp"),
        allowed_tools_addons=[],
        claude_bin=str(fake_claude_binary),
    )
    assert "--permission-mode=acceptEdits" not in holder["argv"]
    assert "--settings" not in holder["argv"]


def test_run_claude_bypassPermissions_never_allowed_even_with_override():
    """--permission-mode=bypassPermissions is permanently refused.
    Even an explicit override doesn't unlock it — it disables Claude
    Code's entire permission system, which is too dangerous to ever
    grant from the bridge."""
    argv = ["claude", "-p", "--permission-mode=bypassPermissions", "--", "x"]
    with pytest.raises(claude_runner.RunnerConfigError):
        claude_runner._assert_safe_argv(
            argv,
            allow_overrides=frozenset({"--permission-mode=bypassPermissions"}),
        )


def test_run_claude_resume_missing_only_fires_with_resume_arg(monkeypatch, fake_claude_binary):
    """If the same stderr arrives but the call wasn't using --resume,
    classify as plain exec_error (not resume_missing) — there's no
    pointer to clear."""
    proc = _FakeProc({}, returncode=1)
    proc._stdout = b""
    proc._stderr = b"No conversation found with session ID: anything\n"
    monkeypatch.setattr(
        claude_runner.subprocess,
        "Popen",
        lambda argv, **kw: proc,
    )
    r = claude_runner.run_claude(
        "hi",
        trust_preset=trust.PRESET_CHAT_ONLY,
        project_directory=Path("/tmp"),
        allowed_tools_addons=[],
        claude_bin=str(fake_claude_binary),
        resume_session_id=None,  # no resume requested
    )
    assert not r.success
    assert r.error_category == "exec_error"


def test_run_claude_handles_malformed_json(monkeypatch, fake_claude_binary):
    proc = _FakeProc({})
    proc._stdout = b"not json at all"
    monkeypatch.setattr(
        claude_runner.subprocess,
        "Popen",
        lambda argv, **kw: proc,
    )
    r = claude_runner.run_claude(
        "hi",
        trust_preset=trust.PRESET_CHAT_ONLY,
        project_directory=Path("/tmp"),
        allowed_tools_addons=[],
        claude_bin=str(fake_claude_binary),
    )
    assert not r.success
    assert r.error_category == "json_parse"


def test_run_claude_handles_timeout(monkeypatch, fake_claude_binary):
    class _SlowProc(_FakeProc):
        def __init__(self):
            super().__init__({"result": "ok"})
            self.pid = 999999  # likely-nonexistent pid

        def communicate(self, timeout=None):
            raise subprocess.TimeoutExpired(cmd="claude", timeout=timeout or 0)

    monkeypatch.setattr(
        claude_runner.subprocess,
        "Popen",
        lambda argv, **kw: _SlowProc(),
    )
    # _kill_process_group will try os.getpgid on a likely-nonexistent pid;
    # that should be silently swallowed.
    r = claude_runner.run_claude(
        "hi",
        trust_preset=trust.PRESET_CHAT_ONLY,
        project_directory=Path("/tmp"),
        allowed_tools_addons=[],
        claude_bin=str(fake_claude_binary),
        timeout_seconds=1,
    )
    assert not r.success
    assert r.error_category == "timeout"


# --- HARD_DISALLOWED coverage --------------------------------------------


def test_hard_disallowed_exact_snapshot():
    """Snapshot of HARD_DISALLOWED. Any addition or removal must update
    this test consciously — that's the point. Round-4 adversarial finding
    was that the prior 'required subset' test missed 11 entries actually
    in the deny list (EnterWorktree, ExitWorktree, TaskStop, TaskOutput,
    TodoWrite, NotebookRead, ListMcpResourcesTool, ReadMcpResourceTool,
    EnterPlanMode, ExitPlanMode, AskUserQuestion) — a regression that
    removed them would have passed silently.
    """
    expected = frozenset(
        {
            # Filesystem write/exec
            "Bash",
            "Write",
            "Edit",
            "MultiEdit",
            "NotebookEdit",
            # Filesystem read
            "Read",
            "Grep",
            "Glob",
            "LS",
            "NotebookRead",
            # Network egress
            "WebFetch",
            "WebSearch",
            # Tool/skill/agent loading
            "Skill",
            "Agent",
            "ToolSearch",
            # Scheduling
            "CronCreate",
            "CronDelete",
            "CronList",
            "CronToggle",
            "ScheduleWakeup",
            # Communication / out-of-band
            "AskUserQuestion",
            "RemoteTrigger",
            "PushNotification",
            # Task / state / plan
            "TodoWrite",
            "TaskStop",
            "TaskOutput",
            "EnterWorktree",
            "ExitWorktree",
            "EnterPlanMode",
            "ExitPlanMode",
            # MCP introspection
            "ListMcpResourcesTool",
            "ReadMcpResourceTool",
        }
    )
    actual = frozenset(claude_runner.HARD_DISALLOWED)
    added = actual - expected
    removed = expected - actual
    assert not (added or removed), (
        "HARD_DISALLOWED drift — added: %s, removed: %s. Update this test "
        "consciously to reflect the security review of the change."
        % (sorted(added), sorted(removed))
    )


def test_hard_forbidden_subset_of_hard_disallowed():
    """Anything we refuse to let users opt INTO must also be in the active
    deny list (otherwise the deny list could be silently widened by config).
    Exception: ``HARD_FORBIDDEN_TOOLS`` is a strict subset that also blocks
    MCP-namespaced tools, which aren't enumerable in HARD_DISALLOWED.
    """
    leaks = claude_runner.HARD_FORBIDDEN_TOOLS - claude_runner.HARD_DISALLOWED
    assert not leaks, f"HARD_FORBIDDEN_TOOLS leak — forbidden but not denied: {sorted(leaks)}"


# --- _encode_cwd_for_projects / _cleanup_sandbox_session -----------------


def test_encode_cwd_for_projects_replaces_slashes():
    """Claude's encoding turns / into - in the projects/ subdir name."""
    encoded = claude_runner._encode_cwd_for_projects(
        Path("/private/var/folders/abc/T/cimb-call-XXXX")
    )
    assert encoded == "-private-var-folders-abc-T-cimb-call-XXXX"


def test_encode_cwd_for_projects_replaces_spaces():
    """Spaces also become - in Claude's encoding (lossy)."""
    encoded = claude_runner._encode_cwd_for_projects(Path("/Users/me/Desktop/With Spaces"))
    assert encoded == "-Users-me-Desktop-With-Spaces"


def test_cleanup_sandbox_session_removes_jsonl(tmp_path: Path):
    """A simulated ~/.claude/projects/<encoded>/<sid>.jsonl is removed."""
    sandbox_cwd = Path("/tmp/cimb-call-fake1234")
    sid = "abcdef01-2345-6789-abcd-ef0123456789"
    projects_root = tmp_path / "projects"
    encoded = claude_runner._encode_cwd_for_projects(sandbox_cwd)
    project_dir = projects_root / encoded
    project_dir.mkdir(parents=True)
    jsonl = project_dir / f"{sid}.jsonl"
    jsonl.write_text('{"type":"user","content":"hi"}\n')
    assert jsonl.exists()

    claude_runner._cleanup_sandbox_session(
        sandbox_cwd,
        sid,
        projects_root=projects_root,
    )

    assert not jsonl.exists()
    # Parent dir was empty, should also be gone (best-effort rmdir).
    assert not project_dir.exists()


def test_cleanup_sandbox_session_silent_on_missing_file(tmp_path: Path):
    """No JSONL on disk = no-op, no exception."""
    sandbox_cwd = Path("/tmp/cimb-call-vanished")
    sid = "abcdef01-2345-6789-abcd-ef0123456789"
    projects_root = tmp_path / "projects"
    projects_root.mkdir()
    # Should not raise.
    claude_runner._cleanup_sandbox_session(
        sandbox_cwd,
        sid,
        projects_root=projects_root,
    )


def test_cleanup_sandbox_session_skips_when_no_session_id(tmp_path: Path):
    """Falsy session_id = nothing to clean. Must not touch disk."""
    sandbox_cwd = Path("/tmp/cimb-call-xxx")
    projects_root = tmp_path / "projects"
    projects_root.mkdir()
    claude_runner._cleanup_sandbox_session(
        sandbox_cwd,
        None,
        projects_root=projects_root,
    )
    claude_runner._cleanup_sandbox_session(
        sandbox_cwd,
        "",
        projects_root=projects_root,
    )


def test_cleanup_sandbox_session_refuses_path_traversal_sid(tmp_path: Path):
    """A claude-returned session id with .. or / must NOT escape the projects tree."""
    sandbox_cwd = Path("/tmp/cimb-call-xxx")
    projects_root = tmp_path / "projects"
    projects_root.mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("DO NOT TOUCH")
    # Even though no file matches these patterns under projects_root, the
    # check is that the function returns without touching disk.
    claude_runner._cleanup_sandbox_session(
        sandbox_cwd,
        "../../../etc/passwd",
        projects_root=projects_root,
    )
    claude_runner._cleanup_sandbox_session(
        sandbox_cwd,
        "../victim",
        projects_root=projects_root,
    )
    assert victim.read_text() == "DO NOT TOUCH"


def test_run_claude_cleans_up_jsonl_after_call(monkeypatch, fake_claude_binary, tmp_path: Path):
    """End-to-end: run_claude completing successfully removes the JSONL."""
    fake_projects = tmp_path / "projects"

    # Capture the sandbox cwd Popen was called with, so we can pre-create the
    # JSONL file at the same encoded location run_claude will look for.
    holder: dict = {}

    def fake_popen(argv, **kwargs):
        holder["cwd"] = kwargs["cwd"]
        # Pre-create the JSONL that claude would have written.
        encoded = claude_runner._encode_cwd_for_projects(Path(kwargs["cwd"]))
        d = fake_projects / encoded
        d.mkdir(parents=True, exist_ok=True)
        jsonl = d / "test-sid-9999.jsonl"
        jsonl.write_text('{"type":"user"}\n')
        holder["jsonl"] = jsonl
        return _FakeProc(
            {
                "result": "hi",
                "session_id": "test-sid-9999",
                "total_cost_usd": 0.001,
            }
        )

    monkeypatch.setattr(claude_runner.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(claude_runner, "DEFAULT_PROJECTS_ROOT", fake_projects)

    r = claude_runner.run_claude(
        "hi",
        trust_preset=trust.PRESET_CHAT_ONLY,
        project_directory=Path("/tmp"),
        allowed_tools_addons=[],
        claude_bin=str(fake_claude_binary),
    )
    assert r.success
    assert r.session_id == "test-sid-9999"
    # Cleanup must have run after the with-block exit.
    assert not holder["jsonl"].exists()


def test_assert_safe_argv_prefix_consistency():
    """Every bare-flag entry in ARGV_DENYLIST must also be refused in the
    `--flag=value` form. Round-4 finding: the prior hand-rolled prefix list
    omitted some bare flags (e.g., `--no-permissions`); deriving the
    prefix-form check from the exact set keeps them in sync.
    """
    bare_flags = [t for t in claude_runner.ARGV_DENYLIST if "=" not in t]
    assert bare_flags, "ARGV_DENYLIST must contain at least some bare-flag entries"
    for flag in bare_flags:
        with pytest.raises(claude_runner.RunnerConfigError):
            claude_runner._assert_safe_argv([flag + "=true"])
