"""Invoke ``claude -p`` for a single inbound message and parse the result.

Phase B scope: stateless invocation. Each inbound message spawns a fresh
``claude -p`` call into a **hermetic sandbox**:

- cwd is a dedicated empty directory (NOT the user's project_directory) so
  the user's global CLAUDE.md, .mcp.json, .claude/ skills, and settings.json
  do not load into the model's context.
- ``--strict-mcp-config`` + ``--mcp-config <empty>.json`` prevents MCP
  server discovery and startup (no Gmail/Slack/Drive process inheritance).
- ``--append-system-prompt`` injects a minimal "you are a text-only chat
  bot, no tools, no memory" role description.
- ``--tools ""`` disables all built-in tools by default. The config opt-in
  pattern is to list explicit tools, which then become the *only* tools
  Claude may call (and are further filtered against HARD_FORBIDDEN_TOOLS).
- ``--max-turns N`` (default 1) puts a hard ceiling on per-call spend
  before claude even starts spending.
- ``--`` separator placed immediately before the prompt so a malicious
  message body starting with ``--`` cannot be reparsed as additional CLI
  flags by Claude's argument parser.
- Child process is spawned with ``start_new_session=True`` so on timeout
  we can kill the whole process group, not just the immediate ``claude``
  process (Node MCP children otherwise survive as orphans).
- Child environment is scrubbed: only PATH, HOME, ANTHROPIC_API_KEY (if
  set), USER, LANG. No general env inheritance so a prompt that asks for
  ``env`` can only see this whitelist.

Result is a structured ``ClaudeResult``. We never raise on Claude-side
errors; those become ``success=False`` with ``error`` set.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Optional

logger = logging.getLogger(__name__)

# Default location for the Claude Code CLI. Preflight verifies it exists.
DEFAULT_CLAUDE_BIN: Final = "/usr/local/bin/claude"

# Tools the bridge will NEVER allow regardless of config. Belt-and-suspenders
# above the user-tunable forbidden list. Adding to this set requires editing
# THIS constant — deliberate friction point.
HARD_FORBIDDEN_TOOLS: Final = frozenset({
    "Bash",
    "Write",
    "Edit",
    "MultiEdit",
    "NotebookEdit",
    "WebFetch",
    "WebSearch",
    "Skill",
    # MCP-namespaced tools blocked via prefix check, not exact match.
})

# argv tokens that, if present anywhere in argv, mean an unsafe invocation.
# Refusal happens before exec. These should never be in argv constructed by
# this module — the check is purely defense against future regressions or a
# hijacked argv-building path.
ARGV_DENYLIST: Final = frozenset({
    "--dangerously-skip-permissions",
    "--bypass-permissions",
    "--no-permissions",
    "--allow-dangerously-skip-permissions",
    # Unsafe flag values that, if a malicious prompt somehow re-entered argv:
    "--permission-mode=bypassPermissions",
    "--permission-mode=acceptEdits",
})

# Hard cap on prompt length we'll pass to claude. The reader already caps
# at 16KB; this is a second layer.
MAX_PROMPT_BYTES: Final = 32 * 1024

# Minimal system prompt injected via --append-system-prompt. Sets a tight
# role so the model doesn't try to reference Gmail/Slack/Drive/etc. that
# the user's global CLAUDE.md would otherwise have made it think it has.
BRIDGE_SYSTEM_PROMPT: Final = (
    "You are a read-only chat assistant reached over iMessage. "
    "You have no access to email, Slack, Drive, calendars, contacts, "
    "MCP servers, skills, project files, or any user-specific memory. "
    "Do not reference customers, deals, projects, or personal context — "
    "that information is not available here. Available tools (if any) "
    "are listed by the caller; assume nothing else. Keep replies under "
    "1500 characters. If a request requires capabilities you don't have, "
    "say so plainly and stop."
)

# Environment variables the child inherits. Everything else is dropped.
_ENV_ALLOWLIST: Final = frozenset({
    "PATH",
    "HOME",
    "USER",
    "LANG",
    "LC_ALL",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "TMPDIR",
})


@dataclass(frozen=True)
class ClaudeResult:
    success: bool
    reply: str
    session_id: Optional[str]
    cost_usd: float
    duration_ms: int
    error: Optional[str] = None
    error_category: Optional[str] = None  # "timeout" | "exec_error" | "json_parse" | "claude_error"


class RunnerConfigError(RuntimeError):
    """Raised when the runner is asked to do something unsafe."""


def _validate_tool_list(tools: list[str]) -> None:
    """Reject tool lists that include forbidden tools. Empty list is OK
    (means "no tools available" — pure text chat)."""
    bad = HARD_FORBIDDEN_TOOLS & set(tools)
    if bad:
        raise RunnerConfigError(
            f"allowed_tools includes hard-forbidden tools: {sorted(bad)}"
        )
    mcp = [t for t in tools if t.startswith("mcp__")]
    if mcp:
        raise RunnerConfigError(
            f"allowed_tools includes MCP-namespaced tools: {sorted(mcp)} — "
            "the bridge cannot vet MCP tool capabilities"
        )


def _assert_safe_argv(argv: list[str]) -> None:
    """Refuse to exec argv containing any denylisted token (exact or prefix)."""
    for tok in argv:
        if not isinstance(tok, str):
            raise RunnerConfigError(f"non-string argv element: {tok!r}")
        if tok in ARGV_DENYLIST:
            raise RunnerConfigError(f"refusing argv with denylisted token: {tok!r}")
        # Also catch prefix-style use of denied flags via =value:
        for bad in ("--dangerously-skip-permissions",
                    "--bypass-permissions",
                    "--allow-dangerously-skip-permissions"):
            if tok.startswith(bad + "="):
                raise RunnerConfigError(f"refusing argv with denylisted flag form: {tok!r}")


def _scrubbed_env() -> dict:
    """Build a minimal environment for the child process."""
    parent = os.environ
    env = {k: parent[k] for k in _ENV_ALLOWLIST if k in parent}
    # Always set a sane PATH if not present.
    if "PATH" not in env:
        env["PATH"] = "/usr/local/bin:/usr/bin:/bin"
    return env


def run_claude(
    prompt: str,
    *,
    sandbox_cwd: Path,
    mcp_config_path: Path,
    allowed_tools: list[str],
    max_turns: int = 1,
    timeout_seconds: int = 90,
    claude_bin: str = DEFAULT_CLAUDE_BIN,
) -> ClaudeResult:
    """Invoke ``claude -p`` once in a hermetic sandbox.

    ``sandbox_cwd`` should be a dedicated empty directory created by the
    daemon at startup (NOT the user's project directory — that would load
    the user's CLAUDE.md and discover MCP servers).

    ``mcp_config_path`` should point at a file containing ``{"mcpServers":{}}``.

    Raises:
        RunnerConfigError: invocation parameters themselves are unsafe.
        FileNotFoundError: claude_bin or mcp_config_path missing.
    """
    _validate_tool_list(allowed_tools)

    if not Path(claude_bin).is_file():
        raise FileNotFoundError(f"claude binary not found at {claude_bin}")

    if not sandbox_cwd.is_dir():
        raise RunnerConfigError(f"sandbox_cwd not a directory: {sandbox_cwd}")
    if not mcp_config_path.is_file():
        raise FileNotFoundError(f"mcp config not found at {mcp_config_path}")

    # Cap prompt length.
    encoded = prompt.encode("utf-8")
    if len(encoded) > MAX_PROMPT_BYTES:
        prompt = encoded[:MAX_PROMPT_BYTES].decode("utf-8", errors="ignore")

    # ``--tools ""`` is the documented way to disable all built-in tools.
    # When the user provides explicit tools, those replace the empty string.
    tools_value = ",".join(allowed_tools) if allowed_tools else ""

    argv = [
        claude_bin,
        "-p",
        "--output-format", "json",
        "--strict-mcp-config",
        "--mcp-config", str(mcp_config_path),
        "--tools", tools_value,
        "--max-turns", str(int(max_turns)),
        "--append-system-prompt", BRIDGE_SYSTEM_PROMPT,
        # ``--`` is REQUIRED: prevents a prompt that begins with ``--`` from
        # being reparsed as additional flags. Position is right before the
        # positional prompt.
        "--",
        prompt,
    ]
    _assert_safe_argv(argv)

    logger.info(
        "claude -p (sandbox_cwd=%s, tools=%r, max_turns=%d, prompt_bytes=%d)",
        sandbox_cwd, tools_value, max_turns, len(prompt.encode("utf-8")),
    )
    start = time.time()

    # Spawn with new session so we can kill the whole process group on
    # timeout — otherwise Node MCP children survive as orphans.
    try:
        proc = subprocess.Popen(
            argv,
            cwd=str(sandbox_cwd),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_scrubbed_env(),
            start_new_session=True,
        )
    except OSError as e:
        return ClaudeResult(
            success=False, reply="", session_id=None, cost_usd=0.0,
            duration_ms=int((time.time() - start) * 1000),
            error=f"spawn failed: {e}",
            error_category="exec_error",
        )

    try:
        stdout, stderr = proc.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        # Kill the whole process group (claude + any Node MCP children).
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        duration = int((time.time() - start) * 1000)
        logger.warning("claude -p timeout after %ds; killed process group",
                       timeout_seconds)
        return ClaudeResult(
            success=False, reply="", session_id=None, cost_usd=0.0,
            duration_ms=duration,
            error=f"timeout after {timeout_seconds}s",
            error_category="timeout",
        )

    duration = int((time.time() - start) * 1000)

    if proc.returncode != 0:
        # Log full stderr server-side; never echo to user (it may include
        # paths, MCP server names, traceback fragments — see review S3).
        logger.warning("claude -p exit=%d stderr_tail=%r",
                       proc.returncode, (stderr or "")[-500:])
        return ClaudeResult(
            success=False, reply="", session_id=None, cost_usd=0.0,
            duration_ms=duration,
            error=f"claude exit {proc.returncode}",
            error_category="exec_error",
        )

    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError as e:
        logger.warning("claude JSON parse failed: %s; stdout_head=%r",
                       e, (stdout or "")[:500])
        return ClaudeResult(
            success=False, reply="", session_id=None, cost_usd=0.0,
            duration_ms=duration,
            error=f"json parse failed: {e}",
            error_category="json_parse",
        )

    if not isinstance(parsed, dict):
        return ClaudeResult(
            success=False, reply="", session_id=None, cost_usd=0.0,
            duration_ms=duration,
            error="claude JSON output was not a dict",
            error_category="json_parse",
        )

    # Some claude error shapes come back with is_error=True instead of a
    # non-zero exit. Detect those.
    if parsed.get("is_error"):
        return ClaudeResult(
            success=False, reply="", session_id=None, cost_usd=0.0,
            duration_ms=duration,
            error=f"claude reported is_error: {parsed.get('subtype','?')}",
            error_category="claude_error",
        )

    reply = parsed.get("result") or parsed.get("response") or ""
    if not isinstance(reply, str):
        reply = str(reply)

    cost_raw = parsed.get("total_cost_usd")
    try:
        cost_usd = float(cost_raw) if cost_raw is not None else 0.0
    except (TypeError, ValueError):
        cost_usd = 0.0

    session_id = parsed.get("session_id")
    if session_id is not None and not isinstance(session_id, str):
        session_id = None

    return ClaudeResult(
        success=True,
        reply=reply,
        session_id=session_id,
        cost_usd=cost_usd,
        duration_ms=duration,
    )
