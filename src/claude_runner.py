"""Invoke ``claude -p`` for a single inbound message and parse the result.

Phase B scope: stateless invocation. Each inbound message spawns a fresh
``claude -p`` call. Session resume (``--resume <id>``) is Phase C — and even
there, only against sessions whose tool authority we're comfortable
exposing to iMessage.

Security gates:

- ``--allowed-tools`` is required. Empty / missing → refuse.
- ``HARD_FORBIDDEN_TOOLS`` cannot appear in the allowlist regardless of
  what config says. Bash, Write, Edit, WebFetch, Skill, etc.
- ``ARGV_DENYLIST`` tokens (``--dangerously-skip-permissions``,
  ``--bypass-permissions``) are checked against the constructed argv
  immediately before exec. Belt-and-suspenders: even if a future code
  change passes one accidentally, we refuse to run.
- Per-call timeout (configurable, default 120s). Kills runaway calls
  rather than letting them block the daemon indefinitely.
- ``cwd`` is set explicitly; we never rely on the daemon's cwd.

The result is a structured ``ClaudeResult`` so the caller can choose what
to do with errors vs. successes without parsing strings.
"""

from __future__ import annotations

import json
import logging
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Optional

logger = logging.getLogger(__name__)

# Default location for the Claude Code CLI. Preflight verifies it exists.
DEFAULT_CLAUDE_BIN: Final = "/usr/local/bin/claude"

# Tools the bridge will NEVER allow regardless of config. The forbidden set
# in config.yaml is a user-tunable surface; this set is a hard floor.
# Adding any of these to a future ``allowed_tools`` requires editing this
# constant — which is a deliberate friction point requiring code review.
HARD_FORBIDDEN_TOOLS: Final = frozenset({
    "Bash",
    "Write",
    "Edit",
    "MultiEdit",
    "NotebookEdit",
    "WebFetch",
    "WebSearch",
    "Skill",
    # MCP-namespaced tools: name-prefix match handled separately.
})

# argv tokens that signal "user asked for unsafe behavior." If any of these
# show up in the constructed argv we refuse to exec. The constructor below
# does not pass these — this is purely a defense against future regressions
# or a hijacked config-to-argv path.
ARGV_DENYLIST: Final = frozenset({
    "--dangerously-skip-permissions",
    "--bypass-permissions",
    "--no-permissions",
})

# Hard cap on prompt length we'll pass to claude. The reader already caps
# at 16KB; this is a second layer in case future code paths fan in larger
# context (e.g., Phase C session history).
MAX_PROMPT_BYTES: Final = 32 * 1024


@dataclass(frozen=True)
class ClaudeResult:
    """Outcome of one ``claude -p`` invocation."""

    success: bool
    reply: str                     # the user-facing response text
    session_id: Optional[str]      # for Phase C resume
    cost_usd: float                # 0.0 if unknown
    duration_ms: int
    error: Optional[str] = None    # non-None iff success=False


class RunnerConfigError(RuntimeError):
    """Raised when the runner is asked to do something unsafe."""


def _validate_tool_list(tools: list[str]) -> None:
    """Reject tool lists that include forbidden tools.

    MCP-prefixed tools (``mcp__*``) are blocked categorically because they
    represent integrations the bridge can't audit (Gmail send, Drive
    upload, etc., all live behind MCP).
    """
    if not tools:
        raise RunnerConfigError(
            "allowed_tools is empty — refuse to invoke claude with no tools "
            "(would default to the full set)"
        )
    bad = HARD_FORBIDDEN_TOOLS & set(tools)
    if bad:
        raise RunnerConfigError(
            f"allowed_tools includes hard-forbidden tools: {sorted(bad)}"
        )
    mcp = [t for t in tools if t.startswith("mcp__")]
    if mcp:
        raise RunnerConfigError(
            f"allowed_tools includes MCP-namespaced tools: {sorted(mcp)} — "
            "the bridge cannot vet MCP tool capabilities; refuse"
        )


def _assert_safe_argv(argv: list[str]) -> None:
    for tok in argv:
        if tok in ARGV_DENYLIST:
            raise RunnerConfigError(f"refusing argv with denylisted token: {tok!r}")


def run_claude(
    prompt: str,
    *,
    cwd: Path,
    allowed_tools: list[str],
    timeout_seconds: int = 120,
    claude_bin: str = DEFAULT_CLAUDE_BIN,
) -> ClaudeResult:
    """Invoke ``claude -p`` once. Returns a ClaudeResult; never raises on
    Claude-side errors (those become ``success=False`` with ``error`` set).

    Raises:
        RunnerConfigError: if the invocation arguments are themselves
            unsafe (forbidden tools, denylisted argv tokens, etc.).
        FileNotFoundError: if ``claude_bin`` is missing.
    """
    _validate_tool_list(allowed_tools)

    if not Path(claude_bin).is_file():
        raise FileNotFoundError(f"claude binary not found at {claude_bin}")

    if not cwd.is_dir():
        raise RunnerConfigError(f"cwd not a directory: {cwd}")

    # Cap prompt length. The reader already caps at 16KB; this is a second
    # ceiling for any future code path that might fan in extra context.
    encoded = prompt.encode("utf-8")
    if len(encoded) > MAX_PROMPT_BYTES:
        prompt = encoded[:MAX_PROMPT_BYTES].decode("utf-8", errors="ignore")

    argv = [
        claude_bin,
        "-p",
        "--allowed-tools", ",".join(allowed_tools),
        "--output-format", "json",
        prompt,
    ]
    _assert_safe_argv(argv)

    logger.info(
        "running claude -p (cwd=%s, tools=%s, prompt_bytes=%d)",
        cwd,
        allowed_tools,
        len(prompt.encode("utf-8")),
    )
    start = time.time()
    try:
        proc = subprocess.run(
            argv,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            # Be explicit about stdin: closed. We pass the prompt as argv,
            # not stdin, so claude shouldn't read from stdin. Closing
            # prevents any accidental hang waiting for input.
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        duration = int((time.time() - start) * 1000)
        logger.warning("claude -p timeout after %ds", timeout_seconds)
        return ClaudeResult(
            success=False,
            reply="",
            session_id=None,
            cost_usd=0.0,
            duration_ms=duration,
            error=f"timeout after {timeout_seconds}s",
        )

    duration = int((time.time() - start) * 1000)

    if proc.returncode != 0:
        # Trim stderr to keep error short. We never echo this back to
        # iMessage verbatim; daemon decides what to say.
        stderr_tail = (proc.stderr or "").strip().splitlines()[-1:]
        err = stderr_tail[0] if stderr_tail else f"exit code {proc.returncode}"
        logger.warning("claude -p failed: exit=%d msg=%s", proc.returncode, err)
        return ClaudeResult(
            success=False,
            reply="",
            session_id=None,
            cost_usd=0.0,
            duration_ms=duration,
            error=f"claude exit {proc.returncode}: {err[:200]}",
        )

    try:
        parsed = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        logger.warning("claude JSON parse failed: %s", e)
        return ClaudeResult(
            success=False,
            reply="",
            session_id=None,
            cost_usd=0.0,
            duration_ms=duration,
            error=f"json parse failed: {e}",
        )

    if not isinstance(parsed, dict):
        return ClaudeResult(
            success=False,
            reply="",
            session_id=None,
            cost_usd=0.0,
            duration_ms=duration,
            error="claude JSON output was not a dict",
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
