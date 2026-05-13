"""Invoke ``claude -p`` for a single inbound message and parse the result.

Each inbound message spawns a fresh ``claude -p`` call into a **hermetic
per-call sandbox** (a `tempfile.TemporaryDirectory` that vanishes when
the call returns):

- cwd is a dedicated empty directory (NOT the user's project_directory) so
  the user's global CLAUDE.md, .mcp.json, .claude/ skills, and settings.json
  do not load into the model's context.
- ``--strict-mcp-config`` + ``--mcp-config <empty>.json`` prevents MCP
  server discovery and startup (no Gmail/Slack/Drive process inheritance).
- ``--append-system-prompt`` injects a minimal "you are a text-only chat
  bot, no tools, no memory" role description.
- **``--disallowed-tools <csv>`` is the real tool-deny mechanism.** This is
  load-bearing and was the critical finding from round-3 adversarial
  review. ``--allowed-tools`` is *additive* — it can only ADD patterns to
  the allow-set, it cannot remove anything. ``--tools ""`` is a documented
  no-op (verified empirically; the CLI accepts it but doesn't deny tools).
  Bash, Read, Write, WebFetch, Skill, etc. are available by DEFAULT in
  ``claude -p`` unless explicitly named in ``--disallowed-tools``. See
  ``HARD_DISALLOWED`` below for the bridge's active deny set. Anything in
  ``allowed_tools`` (user opt-in) is removed from that set per-call; it is
  always filtered against ``HARD_FORBIDDEN_TOOLS`` at config-load time.
- **Empirical startup selftest** (``selftest_bash_denied`` at the bottom of
  this module) spawns one ``claude -p`` call and asserts Bash cannot write
  a canary file. The daemon refuses to start if the canary appears. This
  is the only way to verify the tool-deny boundary holds across Claude
  Code releases — the documented flag semantics drifted at least once
  already (the round-3 finding above).
- ``--max-turns N`` (default 1) puts a hard ceiling on per-call spend
  before claude even starts spending.
- ``--`` separator placed immediately before the prompt so a malicious
  message body starting with ``--`` cannot be reparsed as additional CLI
  flags by Claude's argument parser.
- Child process is spawned with ``start_new_session=True`` so on timeout
  we can kill the whole process group, not just the immediate ``claude``
  process (Node MCP children otherwise survive as orphans).
- Child environment is scrubbed: only PATH, HOME, USER, LANG, LC_ALL,
  ANTHROPIC_API_KEY, CLAUDE_CODE_OAUTH_TOKEN. No general env inheritance
  so a prompt that asks for ``env`` can only see this whitelist; TMPDIR
  specifically is NOT inherited (attacker-controlled TMPDIR could be a
  symlink ladder).

Result is a structured ``ClaudeResult``. We never raise on Claude-side
errors; those become ``success=False`` with ``error_category`` set.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Optional

logger = logging.getLogger(__name__)

# Default location for the Claude Code CLI. Preflight verifies it exists.
DEFAULT_CLAUDE_BIN: Final = "/usr/local/bin/claude"

# Tools the bridge will NEVER allow in ``allowed_tools``. If a user tries to
# add any of these to config.yaml, the daemon refuses to start. This is the
# config-layer floor — see HARD_DISALLOWED below for what we actually pass
# to ``--disallowed-tools``.
HARD_FORBIDDEN_TOOLS: Final = frozenset({
    "Bash",
    "Write",
    "Edit",
    "MultiEdit",
    "NotebookEdit",
    "WebFetch",
    "WebSearch",
    "Skill",
    "Agent",
    "ToolSearch",
    "CronCreate",
    "CronDelete",
    "CronList",
    "CronToggle",
    "ScheduleWakeup",
    "RemoteTrigger",
    "PushNotification",
    "EnterWorktree",
    "ExitWorktree",
    # MCP-namespaced tools blocked via prefix check, not exact match.
})

# Tools the bridge ACTIVELY tells claude to disallow on every invocation, via
# ``--disallowed-tools``. ``--allowed-tools`` is additive (doesn't deny
# anything by itself), so this list is the real security boundary. Bash and
# friends are still available in ``claude -p`` by default unless explicitly
# denied here.
#
# Anything in allowed_tools is removed from this set at invocation time, so
# a user who opts in to (e.g.) ``Read`` gets Read while everything else
# stays denied.
HARD_DISALLOWED: Final = frozenset({
    # Filesystem write / exec
    "Bash", "Write", "Edit", "MultiEdit", "NotebookEdit",
    # Filesystem read (cwd-scoped but still surfaces filenames/contents)
    "Read", "Grep", "Glob", "LS", "NotebookRead",
    # Network egress
    "WebFetch", "WebSearch",
    # Tool/skill/agent loading — these can re-enable denied tools transitively
    "Skill", "Agent", "ToolSearch",
    # Scheduling — could persist arbitrary execution
    "CronCreate", "CronDelete", "CronList", "CronToggle", "ScheduleWakeup",
    # Communication / out-of-band
    "AskUserQuestion", "RemoteTrigger", "PushNotification",
    # Task / state / plan modes
    "TodoWrite", "TaskStop", "TaskOutput",
    "EnterWorktree", "ExitWorktree", "EnterPlanMode", "ExitPlanMode",
    # MCP introspection (the empty mcp config should make these inert, but
    # we deny anyway — defense in depth)
    "ListMcpResourcesTool", "ReadMcpResourceTool",
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

# Minimal system prompt injected via --append-system-prompt. Three jobs:
# 1. Set a tight role so the model doesn't reference Gmail/Slack/Drive/etc.
# 2. Tell the model explicitly that it has NO tools and shouldn't try to
#    fabricate tool calls (observed behavior: in fully-disallowed mode the
#    model sometimes emits fake ``<tool_call>`` blocks with hallucinated
#    output rather than admitting it has no tools).
# 3. Cap reply length close to the iMessage transport cap.
BRIDGE_SYSTEM_PROMPT: Final = (
    "You are a text-only chat assistant reached over iMessage. "
    "You have NO tools — no Bash, no Read, no Write, no WebFetch, "
    "no Skill, no Agent, nothing. Do NOT fabricate tool calls. Do NOT "
    "emit <tool_call> tags. Do NOT pretend to read files or run commands. "
    "If a request requires a tool, refuse plainly: say you have no tools "
    "available in this environment. "
    "You also have no access to email, Slack, Drive, calendars, contacts, "
    "MCP servers, or any user-specific memory. Do not reference customers, "
    "deals, projects, or personal context — that information is not "
    "available here. Keep replies under 1500 characters."
)

# Environment variables the child inherits. Everything else is dropped.
#
# Notably absent:
# - TMPDIR: an attacker-controlled TMPDIR (set in launchd plist, inherited
#   from an unrelated shell session) can become a symlink ladder or a
#   sticky-bit-weak directory claude writes session JSON / prompt caches
#   into. Let claude default to /tmp via libc.
# - ANTHROPIC_AUTH_TOKEN: redundant with CLAUDE_CODE_OAUTH_TOKEN on modern
#   installs, and having both reachable risks claude picking the wrong
#   account when both are set. We only pass through one OAuth path.
_ENV_ALLOWLIST: Final = frozenset({
    "PATH",
    "HOME",
    "USER",
    "LANG",
    "LC_ALL",
    "ANTHROPIC_API_KEY",
    "CLAUDE_CODE_OAUTH_TOKEN",
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
    """Refuse to exec argv containing any denylisted token (exact or prefix).

    The prefix-form (``--flag=value``) check derives from ARGV_DENYLIST
    rather than a hand-rolled list — keeps exact-form and prefix-form
    coverage consistent if a flag is later added/removed (round-4 solver
    finding T2.R / adversarial #8). Entries in ARGV_DENYLIST that already
    contain ``=`` are exact-match only (e.g., ``--permission-mode=…``).
    """
    # Bare flag names (no `=value`) that we also want to refuse in the
    # `--flag=value` form. Derived once from ARGV_DENYLIST.
    _bare = {tok for tok in ARGV_DENYLIST if "=" not in tok}
    for tok in argv:
        if not isinstance(tok, str):
            raise RunnerConfigError(f"non-string argv element: {tok!r}")
        if tok in ARGV_DENYLIST:
            raise RunnerConfigError(f"refusing argv with denylisted token: {tok!r}")
        for bad in _bare:
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


def _kill_process_group(proc: subprocess.Popen) -> None:
    """Best-effort SIGTERM-then-SIGKILL of the child's process group.

    Avoids PID-reuse races by:
      - re-checking proc.poll() before each kill (skip if already exited)
      - resolving the pgid via ``os.getpgid(proc.pid)`` rather than using
        ``proc.pid`` directly (which only happens to equal the pgid because
        we set ``start_new_session=True``).

    All ``OSError``s (ProcessLookupError when the group is already gone,
    PermissionError if somehow targeting a foreign group) are swallowed —
    cleanup is best-effort.
    """
    if proc.poll() is not None:
        return  # already exited; nothing to kill
    try:
        pgid = os.getpgid(proc.pid)
    except (ProcessLookupError, PermissionError):
        return
    try:
        os.killpg(pgid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return
    try:
        proc.wait(timeout=3)
        return
    except subprocess.TimeoutExpired:
        pass
    if proc.poll() is not None:
        return
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    # Final reckoning: if the process is STILL alive after SIGKILL, log
    # loudly. We can't recover, but the operator needs a forensic trail
    # of "the kill didn't actually kill anything" instead of silently
    # returning success-shape from the timeout path (round-4 finding).
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        logger.critical(
            "claude process group pgid=%s still alive after SIGKILL; "
            "manual intervention may be required",
            pgid,
        )


def _write_empty_mcp_safe(path: Path) -> None:
    """Write the empty-mcp.json content to ``path`` without following symlinks.

    Defends against an attacker pre-creating ``path`` as a symlink to a
    sensitive file (e.g., ``~/.ssh/authorized_keys``). ``Path.write_text``
    follows symlinks and would clobber the target; ``os.open`` with
    ``O_NOFOLLOW | O_CREAT | O_EXCL`` refuses to open through a symlink and
    fails if the path already exists.
    """
    fd = os.open(
        str(path),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        os.write(fd, b'{"mcpServers":{}}\n')
    finally:
        os.close(fd)


def run_claude(
    prompt: str,
    *,
    allowed_tools: list[str],
    max_turns: int = 1,
    timeout_seconds: int = 90,
    claude_bin: str = DEFAULT_CLAUDE_BIN,
    resume_session_id: Optional[str] = None,
) -> ClaudeResult:
    """Invoke ``claude -p`` once in a per-call hermetic sandbox.

    Each invocation creates a fresh ``tempfile.TemporaryDirectory`` (mode
    0o700) and writes a fresh ``empty-mcp.json`` into it before spawning
    claude. After the call returns (or times out), the directory and any
    files in it are removed. This kills two attack surfaces in one move:

    1. **Symlink-write on empty-mcp.json** — the path doesn't pre-exist;
       there's nothing for an attacker to pre-create as a symlink. ``O_EXCL``
       + ``O_NOFOLLOW`` on the write enforces this.
    2. **Sandbox-dir tamper between invocations** — a persistent sandbox
       directory could have ``CLAUDE.md`` or ``.mcp.json`` dropped into it
       between calls. A per-call dir means there's no window.

    Cost: one mkdir + one write + one rmtree per call (~ms).

    Raises:
        RunnerConfigError: invocation parameters themselves are unsafe.
        FileNotFoundError: claude_bin missing.
    """
    _validate_tool_list(allowed_tools)

    if not Path(claude_bin).is_file():
        raise FileNotFoundError(f"claude binary not found at {claude_bin}")

    # Cap prompt length.
    encoded = prompt.encode("utf-8")
    if len(encoded) > MAX_PROMPT_BYTES:
        prompt = encoded[:MAX_PROMPT_BYTES].decode("utf-8", errors="ignore")

    # Build the actual deny list passed to claude. HARD_DISALLOWED minus
    # anything the user explicitly opted into. ``--disallowed-tools`` is the
    # REAL deny mechanism in ``claude -p`` — ``--allowed-tools`` only ADDS
    # patterns to the allow-set, it doesn't remove anything. Bash and
    # friends are available by default unless explicitly denied.
    effective_disallow = HARD_DISALLOWED - set(allowed_tools)
    disallow_value = ",".join(sorted(effective_disallow))

    # ``--allowed-tools`` carries the user's opt-in additions. If empty,
    # we still pass it as "" so Claude doesn't widen the allow-set with its
    # defaults. NB: per testing, --allowed-tools "" alone does NOT deny
    # tools — that's why HARD_DISALLOWED above does the actual work.
    allow_value = ",".join(allowed_tools) if allowed_tools else ""

    start = time.time()
    # Per-call hermetic sandbox: fresh tempdir + fresh empty-mcp.json. Both
    # vanish when the context exits. mode=0o700 is the default for
    # TemporaryDirectory on POSIX.
    with tempfile.TemporaryDirectory(prefix="cimb-call-") as sandbox_str:
        sandbox = Path(sandbox_str)
        mcp_path = sandbox / "empty-mcp.json"
        try:
            _write_empty_mcp_safe(mcp_path)
        except OSError as e:
            return ClaudeResult(
                success=False, reply="", session_id=None, cost_usd=0.0,
                duration_ms=int((time.time() - start) * 1000),
                error=f"could not write empty-mcp.json: {e}",
                error_category="exec_error",
            )

        argv = [
            claude_bin,
            "-p",
            "--output-format", "json",
            "--strict-mcp-config",
            "--mcp-config", str(mcp_path),
            "--disallowed-tools", disallow_value,
            "--allowed-tools", allow_value,
            "--max-turns", str(int(max_turns)),
            "--append-system-prompt", BRIDGE_SYSTEM_PROMPT,
        ]
        if resume_session_id:
            # Resume the named session's transcript context. Tool authority
            # is STILL gated by --disallowed-tools above; the resumed
            # session's prior tool uses don't grant new authority.
            argv += ["--resume", resume_session_id]
        argv += [
            # ``--`` is REQUIRED: prevents a prompt that begins with ``--``
            # from being reparsed as additional flags. Position is right
            # before the positional prompt.
            "--",
            prompt,
        ]
        _assert_safe_argv(argv)

        logger.info(
            "claude -p (sandbox=%s, allow=%r, disallow_count=%d, "
            "max_turns=%d, prompt_bytes=%d)",
            sandbox,
            allow_value,
            len(effective_disallow),
            max_turns,
            len(prompt.encode("utf-8")),
        )

        # Spawn with new session so we can kill the whole process group on
        # timeout — otherwise Node MCP children survive as orphans.
        try:
            proc = subprocess.Popen(
                argv,
                cwd=str(sandbox),
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
            # Check proc.poll() each step to avoid PID-reuse races where
            # the kernel reassigns proc.pid to an unrelated process.
            _kill_process_group(proc)
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


# --- Startup self-test ----------------------------------------------------

class SelfTestFailed(RuntimeError):
    """Raised when the startup self-test cannot prove Bash is denied."""


def selftest_bash_denied(
    *,
    claude_bin: str = DEFAULT_CLAUDE_BIN,
    timeout_seconds: int = 60,
) -> None:
    """Ask claude to invoke Bash; refuse to proceed unless it was denied.

    Empirical proof that this build's tool-disallow incantation is still
    correct. Anthropic could in principle change CLI semantics or add new
    tools in a future release; this test catches that the next time the
    daemon boots.

    The canary path is in a dedicated tempdir (outside of
    ``run_claude``'s own per-call sandbox so we can inspect it after the
    call returns and the inner sandbox is gone). The path is constructed
    via mkdtemp + a fixed filename inside, so it's unguessable by a
    malicious model attempting to pre-create the canary in a different
    location.
    """
    with tempfile.TemporaryDirectory(prefix="cimb-selftest-") as st_dir_str:
        st_dir = Path(st_dir_str)
        canary = st_dir / "_selftest_canary.txt"
        if canary.exists():
            # Fresh TemporaryDirectory shouldn't contain anything; if it
            # does, something is very wrong with our sandbox assumption.
            raise SelfTestFailed(
                f"selftest tempdir at {st_dir} already contains the "
                "canary file before the test started — refusing to run"
            )

        test_prompt = (
            f"Use the Bash tool right now to run: "
            f"echo SELFTEST_FAIL > {canary}. "
            f"Then read it back. Report exactly what happened."
        )
        result = run_claude(
            test_prompt,
            allowed_tools=[],
            max_turns=4,
            timeout_seconds=timeout_seconds,
            claude_bin=claude_bin,
        )

        if canary.exists():
            raise SelfTestFailed(
                "Bash WAS executed via claude despite --disallowed-tools — "
                "the Phase B security boundary is NOT holding. Refusing to "
                "start the daemon. Tool-deny config may have drifted in a "
                "Claude Code version bump. Reply text was: "
                f"{result.reply[:200]!r}"
            )

        if not result.success:
            raise SelfTestFailed(
                f"Self-test couldn't complete: {result.error}. "
                "Refusing to start; cannot verify Bash is denied."
            )

        logger.info(
            "selftest: bash denied (canary absent, cost=$%.4f, duration=%dms)",
            result.cost_usd, result.duration_ms,
        )
