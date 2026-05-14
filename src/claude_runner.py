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
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Final, Iterable, Optional

if TYPE_CHECKING:
    # Forward reference only — runtime cycle avoided. ``trust`` imports
    # FROM this module (for HARD_DISALLOWED + BRIDGE_SYSTEM_PROMPT), so
    # this module must NOT import ``trust`` at runtime. Type hints use
    # string forward refs.
    from .trust import TrustPreset

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

# Claude Code records every session as a JSONL transcript at
# ``~/.claude/projects/<encoded-cwd>/<session_id>.jsonl``. The encoded
# directory name is the cwd with ``/`` replaced by ``-`` (and spaces also
# become ``-`` — the encoding is lossy, but we control the cwd so we
# compute the encoding forward, never reverse it).
DEFAULT_PROJECTS_ROOT: Final = Path.home() / ".claude" / "projects"


@dataclass(frozen=True)
class ClaudeResult:
    success: bool
    reply: str
    session_id: Optional[str]
    cost_usd: float
    duration_ms: int
    error: Optional[str] = None
    error_category: Optional[str] = None  # "timeout" | "exec_error" | "json_parse" | "claude_error" | "resume_missing"
    # Permission denials reported by claude in the JSON output. Each entry
    # is the raw dict from `parsed["permission_denials"]` — usually
    # `{"tool_name": "Edit", "tool_input": {"file_path": "..."}}` or
    # similar. Empty list means no denials. The daemon uses this to
    # surface a "Claude wanted to edit X — approve?" prompt and retry
    # with --permission-mode=acceptEdits on confirmation.
    permission_denials: list = field(default_factory=list)


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


def _assert_safe_argv(
    argv: list[str], *, allow_overrides: Optional[frozenset] = None
) -> None:
    """Refuse to exec argv containing any denylisted token (exact or prefix).

    The prefix-form (``--flag=value``) check derives from ARGV_DENYLIST
    rather than a hand-rolled list — keeps exact-form and prefix-form
    coverage consistent if a flag is later added/removed (round-4 solver
    finding T2.R / adversarial #8). Entries in ARGV_DENYLIST that already
    contain ``=`` are exact-match only (e.g., ``--permission-mode=…``).

    ``allow_overrides`` is a frozenset of specific argv tokens that the
    CALLER has explicitly opted into (e.g., ``--permission-mode=acceptEdits``
    for the permission-relay retry path). These bypass the denylist for
    THIS call only. ``--dangerously-skip-permissions``,
    ``--bypass-permissions``, and ``--permission-mode=bypassPermissions``
    are NEVER permitted as overrides — they disable Claude Code's safety
    surface entirely.
    """
    # Bare flag names (no `=value`) that we also want to refuse in the
    # `--flag=value` form. Derived once from ARGV_DENYLIST.
    _bare = {tok for tok in ARGV_DENYLIST if "=" not in tok}
    overrides = allow_overrides or frozenset()
    # Floor: no caller, no override, ever permits these. They disable
    # Claude Code's own permission system entirely (not just one file).
    _PERMANENTLY_REFUSED = frozenset({
        "--dangerously-skip-permissions",
        "--bypass-permissions",
        "--no-permissions",
        "--allow-dangerously-skip-permissions",
        "--permission-mode=bypassPermissions",
    })
    for tok in argv:
        if not isinstance(tok, str):
            raise RunnerConfigError(f"non-string argv element: {tok!r}")
        if tok in _PERMANENTLY_REFUSED:
            raise RunnerConfigError(
                f"refusing argv with permanently-denied token: {tok!r}"
            )
        if tok in ARGV_DENYLIST and tok not in overrides:
            raise RunnerConfigError(f"refusing argv with denylisted token: {tok!r}")
        for bad in _bare:
            if bad in _PERMANENTLY_REFUSED and tok.startswith(bad + "="):
                raise RunnerConfigError(
                    f"refusing argv with permanently-denied flag form: {tok!r}"
                )
            if tok.startswith(bad + "=") and tok not in overrides:
                raise RunnerConfigError(f"refusing argv with denylisted flag form: {tok!r}")


def _scrubbed_env(extra_passthrough: Iterable[str] = ()) -> dict:
    """Build a minimal environment for the child process.

    ``extra_passthrough`` is the trust preset's extra environment-variable
    allowlist — additive on top of ``_ENV_ALLOWLIST``. In ``chat_only``
    mode this is empty (the strictest scrub). In ``coding`` and ``full``
    modes it widens to include things like ``GH_TOKEN`` / ``GITHUB_TOKEN``
    for git operations and a small set of common MCP-server credential
    env-var names. We deliberately enumerate (not wildcard-pattern-match)
    so a new env var Sam acquires doesn't silently leak into the bridge
    until he updates the preset.
    """
    parent = os.environ
    keys = set(_ENV_ALLOWLIST) | set(extra_passthrough)
    env = {k: parent[k] for k in keys if k in parent}
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


def _encode_cwd_for_projects(sandbox_cwd: Path) -> str:
    """Compute the ``~/.claude/projects/<dir>`` name Claude Code uses for
    a given cwd. Matches Claude's encoding: ``/`` → ``-`` (and spaces also
    become ``-`` — we don't reverse, we forward-compute).
    """
    s = str(sandbox_cwd)
    return s.replace("/", "-").replace(" ", "-")


def _cleanup_sandbox_session(
    sandbox_cwd: Path,
    session_id: Optional[str],
    *,
    projects_root: Path = DEFAULT_PROJECTS_ROOT,
) -> None:
    """Delete the bridge-internal JSONL Claude wrote for this call.

    Each ``claude -p`` call appends a JSONL transcript to
    ``<projects_root>/<encoded-cwd>/<session_id>.jsonl``. For hermetic
    per-call sandboxes (cimb-call-*) and selftests (cimb-selftest-*),
    that transcript is plumbing — never user-meaningful — and the
    bridge's session-discovery filter already excludes it from
    /sessions. But leaving the file on disk grows ``~/.claude/projects``
    by one tiny JSONL per inbound message; a long-running daemon
    accumulates thousands.

    This helper is best-effort. All ``OSError``s are swallowed; cleanup
    is not load-bearing. We also try to rmdir the parent dir afterwards
    in case it's now empty (Claude doesn't reuse it after the cwd is
    gone).

    Refuses to operate on a session id that contains path separators or
    parent-dir tokens — a malformed id from claude could otherwise
    escape the projects tree. The same defense applies to the encoded
    dir name.
    """
    if not session_id:
        return
    # Defense against a malformed session id (path traversal). Real
    # Claude session ids are UUIDs; we accept hex + dash only.
    if "/" in session_id or ".." in session_id or "\\" in session_id:
        return
    encoded = _encode_cwd_for_projects(sandbox_cwd)
    if "/" in encoded or ".." in encoded:
        return
    target = projects_root / encoded / f"{session_id}.jsonl"
    try:
        target.unlink()
    except OSError:
        pass
    # Best-effort: remove parent if now empty. Don't recurse — only the
    # immediate parent.
    try:
        target.parent.rmdir()
    except OSError:
        pass


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


def _resolve_inherit_mcp_path(configured: Optional[str]) -> Optional[str]:
    """Resolve the user's MCP config path for ``inherit`` mcp_config_mode.

    Returns the absolute path string. ``None`` means "fall back to empty"
    — caller should treat the same as ``empty`` mode and warn.

    Refuses symlinks (S9 file-swap defense). Refuses files outside the
    user's home dir to avoid an arbitrary-path read at config load.
    """
    if not configured:
        configured = str(Path.home() / ".claude" / ".mcp.json")
    p = Path(configured).expanduser()
    if not p.is_file():
        logger.warning(
            "MCP config inherit path %s does not exist; falling back to empty",
            p,
        )
        return None
    if p.is_symlink():
        logger.warning(
            "MCP config inherit path %s is a symlink; refusing (S9). "
            "Falling back to empty.",
            p,
        )
        return None
    try:
        home = Path.home().resolve()
        if home not in p.resolve().parents and p.resolve() != home:
            logger.warning(
                "MCP config inherit path %s is outside home dir; falling back to empty",
                p,
            )
            return None
    except OSError:
        return None
    return str(p)


def run_claude(
    prompt: str,
    *,
    trust_preset: "TrustPreset",
    project_directory: Path,
    allowed_tools_addons: Optional[list[str]] = None,
    timeout_seconds: int = 90,
    claude_bin: str = DEFAULT_CLAUDE_BIN,
    resume_session_id: Optional[str] = None,
    extra_context: str = "",
    permission_relay_retry: bool = False,
) -> ClaudeResult:
    """Invoke ``claude -p`` once with a TrustPreset-driven invocation.

    The trust preset gates everything material about the invocation:
    - cwd (hermetic tempdir vs. project_directory)
    - MCP config (empty vs. inherit user's real config)
    - tool deny list
    - max-turns cap
    - extra system prompt (chat_only's anti-fabrication; None for others)
    - extra env passthrough (for MCP credentials in coding/full modes)

    ``allowed_tools_addons`` are user opt-ins layered on top of the preset
    — entries in this list are removed from the preset's ``disallowed_tools``
    set for this call. Entries are validated against the addon floor
    (HARD_FORBIDDEN_TOOLS + mcp__* prefix) regardless of preset, since
    those tools can transitively re-enable denied capabilities.

    ``extra_context`` is the memory backend's contribution. Joined with
    the preset's ``extra_system_prompt`` (if any) and passed via
    ``--append-system-prompt``. If both are empty, the flag is omitted
    entirely.

    JSONL cleanup: only fires when ``trust_preset.cwd_mode == 'hermetic_tempdir'``.
    In project_directory mode, the JSONL goes under the user's real
    project's ~/.claude/projects/ directory — a legitimate Sam session
    that should be discoverable via /sessions, NOT deleted.

    Raises:
        RunnerConfigError: invocation parameters themselves are unsafe.
        FileNotFoundError: claude_bin missing.
    """
    addons = list(allowed_tools_addons or [])
    _validate_tool_list(addons)

    if not Path(claude_bin).is_file():
        raise FileNotFoundError(f"claude binary not found at {claude_bin}")

    # Cap prompt length.
    encoded = prompt.encode("utf-8")
    if len(encoded) > MAX_PROMPT_BYTES:
        prompt = encoded[:MAX_PROMPT_BYTES].decode("utf-8", errors="ignore")

    # Effective deny list: preset's deny - user's addons. ``--disallowed-tools``
    # is the real deny mechanism (round-3 finding); ``--allowed-tools`` is
    # additive and only carries the addons.
    effective_disallow = trust_preset.disallowed_tools - set(addons)
    disallow_value = ",".join(sorted(effective_disallow))
    allow_value = ",".join(addons) if addons else ""

    # System prompt: preset's extra + memory's extra_context. None when both
    # are empty — let Claude Code's own defaults handle the system prompt.
    system_prompt_parts = []
    if trust_preset.extra_system_prompt:
        system_prompt_parts.append(trust_preset.extra_system_prompt)
    if extra_context:
        system_prompt_parts.append(extra_context)
    combined_system_prompt = "\n\n".join(system_prompt_parts) if system_prompt_parts else None

    start = time.time()

    # Side dir for the empty MCP config (when applicable) and any other
    # per-call scratch. Always a fresh tempdir, regardless of cwd_mode —
    # we don't write the empty MCP config into the user's project_directory.
    sandbox_for_cleanup: Optional[Path] = None

    with tempfile.TemporaryDirectory(prefix="cimb-call-") as side_dir_str:
        side_dir = Path(side_dir_str)

        # Resolve MCP config path.
        if trust_preset.mcp_config_mode == "empty":
            mcp_path = side_dir / "empty-mcp.json"
            try:
                _write_empty_mcp_safe(mcp_path)
            except OSError as e:
                return ClaudeResult(
                    success=False, reply="", session_id=None, cost_usd=0.0,
                    duration_ms=int((time.time() - start) * 1000),
                    error=f"could not write empty-mcp.json: {e}",
                    error_category="exec_error",
                )
            mcp_path_str = str(mcp_path)
            strict_mcp = True
        elif trust_preset.mcp_config_mode == "inherit":
            resolved = _resolve_inherit_mcp_path(trust_preset.mcp_config_path)
            if resolved is None:
                # Fallback: write an empty one. Already-logged warning.
                mcp_path = side_dir / "empty-mcp.json"
                try:
                    _write_empty_mcp_safe(mcp_path)
                except OSError as e:
                    return ClaudeResult(
                        success=False, reply="", session_id=None, cost_usd=0.0,
                        duration_ms=int((time.time() - start) * 1000),
                        error=f"could not write fallback empty-mcp.json: {e}",
                        error_category="exec_error",
                    )
                mcp_path_str = str(mcp_path)
                strict_mcp = True
            else:
                mcp_path_str = resolved
                # In inherit mode we DON'T pass --strict-mcp-config because
                # the user's real config is what we want claude to load.
                strict_mcp = False
        else:
            raise RunnerConfigError(
                f"unknown mcp_config_mode {trust_preset.mcp_config_mode!r}"
            )

        # Determine cwd. Hermetic mode uses the side_dir; project mode
        # uses the user's configured project_directory (where CLAUDE.md
        # lives and where claude_md memory backend operates).
        if trust_preset.cwd_mode == "hermetic_tempdir":
            cwd_path = side_dir
            sandbox_for_cleanup = side_dir
        elif trust_preset.cwd_mode == "project_directory":
            cwd_path = project_directory
            # NOT a bridge-internal sandbox — Claude's JSONL here is a
            # legitimate user session and should be preserved.
            sandbox_for_cleanup = None
        else:
            raise RunnerConfigError(
                f"unknown cwd_mode {trust_preset.cwd_mode!r}"
            )

        # Build argv.
        argv = [
            claude_bin,
            "-p",
            "--output-format", "json",
            "--mcp-config", mcp_path_str,
            "--disallowed-tools", disallow_value,
            "--allowed-tools", allow_value,
            "--max-turns", str(int(trust_preset.max_turns)),
        ]
        if strict_mcp:
            argv.append("--strict-mcp-config")
        if combined_system_prompt is not None:
            argv += ["--append-system-prompt", combined_system_prompt]
        if resume_session_id:
            # Resume the named session's transcript context. Tool authority
            # is STILL gated by --disallowed-tools above; the resumed
            # session's prior tool uses don't grant new authority.
            argv += ["--resume", resume_session_id]
        # Permission-relay retry path: the user has explicitly approved a
        # blocked edit via iMessage confirmation. Pass
        # ``--permission-mode=acceptEdits`` so claude no longer prompts
        # for edit permission on this single retry call. Scope is files
        # only — Bash/WebFetch/etc. still subject to default-mode
        # rejection in -p mode. ``_assert_safe_argv`` is told to allow
        # this specific token via ``allow_overrides``; ``bypassPermissions``
        # remains permanently refused regardless of opt-in.
        argv_overrides: Optional[frozenset] = None
        if permission_relay_retry:
            argv.append("--permission-mode=acceptEdits")
            argv_overrides = frozenset({"--permission-mode=acceptEdits"})
        argv += [
            # ``--`` is REQUIRED: prevents a prompt that begins with ``--``
            # from being reparsed as additional flags.
            "--",
            prompt,
        ]
        _assert_safe_argv(argv, allow_overrides=argv_overrides)

        logger.info(
            "claude -p (preset=%s, cwd=%s, allow=%r, disallow_count=%d, "
            "max_turns=%d, prompt_bytes=%d, sys_prompt_bytes=%d)",
            trust_preset.name,
            cwd_path,
            allow_value,
            len(effective_disallow),
            trust_preset.max_turns,
            len(prompt.encode("utf-8")),
            len((combined_system_prompt or "").encode("utf-8")),
        )

        try:
            proc = subprocess.Popen(
                argv,
                cwd=str(cwd_path),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=_scrubbed_env(extra_passthrough=trust_preset.extra_env_passthrough),
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

    # ``with`` context exited: side_dir is gone (and with it the empty MCP
    # config, if any).
    duration = int((time.time() - start) * 1000)
    session_id_for_cleanup: Optional[str] = None

    try:
        if proc.returncode != 0:
            logger.warning("claude -p exit=%d stderr_tail=%r",
                           proc.returncode, (stderr or "")[-500:])
            # Detect the specific "stale session" error so the daemon can
            # auto-recover (clear the per-handle pointer + retry fresh).
            # Claude's exit-1 message format is stable enough to match
            # by substring; if Anthropic changes the wording, the daemon
            # falls back to the generic "exec_error" path and the user
            # gets a one-message stutter before recovering on the next.
            stderr_text = ""
            if stderr:
                try:
                    stderr_text = (
                        stderr.decode("utf-8", errors="replace")
                        if isinstance(stderr, bytes) else stderr
                    )
                except Exception:
                    stderr_text = ""
            if resume_session_id and "No conversation found" in stderr_text:
                return ClaudeResult(
                    success=False, reply="", session_id=None, cost_usd=0.0,
                    duration_ms=duration,
                    error=f"resume session {resume_session_id[:8]} not on disk",
                    error_category="resume_missing",
                )
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

        sid_raw = parsed.get("session_id")
        if isinstance(sid_raw, str):
            session_id_for_cleanup = sid_raw

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

        # Extract permission_denials so the daemon can surface them for
        # interactive approval. Claude reports this even on success when
        # the model attempted (and was denied) tool calls — the model
        # continues anyway and summarizes the partial outcome.
        denials_raw = parsed.get("permission_denials")
        permission_denials = denials_raw if isinstance(denials_raw, list) else []

        return ClaudeResult(
            success=True,
            reply=reply,
            session_id=session_id_for_cleanup,
            cost_usd=cost_usd,
            duration_ms=duration,
            permission_denials=permission_denials,
        )
    finally:
        # Cleanup only fires when this was a hermetic-tempdir call.
        # In project_directory mode, the JSONL is a legitimate user
        # session and must be preserved (it's how cross-device session
        # continuation works in trust mode).
        if sandbox_for_cleanup is not None:
            _cleanup_sandbox_session(
                sandbox_for_cleanup, session_id_for_cleanup,
                projects_root=DEFAULT_PROJECTS_ROOT,
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
        # Lazy import to avoid the trust→claude_runner circular at module
        # load time. By the time this function runs, both modules are
        # fully loaded.
        from .trust import PRESET_CHAT_ONLY
        result = run_claude(
            test_prompt,
            trust_preset=PRESET_CHAT_ONLY,
            project_directory=st_dir,  # ignored in hermetic mode
            allowed_tools_addons=[],
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

    # The selftest's claude call wrote a JSONL transcript under
    # ~/.claude/projects/<encoded-cimb-call-dir>/<sid>.jsonl — and
    # ``run_claude`` already cleaned that up internally. Belt-and-suspenders:
    # if a future refactor moves the cleanup away from ``run_claude``,
    # call it explicitly here too so selftest sessions don't accumulate.
    if result.session_id and st_dir is not None:
        # The selftest's outer tempdir (cimb-selftest-*) is different from
        # the per-call inner sandbox (cimb-call-*) that run_claude uses,
        # so this cleanup is a no-op in the current code path. Documented
        # for forward-compatibility.
        _cleanup_sandbox_session(st_dir, result.session_id)


# --- Trust-mode-agnostic selftests ----------------------------------------
#
# These run on every daemon startup regardless of trust mode (selftest_
# bash_denied above is chat_only-specific because in coding/full modes
# Bash is legitimately enabled). They verify defenses that apply across
# all trust modes — the allowlist gate and the argv-flag denylist.


def selftest_allowlist_enforced(
    *,
    allowlist: list,
    allow_group_chat_guids: list,
) -> None:
    """Verify the allowlist filter rejects a non-allowlisted handle.

    This is the load-bearing defense in trust modes that expose more
    capability (coding/full). If the allowlist isn't enforcing, an
    attacker who can put any handle into chat.db drives full Claude Code.

    We synthesize a ``Message`` with a sender NOT in the allowlist and
    pipe it through the same ``_decide`` logic the daemon uses. Asserts
    ``accept == False``. Doesn't spawn claude — costs nothing.
    """
    # Lazy imports — these modules import claude_runner transitively.
    from . import imessage_reader
    from .daemon import _decide
    from types import SimpleNamespace

    # Build a fake sender that's structurally valid but not allowlisted.
    # Use a phone outside the allowlist (or a fixed sentinel if the
    # allowlist somehow covers all 10-digit numbers).
    fake_sender = "+19998887766"
    if fake_sender in allowlist:
        # Improbable but defensive — pick a different sentinel.
        fake_sender = "+15555555555"
        if fake_sender in allowlist:
            raise SelfTestFailed(
                "Cannot synthesize a non-allowlisted handle for selftest; "
                "allowlist is unexpectedly broad"
            )

    msg = imessage_reader.Message(
        rowid=0,
        chat_guid="selftest-chat",
        is_group=False,
        sender_handle=fake_sender,
        timestamp_iso="2026-01-01T00:00:00Z",
        body="selftest probe",
        body_truncated=False,
    )
    cfg = SimpleNamespace(
        allowlist=list(allowlist),
        allowlist_set=set(allowlist),
        allow_group_chat_guids=list(allow_group_chat_guids),
    )
    accept, reason = _decide(msg, cfg)
    if accept:
        raise SelfTestFailed(
            f"selftest_allowlist_enforced: synthetic non-allowlisted "
            f"handle {fake_sender!r} was ACCEPTED (reason: {reason!r}). "
            "The allowlist gate is not working. Refusing to start."
        )
    logger.info("selftest: allowlist enforced (synthetic %s rejected as %s)",
                fake_sender, reason)


def selftest_argv_invariants() -> None:
    """Verify ``_assert_safe_argv`` rejects every dangerous flag.

    The argv denylist is what stops a future refactor or a hijacked
    argv builder from passing ``--dangerously-skip-permissions``. The
    test enumerates every entry in ARGV_DENYLIST and asserts each one
    triggers a refusal.
    """
    for bad_flag in ARGV_DENYLIST:
        argv = ["claude-binary-stub", "-p", bad_flag, "--", "harmless"]
        try:
            _assert_safe_argv(argv)
        except RunnerConfigError:
            continue
        raise SelfTestFailed(
            f"selftest_argv_invariants: _assert_safe_argv accepted argv "
            f"containing {bad_flag!r}; argv-injection defense is not "
            "holding. Refusing to start."
        )

    # Also verify the prefix-form (--flag=value) path. Pick one bare
    # flag and confirm its `=value` form is rejected.
    bare_flags = [t for t in ARGV_DENYLIST if "=" not in t]
    if bare_flags:
        attack = bare_flags[0] + "=arbitrary"
        argv = ["claude-binary-stub", "-p", attack, "--", "harmless"]
        try:
            _assert_safe_argv(argv)
        except RunnerConfigError:
            pass
        else:
            raise SelfTestFailed(
                f"selftest_argv_invariants: prefix-form {attack!r} was "
                "accepted; the =value injection vector is open. "
                "Refusing to start."
            )
    logger.info("selftest: argv invariants hold (%d dangerous flags rejected)",
                len(ARGV_DENYLIST))
