# Overnight Build Notes — 2026-05-12

All six items completed, each as its own commit, pushed to `origin/main`.
Final state: **274 tests passing, ruff + mypy + bandit all green.**

## Commit sequence (top of `git log`)

| # | Commit  | Item                                                                  |
|---|---------|-----------------------------------------------------------------------|
| 6 | f7bf145 | `feat(commands): /cost-today /whoami /tail-audit read-only convenience` |
| 5 | 3d259ad | `feat(commands): /pause and /resume via iMessage (work even while paused)` |
| 4 | 8c6c754 | `feat(scripts): cimb-status CLI for daemon health at a glance`        |
| 3 | 19b04e0 | `feat(commands): session aliases — /use wesco resolves config-defined shortcuts` |
| 2 | 916e8f1 | `feat(runner): clean up bridge-internal JSONL after each call`        |
| 1 | 5099a65 | `feat(daemon): --skip-selftest for dev iteration (refused in non-interactive mode)` |

Test counts grew 212 → 214 → 221 → 238 → 249 → 259 → 274.

## What landed where

- **Item 1** — `src/daemon.py` argparse + selftest branch; `tests/unit/test_daemon.py` (+2).
- **Item 2** — `src/claude_runner.py` adds `_encode_cwd_for_projects`,
  `_cleanup_sandbox_session`, `DEFAULT_PROJECTS_ROOT`. `run_claude` refactored to
  capture sandbox path inside the with-block and run cleanup in a
  try/finally OUTSIDE the with-block. `selftest_bash_denied` explicit
  cleanup added (no-op in current code path, kept for forward-compat).
  `tests/unit/test_claude_runner.py` (+7).
- **Item 3** — `src/config.py` grows `session_aliases` Dict + `_parse_session_aliases`
  + regex validators. `src/commands.py` `parse_and_dispatch` accepts
  `aliases=`, `_use` checks aliases first w/ case-insensitive match,
  `_aliases` command added. `src/daemon.py` passes `cfg.session_aliases`
  through. `config.example.yaml` documents the block.
  `tests/unit/test_config.py` (+10), `tests/unit/test_commands.py` (+7).
- **Item 4** — `scripts/cimb-status` (new, executable, no .py extension).
  Standalone stdlib-only. `tests/unit/test_cimb_status.py` (+11).
- **Item 5** — `src/commands.py` adds `/pause`, `/resume` handlers;
  `/status` surfaces pause reason. `src/daemon.py` refactor: top-of-loop
  pause short-circuit removed; pause check moved inside `_handle_one`
  to gate ONLY the claude-invocation path. Pause-while-receiving-text
  now sends a courtesy notice. `_read_pause_reason` helper added.
  `tests/unit/test_commands.py` (+7), `tests/unit/test_daemon.py` (+3,
  incl regression guard against re-adding top-of-loop pause).
- **Item 6** — `src/commands.py` adds `/cost-today`, `/whoami`,
  `/tail-audit`. `parse_and_dispatch` grows optional `cfg=` param.
  `src/state.py` adds `tail_audit_rows(n)` helper. `src/daemon.py`
  passes `cfg=` to dispatch.
  `tests/unit/test_commands.py` (+15).

## Design decisions worth flagging for review

- **Item 2 — DEFAULT_PROJECTS_ROOT lookup in `run_claude`:** Resolved
  via module-attribute lookup (not default-arg) so tests can monkeypatch.
  Python evaluates default args at function-def time, which would have
  baked the real `~/.claude/projects` into the test path.
- **Item 3 — aliases case-folded on load:** All comparisons are lower.
  `/use Wesco`, `/use WESCO`, `/use wesco` all hit the same alias. The
  YAML key is allowed to be any case but stored lower; duplicates after
  case-folding are refused at load time.
- **Item 5 — `/resume` also resets `consecutive_failures`:** Without
  this, a circuit-breaker-tripped PAUSE followed by `/resume` would
  immediately re-trip on the next failure because the counter never got
  reset. This isn't in the task spec — judgment call. If you'd rather
  preserve the counter for forensics, just remove the
  `state.reset_claude_failures(...)` line in `_resume`.
- **Item 5 — pause refactor courtesy reply:** Plain-text messages
  received while paused now get a courtesy reply explaining why they
  weren't actioned, with the pause reason. Audit row recorded as
  `direction=out kind=drop detail=paused`. This is more chatty than
  the previous silent-drop behavior — but the previous behavior was
  paired with a fully-idle main loop, so the user got NO feedback at
  all. With the new architecture they'll see at least one notice.
- **Item 6 — `cfg` plumbed as optional:** `parse_and_dispatch(cfg=None)`
  is the default. Commands that need it (`/cost-today`, `/whoami`)
  return graceful fallbacks rather than crashing. This kept existing
  tests passing unchanged. The daemon always passes the real cfg.

## Things I did NOT touch (per task ground rules)

- No new third-party deps. `pyproject.toml` still has just `pyyaml`.
- `HARD_DISALLOWED`, `HARD_FORBIDDEN_TOOLS`, threat model, README design
  philosophy — untouched.
- Session 2 / Session 3 items (context profiles, captures, OCR, backups)
  — untouched.
- Did not run the daemon live.
- Pushed only to `origin/main`; no PRs created.

## Live-test next steps

Pre-flight before you actually run this:
1. Add a `session_aliases:` block to `~/.claude-imessage-bridge/config.yaml`
   if you want to try `/use wesco`. Without it, alias commands behave
   as no-ops (which is tested).
2. Verify `/usr/local/bin/claude` still exists at the pinned path — the
   selftest will fail otherwise (use `--skip-selftest` if you really
   want to bypass; it requires an interactive tty).
3. Try `python3 scripts/cimb-status` while the daemon is running — and
   then again 12 minutes after stopping it (should show STALE banner).

If `/resume` doesn't respond when sent while paused, that means the
pause-refactor regression: the top-of-loop short-circuit got
re-introduced somewhere. Test `test_daemon_main_loop_no_longer_top_level_pause_check`
guards against this.
