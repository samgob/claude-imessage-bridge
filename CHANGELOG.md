# Changelog

All notable changes to claude-imessage-bridge. Versions follow [Semantic Versioning](https://semver.org/).

This project is **pre-1.0**. Public APIs (config schema, state.db schema, audit-log shape) may change between minor versions. Breaking changes are called out explicitly.

## [0.1.0-pre.1] — 2026-05-24 (Phase E: images, audio, edit UX)

### Pre-publication hardening pass (2026-05-24)

Closures from the paired security + polish reviews performed before
flipping the repo public:

- **Whisper sidecar no longer leaks into iMessage attachments dir.**
  whisper-cli's `-otxt` flag writes `<input>.txt` adjacent to its
  input. Previously, when an attachment was already WAV, the bridge
  passed the chat.db path directly — whisper then wrote a sidecar
  inside `~/Library/Messages/Attachments/`, which iCloud Messages
  may sync. Fixed: all audio (including native WAV) is now staged
  into a per-call tempdir before whisper sees it.
- **`resume_session_id` UUID-shape validated at the argv-build path.**
  The `_assert_safe_argv` denylist matches by flag string, not by
  argv position. A malformed session_id of `--some-flag` would not
  have been caught. Added an explicit regex check before argv
  injection; same defense covers any `extra_arg` flowing from the
  pending-intent permission-relay retry path.
- **Per-handle batch buffer bounded.** A handle that never gives the
  bridge 3 s of quiet would grow its batch unbounded.
  `MAX_BATCH_MSGS_PER_HANDLE = 20` triggers an early flush.
- **BiDi / zero-width / C0-control stripping on inbound bodies.** The
  outbound sender already did this; the reader now does too, so the
  audit log, the model's view, and the recipient's rendered text all
  agree.
- **Structural argv invariant: `--` must immediately precede the
  prompt.** Defense in depth; code always builds it that way, this
  check catches future regressions.
- **Docs refreshed:** schema-version drift (v1 → v3) across
  `AUDIT_LOG_COOKBOOK.md`, `RECOVERY.md`, `ARCHITECTURE.md`. Trust-mode
  interaction explained in `TOOL_OPT_IN.md`. README adds Prerequisites
  (Claude Code CLI), Memory backend section, badges. Internal dev
  notes deleted from repo root.



### Added

- **Image / PDF attachments are now handled.** The reader joins the
  `attachment` table to resolve on-disk file paths; the daemon hands
  those paths to claude with a "use the Read tool" instruction.
  Claude's Read tool decodes the image and shows it to the model
  natively. Active in `coding` and `full` trust modes.
- **Voice-note transcription via whisper.cpp.** Audio attachments
  (`.caf`, `.m4a`, `.mp3`, `.wav`, etc.) are transcribed offline by a
  locally-installed [whisper.cpp](https://github.com/ggerganov/whisper.cpp)
  binary and inlined into the prompt as text. No network call, no
  API. New config: `whisper_binary`, `whisper_model_path` (both
  optional — defaults try `whisper-cli` on PATH and
  `~/whisper.cpp/models/ggml-base.en.bin`).
- **Auto-accept edits in `coding` / `full` modes.** Routine file
  edits no longer round-trip through the permission relay for each
  one. New config: `protected_files` (default `["~/.claude/CLAUDE.md"]`)
  — those specific paths still require explicit user approval via
  the relay flow. `bypassPermissions` remains permanently refused
  by the runner.
- **Per-handle inbound batching window.** Adjacent messages from the
  same handle merge into one claude call after a 3-second quiet
  window. Handles "text + image" naturally (one reply instead of
  two). Cursor advances at enqueue; a crash during a settle window
  loses buffered messages (user re-sends) but never duplicates.
- **Outbound-rate auto-PAUSE.** New safety net: if a single handle
  receives more than 6 outbound sends within 60s, the daemon trips
  the PAUSE file. Sits below the existing reply rate limit (which
  drops messages but doesn't pause); this catches sustained loops.
- **Phantom-attachment defense.** Rows with
  `cache_has_attachments=1` but no resolvable path AND no caption
  yield as `<empty-skip>`. Apple's chat.db back-fills the attachment
  flag on link-preview metadata, audio-message metadata, and
  delayed iCloud sync echoes — without this, the bridge would emit
  spurious "📎 try resending" acks hours after any real activity.
- New module `src/audio_transcribe.py` with explicit size, wallclock,
  and output caps.
- New threat-model sections S13–S16 covering the above.

### Changed

- **Per-call cost cap default raised from $0.50 → $1.00.** Image
  calls (vision tokens) + memory-backend context (20-40K input
  tokens) routinely land $0.30–0.70; $1.00 gives 2x headroom. The
  daily cost cap (default $5) still bounds total exposure.
- **Pending-intent TTL raised from 60s → 15 minutes.** 60s assumed
  computer-paced confirmations; reality is phone-paced. Stale
  pendings still expire so a "yes" from yesterday can't trigger
  today's action.
- **Echo dedupe hardened.** Body hashing now normalizes smart quotes,
  em/en dashes, NBSP, multi-hyphen runs, whitespace, and case before
  hashing. Live test showed only 1 of ~14 echoes matched exact-bytes
  — iMessage autocorrect rewrites between send and sync-back.
- **`attributedBody` plist-parse failures downgraded to DEBUG.** They
  fire constantly on modern macOS rows; the previous WARNING level
  caused log floods on benign skips.

### Fixed

- **Cursor-advance-on-skip.** `fetch_new_messages` previously
  `continue`'d silently on rows with empty bodies, causing the
  cursor to pin in front of N unparseable rows and re-emit warnings
  every poll. Now every SQL row yields a Message (empty-skip
  sentinel for the unusable ones) so the cursor advances.
- **Spurious "📎 try resending" acks fired hours after real
  activity.** See phantom-attachment defense above.

## [Phase D] — Test suite + CI + threat-model resync

- 200+ unit tests (now 513), audit_log schema migrations, status.json
  health sidecar, operator docs (audit-log cookbook, recovery,
  launchd, tool opt-in), CI workflow (pytest/ruff/mypy/bandit/pip-audit/
  detect-secrets) with SHA-pinned actions.
- README + SECURITY polish, LICENSE attached.
- 4 rounds of adversarial + solver review applied.
- Memory backend (`memory.backend: claude_md`) with lazy reference
  loading.
- Nightly state.db backup rotation.

## [Phase C] — Sessions

- `/sessions`, `/pick N`, `/use <keyword>`, `/new`, `/status`,
  `/halt`, `/help`, `/sources`, `/last`.
- Numbered-options UX (no inline UI) for any iMessage client.
- Per-handle current-session pointer in state.db; automatic
  recovery on stale-session resume.
- Natural-language intent classifier + 15-minute confirmation flow
  for destructive intents.

## [Phase B] — Claude SDK invocation

- `claude_runner` with hermetic per-call sandbox, `_assert_safe_argv`
  invariants, scrubbed env, process-group kill on timeout.
- Trust mode framework (`chat_only` / `coding` / `full`).
- Cost cap (daily + per-call), reply rate limit, circuit breaker
  → auto-PAUSE.
- Empirical Bash-denied selftest at startup.

## [Phase A] — Plumbing

- chat.db read-only reader with SQL-layer filters.
- AppleScript-driven Messages.app sender with handle validation.
- Allowlist gating.
- Echo daemon (no claude yet).
