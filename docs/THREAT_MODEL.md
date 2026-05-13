# claude-imessage-bridge — Threat Model

**Status:** Post-Session-2 (trust modes). The bridge now serves three
distinct audiences with different threat profiles. This document
catalogs the defenses by which trust mode they apply in, so an OSS user
flipping `trust.default: full` understands exactly which assumptions
they're trading for utility.

## What changed in Session 2

Prior versions of this doc were calibrated for **hermetic-by-default**:
the bridge invokes `claude -p` with empty MCP config, full
`HARD_DISALLOWED` deny list, and a tempdir cwd. That's right when:

- Multiple non-operator handles might be on the allowlist (family,
  friends, public demo).
- The operator wants the bridge to be a *less powerful* surface than
  their foreground Claude Code.

It's wrong for the case the bridge is most useful in: a single-operator
setup where the user's Apple ID is the only allowlisted handle and the
goal is "Claude Code reached via iMessage." Most of the defensive
scaffolding was protecting against the operator-as-attacker scenario,
which doesn't apply when the operator is the only one driving.

The trust-mode framework lets the user pick the right defenses for
their situation:

- **`chat_only`** (default, OSS): pre-Session-2 hermetic behavior.
- **`coding`**: filesystem-aware Claude without network.
- **`full`**: Claude Code in iMessage.

## Scope

A local macOS daemon that:
1. Reads new messages from `~/Library/Messages/chat.db` (read-only).
2. Decides whether the sender is on an allowlist; ignores otherwise.
3. Optionally classifies the message text against a natural-language
   intent matcher → maps to a built-in command if it matches.
4. Routes the message to either a built-in command handler (e.g.,
   `/sessions`, `/pick N`, `/help`), or to a Claude Code session
   (`claude -p --resume <id>` or fresh), invocation gated by the
   active trust preset.
5. Sends the response back via AppleScript-driven Messages.app.

No network ports are opened. All I/O is local. No telemetry.

## Asset inventory

| Asset | Sensitivity | Why an attacker would want it |
|---|---|---|
| User's local file system | High (Full Disk Access granted) | Read /Documents, /Desktop, secrets, browser cookies |
| User's iMessage history (chat.db) | High | Reveals contacts, private conversations |
| User's Claude Code session transcripts | High | Reveals work context, customer data, plans |
| Claude API quota / cost | Medium | Run up bills if abused |
| User's Messages.app sending capability | High | Send spam/phishing to user's contacts (reputation risk) |
| User's identity / public reputation as open-source author | High | A vulnerable project = headline reputation damage |
| **In `coding`/`full` modes:** the user's CLAUDE.md + memory/ tree | High | Customer pipeline, contact glossary, deal notes |
| **In `full` mode:** any MCP servers loaded (Gmail, Slack, Drive, etc.) | High | Same authority surface as foreground Claude Code |
| IP address / network identity | Low | No network listener; only relevant if Claude SDK leaks something |

## Trust modes

### `chat_only` (default — OSS safe baseline)

**Posture:** strictest hermetic. Identical to pre-Session-2 behavior.

| Defense | Active |
|---|---|
| Allowlist + `service='iMessage'` filter + group-chat refusal | ✓ |
| Hermetic `tempfile.TemporaryDirectory()` cwd | ✓ |
| `--strict-mcp-config` + empty MCP config | ✓ |
| Full `HARD_DISALLOWED` (32 tools) | ✓ |
| `--max-turns 1` | ✓ |
| Anti-fabrication system prompt | ✓ |
| Memory backend forced to `NoneBackend` regardless of config | ✓ |
| `_scrubbed_env` (7-var allowlist; no MCP credential pass-through) | ✓ |
| `selftest_bash_denied` empirical check at startup | ✓ |
| All cross-cutting defenses (see below) | ✓ |

**Defends against:** prompt-injection from an attacker on the allowlist
(family member's compromised device, a contact the operator added
without full trust, public demo handle).

**Use this when:** the bridge will be shared, demoed, or accessible to
handles you don't fully trust to drive your full Claude environment.

### `coding`

**Posture:** filesystem-aware Claude without network access or MCPs.

| Defense | Active |
|---|---|
| Allowlist + service filter + group-chat refusal | ✓ |
| `project_directory` as cwd (CLAUDE.md loads) | — |
| `--strict-mcp-config` + empty MCP config | ✓ |
| `HARD_DISALLOWED` minus filesystem tools (Bash, Read, Write, Edit, Grep, Glob, LS, NotebookRead, NotebookEdit, MultiEdit) | partial |
| `--max-turns 10` | configurable |
| Anti-fabrication system prompt | — (not needed; tools available) |
| Memory backend: `claude_md` (lazy reference loader) | — |
| `_scrubbed_env` + `GH_TOKEN` / `GITHUB_TOKEN` pass-through | partial |
| `selftest_bash_denied` | skipped (Bash IS allowed) |
| `selftest_allowlist_enforced` | ✓ |
| `selftest_argv_invariants` | ✓ |
| Cross-cutting defenses | ✓ |

**Defends against:** prompt-injection from inbound text driving the bridge
to make network requests, install crons, run MCP tools, or use Skill/Agent
to escape the tool deny list.

**Accepts:** the model can read, write, and run shell on the operator's
behalf within the project_directory's filesystem authority. CLAUDE.md is
loaded. memory/ references can be loaded by the memory backend.

**Use this when:** you want code-work-from-the-train but don't want the
bridge to be able to send Slack messages or hit external APIs.

### `full`

**Posture:** Claude Code reached via iMessage.

| Defense | Active |
|---|---|
| Allowlist + service filter + group-chat refusal | ✓ (LOAD-BEARING) |
| `project_directory` as cwd | — |
| Real MCP config (`~/.claude/.mcp.json`) loaded | — |
| `HARD_DISALLOWED` = `{AskUserQuestion}` only | ✓ for one tool |
| `--max-turns 20` | configurable |
| Anti-fabrication system prompt | — (the model HAS tools) |
| Memory backend: `claude_md` lazy loader | — |
| `_scrubbed_env` + MCP-credential env pass-through (GH_TOKEN, GOOGLE_OAUTH_*, SLACK_*) | — |
| `selftest_bash_denied` | skipped |
| `selftest_allowlist_enforced` | ✓ |
| `selftest_argv_invariants` | ✓ |
| Cross-cutting defenses | ✓ |

**Defends against:** anything that could let a non-allowlisted handle
reach the bridge. The allowlist is now the load-bearing defense.

**Accepts:** an attacker who CAN drive the bridge (Apple ID compromise,
or a compromised allowlisted contact in a multi-allowlist setup) has
full Claude Code authority — Bash on the operator's machine, MCP-server
calls under the operator's OAuth tokens, etc. This is the same authority
the operator's foreground Claude Code already has. The bridge does not
create new authority; it exposes existing authority to a new I/O surface.

**Use this when:** you are the only allowlisted handle on your bridge.
The bridge becomes a mobile port to your Claude Code.

## Cross-cutting defenses (active in ALL trust modes)

These defend the I/O layer, not the invocation. They apply regardless
of trust mode.

### S1. chat.db ingestion

- SQLite opened **read-only** (`?mode=ro`).
- `handle.service = 'iMessage'` SQL filter (SMS dropped — caller-ID is spoofable).
- Hard cap on body length (`MAX_BODY_BYTES = 16 KB`).
- `attributedBody` parsed with stdlib `plistlib` only, 256 KB cap, rich-class refusal.
- SQL-layer filters drop tapbacks, edits, expressive effects, participant-add/leave events, balloon-bundle apps, attachments.
- Strict allowlist check **before** any further processing.
- Sender handle validated against E.164 or email regex.

### S2. Allowlist gating

- `validate_handle` enforces strict E.164 phone or `local@domain` email regex.
- Group chats refused unless GUID is in `allow_group_chat_guids`.
- Allowlist normalized once at startup; invalid entries refuse startup.

### S3. Argument-injection (`_assert_safe_argv`)

`ARGV_DENYLIST` covers every variant of `--dangerously-skip-permissions`,
`--bypass-permissions`, `--no-permissions`, and
`--permission-mode=bypassPermissions` / `=acceptEdits`. Refuses both
exact-form and `=value` prefix-form. Verified by
`selftest_argv_invariants` at every daemon startup. These flags are
forbidden in **every** trust mode — they disable Claude Code's own
permission system, which we don't override even in full mode.

### S4. AppleScript send

- Argv-only AppleScript (`osascript -e SCRIPT -- handle body`). No `do shell script`, no string interpolation.
- `osascript` pinned to `/usr/bin/osascript`.
- Body sanitized through `_strip_display_attacks` (BiDi, zero-width, C0/C1 controls).
- Body capped at `MAX_REPLY_BYTES = 8 KB` on a UTF-8 boundary.
- Handle re-validated at send time.

### S5. Bridge-as-bot abuse (outbound)

- The bridge replies **only to the sender of the inbound message**.
- Per-minute rate limit per handle (atomic SQL reservation; TOCTOU-closed).
- Daily cost cap (integer cents).
- Per-call cost cap.
- Circuit breaker auto-PAUSE on N consecutive failures.

### S6. Open-source / repo

- `.gitignore` covers `.env*`, `config.yaml`, `state.db`, `*.sqlite*`, `logs/`, `samples/`, `chat.db`.
- `detect-secrets` scan in CI.
- SECURITY.md with private disclosure address.
- Dependencies pinned (`pyyaml` only third-party).
- Bandit + pip-audit + ruff + mypy in CI.

### S7. Supply chain

- Stdlib-only where reasonable.
- One third-party dependency (`pyyaml`).
- GitHub Actions pinned by SHA, not floating `@v4`.
- `claude_binary` symlink chain validated: resolved file must be regular, owned by root or current uid, not group/world writable, with no group/world writable dir on the symlink chain.

### S8. Local file leakage

- **Audit log NEVER contains raw bodies.** Detail field is structured
  summary only (e.g., `ok dur=1234ms cost_cents=4 sid=abc12345`).
- Audit log uses `handle_redacted` (the masked form like `+13***67`).
- User-facing error replies are canned strings keyed off `error_category`.
  Internal error string + consecutive-failure count log to stderr only.
- `state.db` mode 0o600 in 0o700 directory. If perms drift, daemon
  tightens on startup.
- `status.json` health sidecar mode 0o600. Schema-versioned, atomic write.
- `--debug` mode logs bodies to stderr only (never to state.db).
- `/halt` exit drops any in-flight tool authority by terminating the
  process group.

### S9. Confused-deputy / FDA

- The bridge has Full Disk Access (chat.db requires it).
- Code reads ONLY `~/Library/Messages/chat.db` and writes ONLY to
  `~/.claude-imessage-bridge/` and (in coding/full modes) the
  configured `project_directory` via Claude Code's tools.
- state.db symlink refusal at startup (file-swap defense).
- `claude_binary` validated as described in S7.
- Cursor regression guard: state.set_cursor refuses backward motion
  unless `allow_regression=True`. A restored backup of state.db won't
  silently replay messages.
- **Nightly state.db backups** (Session 2): 4am local, 14-day retention,
  gzip after 3 days. Makes the cursor regression guard meaningful.

### S10. Session-content leaks via iMessage

- `/sessions` and `/use` show truncated snippets (first ~60 chars) only.
- `last_options` for `/pick` expires after 30 min.
- In `coding` and `full` modes, the bridge can be asked "dump your
  CLAUDE.md verbatim" and will comply — same as foreground Claude.
  This is documented as accepted risk for those modes.

### S11. Self-chat echo loop (live-test fix)

- In-memory ring of recent outbound body hashes per handle, TTL 180s.
- iCloud Messages sync echoes the bridge's own outbound reply back as
  `is_from_me=0` (indistinguishable from a new inbound). The dedupe
  catches these and skips them.

### S12. Natural-language intent dispatch (Session 2)

- Pattern-based regex matcher; NOT an LLM call. No prompt-injection
  surface in the classifier.
- Destructive intents require explicit yes-confirmation via a 60s-TTL
  pending state in `conversations.pending_intent_json`.
- Read-only intents execute immediately.
- Slash commands (`/halt` etc.) pass through the classifier
  unchanged — explicit-form always works.

## Residual risks (accepted)

1. **The user can ask the bridge to do destructive things in their own
   work directory.** With `allowed_tools: []` (chat_only default),
   nothing destructive is possible. In `coding` or `full` modes, the
   user has the same authority as their foreground Claude Code.

2. **Apple ID compromise = bridge compromise.** An attacker who controls
   the operator's iCloud can message the bridge as the operator. In
   `chat_only` mode they can chat. In `coding` mode they can read/write
   files. In `full` mode they have the operator's entire Claude Code
   authority including MCPs.

3. **Physical access to the Mac.** Outside scope.

4. **Claude API compromise** (Anthropic-side). Outside scope.

5. **Edit/unsend on chat.db rows.** An attacker who can edit a sent
   message after we read it produces an "audit says X, current chat
   says Y" gap. Documented; not mitigated.

6. **Session-resume inherits the resumed session's tool authority.**
   `claude --resume <id>` against a session that has Gmail/Slack/Drive
   etc. MCPs configured gives the resumed conversation the same
   authority. In `chat_only` mode this is bounded by the bridge's
   `HARD_DISALLOWED` (resumed session can't escape the deny list). In
   `full` mode there's no escape — by design.

7. **Cost-exhaustion within caps.** An allowlisted attacker can burn
   the daily cap by saturating the rate limit. Bounded loss.

8. **Per-message `cost_cents` is a coarse length side-channel.** Audit
   log column correlates with token count and thus content length. We
   accept the trade-off because the column's purpose is per-handle and
   per-day spending forensics.

9. **`_redact_handle` preserves the email domain.** Rare or unique
   domains can be re-identifying. We accept because the operator needs
   to map redacted handles back to contacts when reading their own
   audit log.

10. **Selftest narrowness.** `selftest_bash_denied` verifies Bash
    specifically (chat_only mode only). The new
    `selftest_allowlist_enforced` and `selftest_argv_invariants` are
    trust-mode-agnostic and verify the load-bearing defenses across
    every mode.

11. **Trust mode is set in config, not negotiable per message.** This
    is a feature — preventing attacker-controlled input from escalating
    trust. But it means an operator changing trust mode requires
    editing config.yaml and restarting the daemon. No dynamic switching.

12. **Memory backend exposes CLAUDE.md content to iMessage.** In
    `coding` and `full` modes with `memory.backend: claude_md`, asking
    the bridge "what's in your CLAUDE.md" gets a useful answer.
    Reviewing what got loaded for the last call: send `/sources`.

## Pre-public-release gates

- [x] Round-3 independent adversarial review of code
- [x] Hermetic per-call invocation verified
- [x] Threat model resynced to ship state (this doc, Session 2)
- [x] Test suite covering every security-boundary module (440+ tests)
- [x] `bandit`, `pip-audit`, `ruff`, `mypy` clean in CI
- [x] README documents permissions, FDA scope, the three trust modes
- [x] SECURITY.md disclosure address + triage SLOs
- [x] LICENSE attached (MIT)
- [ ] At minimum 1 week of soak under real load on author's machine
- [ ] Final independent adversarial review on Session 2 work specifically
- [x] Explicit `WARNING: research preview` in README
