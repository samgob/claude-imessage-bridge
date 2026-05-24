# claude-imessage-bridge — Architecture

## Overview

Local macOS daemon. Reads incoming messages from `~/Library/Messages/chat.db`,
routes by sender against an allowlist, drives a Claude Code session per
conversation (self-chat or per allowed contact), replies via AppleScript.

```
┌──────────────────────────────────────────────────────────────────┐
│ User on iPhone/iPad/Mac sends iMessage to themselves             │
└────────────────────────────┬─────────────────────────────────────┘
                             ▼
                ┌────────────────────────┐
                │ chat.db (Apple-managed)│  Full Disk Access required
                │ ~/Library/Messages/    │  (one-time grant by user)
                └────────────────────────┘
                             │
       poll every N seconds  │  (read-only SQLite open)
                             ▼
                ┌────────────────────────┐
                │  imessage_reader.py    │
                │  - track last_rowid    │
                │  - parse message rows  │
                │  - sender normalization│
                └────────────────────────┘
                             │
                  Message dataclass
                             ▼
                ┌────────────────────────┐
                │  allowlist filter      │  silently drops disallowed
                │  + group-chat refusal  │  (unless group GUID opted-in)
                └────────────────────────┘
                             │
                             ▼
                ┌────────────────────────┐
                │  daemon._handle_one    │
                │  - commands: /sessions /pick /help /new /use <query>
                │  - else: route to Claude with current session id
                │  - per-conversation state in SQLite (state.db)
                └────────────────────────┘
                             │
              ┌──────────────┴──────────────┐
              ▼                             ▼
   ┌────────────────────┐         ┌────────────────────────┐
   │ commands.py        │         │ claude_runner.py       │
   │ (numbered options, │         │ - claude -p --resume   │
   │  in-conversation)  │         │ - per-call sandbox     │
   └─────────┬──────────┘         │ - --disallowed-tools   │
             │                    │ - per-day cost cap     │
             │                    └─────────┬──────────────┘
             └──────────────┬───────────────┘
                            ▼
                ┌────────────────────────┐
                │ imessage_sender.py     │
                │ - osascript -- argv    │
                │ - strict handle regex  │
                │ - BiDi-stripped body   │
                │ - rate-limit / cap     │
                └────────────────────────┘
                            │
                            ▼
                   reply lands in same
                   conversation thread
```

## State store

`~/.claude-imessage-bridge/state.db` (SQLite, mode 0o600 in 0o700 dir).
Schema is versioned via `PRAGMA user_version`; current: **v1**.

| Table | Purpose |
|---|---|
| `cursor` | `chatdb_last_rowid` for chat.db (so we don't re-process on restart) plus `consec_failures` for the circuit breaker |
| `conversations` | `(handle, current_session_id, last_options_json, last_options_at, updated_at)` — `last_options_json` is the numbered list from the last `/sessions` or `/use`, used by `/pick N`; ages out after 30 min |
| `audit_log` | one row per inbound + outbound event: ts, redacted handle, direction, kind (command/text/reply/drop), short detail, reply byte length, chatdb rowid, cost cents, error category. **Never contains raw bodies.** |
| `reply_counter` | per-(handle, minute-bucket) reply counts for atomic rate-limit reservation |
| `daily_cost` | per-UTC-date spend tally in integer cents for the daily cap |

A sidecar `status.json` is written next to state.db on every heartbeat —
see `src/health.py` for the schema. Atomic write; intended for
`cimb-status`-style external monitors.

## Config

`~/.claude-imessage-bridge/config.yaml` (NOT in repo; perms 0o600):

```yaml
# Where claude -p runs (cwd of each per-call sandbox is a fresh tempdir,
# NOT this path — this is just what shows in your project picker).
project_directory: /Users/<you>/code/some-project

allowlist:
  - "+1XXXXXXXXXX"             # E.164 phone
  - "user@example.com"          # Apple ID email
allow_group_chat_guids: []      # default empty — group chats refused

# Pure text-only chat (recommended default). Adding tools widens the
# attack surface; see docs/TOOL_OPT_IN.md before changing this.
allowed_tools: []
forbidden_tools: []             # extra denies on top of HARD_DISALLOWED

poll_interval_seconds: 3
reply_rate_limit_per_minute: 10
daily_cost_cap_usd: 5.00
per_call_cost_cap_usd: 0.50
per_call_max_turns: 1
per_call_timeout_seconds: 90
circuit_breaker_failures: 5     # consecutive claude failures → auto-PAUSE
claude_binary: /usr/local/bin/claude
debug: false                    # turning this on logs message bodies to stderr
```

`allowed_tools` and `forbidden_tools` are checked against
`claude_runner.HARD_FORBIDDEN_TOOLS` at config-load time; any of `Bash`,
`Write`, `Edit`, `WebFetch`, `Skill`, `Agent`, or `mcp__*` entries cause the
daemon to refuse to start. The runtime deny list (`HARD_DISALLOWED`) is the
broader set actually passed to `--disallowed-tools` — entries from
`allowed_tools` are subtracted from it for each call.

## UX — numbered options pattern

Users don't type session IDs. We give them numbered options that age out
in 30 minutes.

### `/sessions`

```
Recent sessions
[1] a1b2c3d4 · 2h ago — refactor auth flow
[2] b2c3d4e5 · 1d ago — dashboard styling notes
[3] c3d4e5f6 · 3d ago — investigation: payment retry loop
[4] d4e5f6a7 · 5d ago — q4 planning doc
[5] e5f6a7b8 · 1w ago — onboarding script

Reply /pick <N> to switch. Add --all to include routines.
```

### `/use auth-refactor`

If exactly one match: auto-resumes that session. If multiple, shows a
numbered list and waits for `/pick N`. If none, says "No sessions match".

The numbered list state lives in `conversations.last_options_json` keyed
by handle; `/pick N` looks up that conversation's last list. The list
expires after `LAST_OPTIONS_TTL_SECONDS` (30 min) so a much-later `/pick`
can't resurrect old context.

### `/help`

```
Commands:
/help — this list
/new — start a fresh session
/status — current session info
/sessions — list recent sessions (numbered)
/use <query> — search by keyword; shows matches as numbered list
/pick <N> — switch to a numbered match from the last list

Anything else continues your current session.
```

## Security defaults

See `THREAT_MODEL.md` for the full design. Highlights:

- Read-only chat.db (`?mode=ro`); `handle.service = 'iMessage'` SQL filter (SMS dropped).
- Hermetic per-call sandbox: fresh `tempfile.TemporaryDirectory` + fresh
  empty MCP config written with `O_NOFOLLOW | O_EXCL` (symlink-write safe).
- `--disallowed-tools <csv>` is the real tool-deny mechanism (NOT `--tools ""`
  which is a documented no-op). Default `allowed_tools: []` → pure text chat.
- Empirical Bash-denied selftest at every daemon startup; daemon refuses to
  start if denial regresses.
- No `--dangerously-skip-permissions`; `_assert_safe_argv` rejects any
  variant of it in argv.
- AppleScript send is argv-only (`osascript -e SCRIPT -- handle body`); body
  is BiDi-stripped and length-capped.
- Daily + per-call cost caps (integer cents); atomic per-handle minute
  rate-limit; circuit breaker auto-PAUSE on N consecutive failures.
- Group chats refused unless GUID is explicitly opted into config.
- Audit log never contains raw bodies. User-facing error messages are
  canned strings.

## Phases

- **Phase A:** chat.db reader + sender + echo daemon. No Claude. Proves plumbing + security baseline.
- **Phase B:** Claude SDK call on incoming text, hermetic invocation, fresh session each time. No commands. Validates the LLM round-trip.
- **Phase C:** `/sessions`, `/pick`, `/use <query>`, `/new`, `/help`, `/status`. Per-conversation session state. The differentiator.
- **Phase D:** Test suite, schema-migration framework (`SCHEMA_VERSION=3` at time of writing), `status.json` health sidecar, threat-model resync, README + SECURITY polish, CI workflow, operator docs.
- **Phase E:** Image attachments handed to claude via Read tool, voice-note transcription via whisper.cpp (with afconvert transcoding), `accept_edits` + `protected_files` (auto-accept routine edits except for a denylist), per-handle inbound batching window, phantom-attachment defense, outbound-rate auto-PAUSE safety net.
- **Public:** LICENSE attached, two-stream review (security + polish), repo visibility flipped.
