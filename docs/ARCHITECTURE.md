# claude-imessage-bridge — Architecture (v0)

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
                │  router.py             │
                │  - /sessions /pick /help /new /use <query>
                │  - else: route to Claude with current session id
                │  - per-conversation state in SQLite (state.db)
                └────────────────────────┘
                             │
              ┌──────────────┴──────────────┐
              ▼                             ▼
   ┌────────────────────┐         ┌────────────────────────┐
   │ command_handler.py │         │ claude_runner.py       │
   │ (numbered options, │         │ - claude -p --resume   │
   │  in-conversation)  │         │ - restricted tool set  │
   └─────────┬──────────┘         │ - per-day cost cap     │
             │                    └─────────┬──────────────┘
             └──────────────┬───────────────┘
                            ▼
                ┌────────────────────────┐
                │ imessage_sender.py     │
                │ - osascript wrapper    │
                │ - strict handle regex  │
                │ - body via tempfile    │
                │ - rate-limit / cap     │
                └────────────────────────┘
                            │
                            ▼
                   reply lands in same
                   conversation thread
```

## State store

`~/.claude-imessage-bridge/state.db` (SQLite):

| Table | Purpose |
|---|---|
| `cursor` | `last_seen_rowid` for chat.db (so we don't re-process on restart) |
| `conversations` | `(handle, current_session_id, last_command_options_json)` — options is the numbered list from the last /sessions or /use query, used by /pick N |
| `audit_log` | one row per inbound message: ts, handle, command-or-text, route taken, reply length (no body content unless --debug) |
| `cost` | per-day cost tally for spend caps |

## Config

`~/.claude-imessage-bridge/config.yaml` (NOT in repo):

```yaml
project_directory: /Users/<you>/Desktop/Claude Homebase
allowlist:
  - "+1XXXXXXXXXX"           # E.164
  - "user@example.com"        # Apple ID email
allow_group_chat_guids: []    # default empty
allowed_tools:                # see TOOLS_DEFAULT in code
  - Read
  - Grep
  - Glob
  - LS
  - WebFetch
  - Skill
forbidden_tools:              # explicitly blocked, even if model tries
  - Bash
  - Write
  - Edit
  - MultiEdit
poll_interval_seconds: 3
reply_rate_limit_per_minute: 10
daily_cost_cap_usd: 5.00
redact_snippets: true
debug: false                  # turning this on logs message bodies
```

## UX — numbered options pattern

Per Sam's feedback (2026-05-12): users don't type session IDs. We give them
numbered options.

### `/sessions`

```
Recent sessions (interactive only):
[1] b6da370a — Wesco POC deck (2d)
[2] 1ae3935e — Wesco UC1 schema (2d)
[3] 7cbff517 — Wesco model arch (4d)
[4] 069ac15d — DC adjunct positions (4d)
[5] cf1f4e30 — POC kickoff prep (7h)

Reply /pick 1..5 to switch. /sessions --all includes routines.
```

### `/use wesco`

```
Resumed [1] b6da370a — Wesco POC deck.

Other matches:
[2] 1ae3935e — Wesco UC1 schema
[3] 7cbff517 — Wesco model arch
Reply /pick 2 or /pick 3 to switch.
```

The numbered list state lives in `conversations.last_command_options_json`
keyed by handle; `/pick N` looks up that conversation's last list.
Numbering resets on each new `/sessions` or `/use`.

### `/help`

```
Commands:
/new — fresh session
/sessions [--all] — list recent
/use <query> — find by keyword
/pick <n> — switch to numbered option
/status — current session info
/help — this

Anything else continues your current session.
```

## Security defaults

See `THREAT_MODEL.md`. Highlights:

- No `--dangerously-skip-permissions`. Tool allowlist enforces what Claude can do.
- Group chats refused unless GUID is explicitly opted into config.
- Daily cost cap.
- Reply rate limit.
- Read-only chat.db.
- AppleScript body passed via tempfile, not string interpolation.
- Logs do not contain message bodies unless `--debug` is set.

## Phases

- **Phase A (v0.1):** chat.db reader + sender + echo daemon. No Claude. Proves plumbing + security baseline.
- **Phase B (v0.2):** Claude SDK call on incoming text, fresh session each time. No commands. Validates the LLM round-trip.
- **Phase C (v0.3):** `/sessions`, `/pick`, `/use <query>`, `/new`, `/help`. Per-conversation session state. The differentiator.
- **Phase D (v0.4):** README, LICENSE, CHANGELOG, hardening, public release.
