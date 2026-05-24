# claude-imessage-bridge

[![CI](https://github.com/samgob/claude-imessage-bridge/actions/workflows/ci.yml/badge.svg)](https://github.com/samgob/claude-imessage-bridge/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![macOS](https://img.shields.io/badge/macOS-only-lightgrey.svg)](#prerequisites)

> ⚠ **Research preview.** Not yet stable. Treat installations as
> experimental until v0.1 ships. See [SECURITY.md](SECURITY.md) and
> [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before installing.

A local macOS daemon that lets you chat with Claude Code via iMessage,
with **per-conversation session resume** — pick up the same Claude
session you were in yesterday, from your phone.

## Why this exists

Anthropic ships an [official iMessage plugin](https://github.com/anthropics/claude-plugins-official/tree/main/external_plugins/imessage)
for Claude Code. It pushes events into **one** running Claude Code session.
That's enough for "ask Claude something quick" but it can't resume a
specific past session, switch between sessions, or maintain per-
conversation state.

This bridge fills that gap: it runs as a daemon, polls `chat.db`, and
routes each inbound message to a Claude Code session of your choice via
`claude --resume`.

## Status

| Phase | Scope | State |
|---|---|---|
| **A** | Plumbing — chat.db reader + AppleScript sender + echo daemon | ✅ shipped |
| **B** | Claude SDK invocation, hermetic per-call sandbox | ✅ shipped (3 rounds of adversarial review) |
| **C** | `/sessions`, `/pick`, `/use`, `/new`, `/help` with numbered options + per-handle resume | ✅ shipped |
| **D** | Test suite, threat-model resync, status.json, schema migrations, CI, README/SECURITY polish | ✅ shipped |
| **E** | Images (via Read tool), audio (via whisper.cpp), auto-accept edits + `protected_files`, per-handle batching window | ✅ shipped |
| **public** | License attached, public push to GitHub, final adversarial review | ⏳ in progress |

## Feature matrix

| Capability | Supported | Notes |
|---|---|---|
| Resume a specific past Claude session by iMessage | ✅ | `/use <keyword>` / `/pick <N>` |
| Per-handle session persistence | ✅ | each allowlisted contact gets their own active session |
| Multiple allowlisted contacts | ✅ | each can drive a different session |
| Numbered-options UX (no inline UI) | ✅ | works on any iMessage client (iPhone, Mac, Watch) |
| List recent sessions | ✅ | `/sessions` (10 most-recent); `--all` includes routines |
| Search sessions by keyword | ✅ | `/use auth-refactor` matches by transcript content |
| Start a fresh session | ✅ | `/new` |
| Show current session | ✅ | `/status` |
| Daily + per-call cost caps | ✅ | configurable, integer-cents accounting |
| Rate limit per handle/minute | ✅ | atomic SQL reservation |
| Circuit breaker on consecutive failures | ✅ | auto-creates PAUSE file after N failures |
| Hermetic per-call sandbox (no CLAUDE.md / MCP / skills) | ✅ | fresh tempdir + empty-mcp.json per call |
| Empirical Bash-denied selftest at startup | ✅ | refuses to start if denial regresses |
| Group chats | ⚠️ opt-in only | explicit GUID allowlist; refused by default |
| SMS | ❌ never | `handle.service = 'iMessage'` filter at SQL layer |
| Images / PDFs | ✅ | paths handed to claude; `Read` tool views them inline (`trust=full` or `coding`) |
| Voice notes / audio | ✅ optional | offline transcription via [whisper.cpp](https://github.com/ggerganov/whisper.cpp); install instructions below |
| Auto-accept routine edits | ✅ | `trust=full` / `coding` mode default; `protected_files` (default `~/.claude/CLAUDE.md`) still gates explicit approval |
| Per-handle batching window | ✅ | adjacent messages from the same handle merge into one claude call (3s settle) — handles "text + image" naturally |
| Message edits / unsends | ❌ | first-seen content is what we processed; audit log records that |

## Prerequisites

- **macOS** (the AppleScript send path is macOS-coupled — no Linux/Windows
  support).
- **Python 3.11+**.
- **Claude Code CLI** installed on `PATH`. The bridge invokes `claude -p`
  as a subprocess; it does **not** ship with Claude Code. Install from
  [Anthropic's docs](https://docs.anthropic.com/claude-code) and confirm
  `which claude` returns a path before continuing. The default
  install location is `/usr/local/bin/claude` — override via
  `claude_binary:` in `config.yaml` if yours is elsewhere.
- *(Optional)* **whisper.cpp** for voice-note transcription — see
  [Images, voice notes, and edit permissions](#images-voice-notes-and-edit-permissions)
  below.

## Quickstart

```bash
git clone https://github.com/samgob/claude-imessage-bridge.git
cd claude-imessage-bridge
python3.11 -m pip install -e .

# One-time setup:
mkdir -p ~/.claude-imessage-bridge
cp config.example.yaml ~/.claude-imessage-bridge/config.yaml
chmod 600 ~/.claude-imessage-bridge/config.yaml
# Edit ~/.claude-imessage-bridge/config.yaml:
#   - allowlist:        your Apple ID email + any phones to permit
#   - project_directory: absolute path to a Claude Code project
#   - allowed_tools:     leave [] for text-only chat (recommended default)
#   - trust:             defaults to chat_only. Flip to `coding` for
#                        filesystem-aware Claude or `full` for the
#                        "Claude Code in iMessage" experience. See the
#                        config.example.yaml comments and
#                        docs/THREAT_MODEL.md before changing.

# Foreground run (Ctrl-C to stop):
python3 -m src.daemon

# One-shot mode for testing:
python3 -m src.daemon --once
```

On first run, macOS will prompt for Full Disk Access (for `chat.db`)
and Automation > Messages (to send replies). The daemon refuses to
start unless its empirical Bash-denied selftest passes — if Anthropic
ever changes Claude Code's tool-flag semantics, you'll see a clear
error before any user messages are processed.

You can also talk to the bridge in plain English. A pattern-based intent
classifier maps phrases like *"how much have I spent today"*, *"pause
the bridge"*, *"what session am I in"* to the matching slash command,
with confirmation prompts for anything destructive. Send `/help` to see
the full command surface (16+ commands including `/status`, `/pause`,
`/resume`, `/sources`, `/last`, `/cost-today`, `/tail-audit`, …).

## Images, voice notes, and edit permissions

These features are active in `coding` and `full` trust modes only.
`chat_only` (the OSS default) ignores attachments and has no edit
authority.

### Images / PDFs

When you send an image or PDF, the bridge resolves its on-disk path
(must live under `~/Library/Messages/Attachments/`, must exist) and
hands it to claude in the prompt with a "use the Read tool to view"
instruction. The Read tool handles image and PDF files natively — same
code path as foreground Claude Code reading any local file.

No setup required. Just send the image.

### Voice notes (optional)

Audio attachments (`.caf`, `.m4a`, `.mp3`, etc.) are transcribed
**locally** via [whisper.cpp](https://github.com/ggerganov/whisper.cpp).
No network call, no third-party API. The transcript is inlined into
the prompt as text.

To enable:

```bash
brew install whisper-cpp

# Download a model (base.en is a good speed/quality tradeoff for English
# voice notes; ~150MB; ~1x realtime on Apple Silicon):
mkdir -p ~/whisper.cpp/models
cd ~/whisper.cpp/models
curl -L -o ggml-base.en.bin \
  https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-base.en.bin
```

The bridge auto-discovers `whisper-cli` on `PATH` and looks for the
model at `~/whisper.cpp/models/ggml-base.en.bin`. Override either via
config:

```yaml
whisper_binary: /opt/homebrew/bin/whisper-cli   # explicit (optional)
whisper_model_path: /path/to/your/model.bin     # explicit (optional)
```

If whisper.cpp isn't installed when a voice note arrives, the bridge
sends a one-time setup-hint reply and skips claude (no cost incurred).

### Auto-accept edits + `protected_files`

In `coding` / `full` modes the bridge runs claude with
`--permission-mode=acceptEdits` so routine edits to memory files,
project notes, the health log, etc. go through without an
iMessage round-trip for each one.

A short `protected_files` list is enforced via inline
`--settings` JSON `permissions.deny` rules. Edits to those paths
still surface as `permission_denials` and route to the
permission-relay flow (you get a "🔒 Claude wanted to edit ... Reply
yes to approve" message; reply yes; the edit applies).

Default protected set:

```yaml
protected_files:
  - ~/.claude/CLAUDE.md
```

Extend if you want other files behind the gate. The relay never gives
claude `bypassPermissions` authority — that flag is permanently refused
by the runner regardless of caller opt-in.

### Per-handle batching window

iMessage stores "text + image" as two adjacent chat.db rows. Without
batching each would spawn its own claude call (two replies to one
logical user action, useless first one, 2x cost).

The daemon buffers inbound messages per handle for 3 seconds. If
another message from the same handle arrives in that window, both
merge into one claude call. Bodies are concatenated; attachment paths
are union'd.

**Cost:** every reply gets 3–6s of added latency (one poll cycle plus
the settle window). Fine for phone-paced messaging.

## Permissions required

| Permission | Why |
|---|---|
| **Full Disk Access** for your terminal/launcher | To read `~/Library/Messages/chat.db`. macOS guards this. |
| **Automation > Messages** for your terminal/launcher | To send replies via AppleScript. |

⚠ Full Disk Access is **broader than just chat.db** — granting it to a
process gives that process read access to everything in `~/Library/` and
most of your home directory. Grant only after reading the code, or pin a
specific commit and review it.

## Memory backend (optional)

In `coding` and `full` trust modes you can opt into the `claude_md`
**memory backend**: every claude invocation gets a system-prompt
injection containing your `~/.claude/CLAUDE.md` plus any
`memory/projects/*.md` or `memory/people/*.md` files whose content
matches the incoming message. This lets the bridge act with the same
context you'd give a foreground Claude Code session — names, deals,
preferences — without restating them in every message.

Off by default. To enable, set `memory.backend: claude_md` in
`config.yaml`. Capped at 32 KB per call with a 5-minute cache.
Inspect what was loaded for the last call by sending `/sources`.

`chat_only` trust mode **forces** the memory backend off regardless of
this setting — defense in depth, so a single OSS user with a
misconfigured config can't accidentally exfiltrate their memory tree
to anyone on their allowlist.

## Networking

The daemon opens **no network listeners**. It does, however, generate
outbound traffic:

- **Claude API** — every reply round-trips through `api.anthropic.com` via
  the `claude` CLI. Anthropic sees the message content and your IP.
- **macOS gatekeeper / OCSP** — first-launch macOS may contact Apple's
  notarization endpoints when verifying the binaries you grant FDA to.
- **Any `WebFetch` you opt-in to** would hit arbitrary hosts. The default
  allowlist is `[]` (none), so no `WebFetch` happens unless you change it.

So "no listeners" — not "no traffic."

## Important: family-shared Apple ID

If your Apple ID is signed in on a family member's device (spouse's iPad,
shared family iPhone), **they see every reply this bot sends** in their
Messages app, exactly as if you'd sent it yourself. The bot reading your
own messages and replying TO your own Apple ID means the conversation
syncs to all your Apple-ID-signed-in devices. There's no per-device
filter.

If this matters, either don't use this bot, or set it up on an Apple ID
that's only signed in on devices you control.

## Security posture (summary)

- Read-only SQLite open on `chat.db` (`?mode=ro`).
- `handle.service = 'iMessage'` SQL filter — SMS is dropped (spoofable caller-ID).
- Strict sender allowlist; group chats refused unless explicitly opted in by GUID.
- **Default Claude tool allowlist is empty** — pure text chat. Bash, Read, Write,
  WebFetch, Skill, Agent, every MCP, etc. are denied via `--disallowed-tools`.
  Tool denial is **verified empirically** at every daemon startup (the daemon
  spawns one `claude -p` call and asserts Bash cannot write a canary file —
  the daemon refuses to start otherwise).
- Hermetic per-call sandbox: dedicated fresh tempdir + fresh empty MCP config,
  written with `O_NOFOLLOW | O_EXCL` (symlink-write safe). User's global
  `CLAUDE.md`, `.mcp.json`, skills, and `settings.json` don't load.
- Daily cost cap + per-call cost cap + per-minute rate limit (atomic at the SQL layer).
- Circuit breaker auto-creates `PAUSE` after N consecutive Claude failures.
- Cursor regression guard: a restored backup of state.db won't replay messages.
- Audit log NEVER contains raw message bodies. Debug mode logs bodies to
  stderr only, never to state.db.
- User-facing error messages are canned strings; internal error detail and
  consecutive-failure count don't leak over iMessage.

Full design rationale: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Known limitations

- **macOS-only.** AppleScript send path is fundamentally macOS-coupled.
- **Single user.** The bridge runs as you, sends as you, reads your chat.db.
  There's no multi-tenant mode.
- **3–6s reply latency.** Per-handle batching window (3s) + poll
  interval (3s default). The tradeoff: "text + image" combos merge
  into one claude call instead of producing two replies.
- **Audio requires whisper.cpp.** If you want voice-note transcription,
  install whisper.cpp + a model (see above). Otherwise voice notes get
  a one-time setup-hint reply.
- **No edit/unsend handling.** If a message is edited after we read it, we
  process the first-seen version. The audit log records what we processed.
- **No telemetry, no auto-update.** You pull updates manually.
- **macOS Messages sync limitation.** The bridge can only reply *to the sender
  of the inbound message*. There's no API to "send to a different contact" —
  this is by design (see threat model S5).
- **Cost-exhaustion within caps.** An allowlisted attacker can burn the daily
  cap by saturating the rate limit. Lower `daily_cost_cap_usd` or
  `reply_rate_limit_per_minute` if that worries you. Image / audio calls
  cost more (vision tokens, memory context); the per-call default is $1.00.
- **Phantom-attachment defense may drop slow-downloading images.**
  Apple back-fills `cache_has_attachments=1` on metadata-only rows; we
  drop attachment rows that have no resolvable path. If a real image
  is still downloading from iCloud when we poll, we drop it — re-send
  if needed. The alternative (acks firing hours later for no reason)
  was worse.

## Operator docs

- [docs/AUDIT_LOG_COOKBOOK.md](docs/AUDIT_LOG_COOKBOOK.md) — common SQL queries on `state.db`
- [docs/RECOVERY.md](docs/RECOVERY.md) — restoring from a corrupted DB, clearing the cursor, etc.
- [docs/LAUNCHD.md](docs/LAUNCHD.md) — running the daemon under launchd
- [docs/TOOL_OPT_IN.md](docs/TOOL_OPT_IN.md) — decision tree for adding tools to `allowed_tools`

## License

[MIT](LICENSE) — Copyright (c) 2026 samgob.
