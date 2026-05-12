# claude-imessage-bridge

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
| **D** | Test suite, threat-model resync, status.json, schema migrations, CI, README/SECURITY polish | 🚧 in progress |
| **public** | License attached, public push to GitHub, final adversarial review | ⏳ blocked on Phase D + final review |

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
| Attachments / images | ❌ | v0 chat surface only |
| Message edits / unsends | ❌ | first-seen content is what we processed; audit log records that |

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

## Permissions required

| Permission | Why |
|---|---|
| **Full Disk Access** for your terminal/launcher | To read `~/Library/Messages/chat.db`. macOS guards this. |
| **Automation > Messages** for your terminal/launcher | To send replies via AppleScript. |

⚠ Full Disk Access is **broader than just chat.db** — granting it to a
process gives that process read access to everything in `~/Library/` and
most of your home directory. Grant only after reading the code, or pin a
specific commit and review it.

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
- **No attachments.** v0 only handles plain text. Inbound images are filtered
  out at the SQL layer (`cache_has_attachments = 1`).
- **No edit/unsend handling.** If a message is edited after we read it, we
  process the first-seen version. The audit log records what we processed.
- **No telemetry, no auto-update.** You pull updates manually.
- **macOS Messages sync limitation.** The bridge can only reply *to the sender
  of the inbound message*. There's no API to "send to a different contact" —
  this is by design (see threat model S5).
- **Cost-exhaustion within caps.** An allowlisted attacker can burn the daily
  cap in ~60s at default settings (10 replies/min × $0.044/call). Lower
  `daily_cost_cap_usd` or `reply_rate_limit_per_minute` if that worries you.

## Operator docs

- [docs/AUDIT_LOG_COOKBOOK.md](docs/AUDIT_LOG_COOKBOOK.md) — common SQL queries on `state.db`
- [docs/RECOVERY.md](docs/RECOVERY.md) — restoring from a corrupted DB, clearing the cursor, etc.
- [docs/LAUNCHD.md](docs/LAUNCHD.md) — running the daemon under launchd
- [docs/TOOL_OPT_IN.md](docs/TOOL_OPT_IN.md) — decision tree for adding tools to `allowed_tools`

## License

[MIT](LICENSE) — Copyright (c) 2026 samgob.
