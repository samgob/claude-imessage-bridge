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

| | |
|---|---|
| Phase A | Plumbing (chat.db reader + sender + echo daemon) |
| Phase B | Claude SDK invocation, fresh session per message |
| Phase C | `/sessions`, `/pick`, `/use`, `/new`, `/help` with numbered options |
| Phase D | Public release |

This README is in its early state. Setup steps follow once Phase A is verified.

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
- **Any `WebFetch` you opt-in to** would hit arbitrary hosts.

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

- Read-only SQLite open on `chat.db`.
- Strict sender allowlist; group chats refused unless explicitly opted in by GUID.
- Default Claude tool allowlist excludes `Bash`, `Write`, `Edit`, `MultiEdit`,
  and similar exfiltration vectors. Prompt injection via inbound text cannot
  trigger writes by default.
- Daily cost cap; per-minute reply rate limit.
- Message bodies are not logged unless `--debug` is set.

Full design rationale: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## License

MIT (see [LICENSE](LICENSE) when added in Phase D).
