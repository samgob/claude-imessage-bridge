# claude-imessage-bridge — Threat Model

**Status:** v0 draft. Subject to independent adversarial review before any code
ships and before public release.

## Scope

A local macOS daemon that:
1. Reads new messages from `~/Library/Messages/chat.db` (read-only).
2. Decides whether the sender is on an allowlist; ignores otherwise.
3. Routes the message to either a built-in command handler (e.g.,
   `/sessions`, `/pick N`, `/help`) or to a Claude Code session
   (`claude -p --resume <id>` or fresh).
4. Sends the response back via AppleScript-driven Messages.app.

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
| IP address / network identity | Low | No network listener; only relevant if Claude SDK leaks something |

## Threat actors

1. **Casual external attacker** — random scanner, untargeted exploit attempts. No specific knowledge of the user.
2. **Targeted external attacker** — knows the user, knows they run this bridge, attempts to compromise via crafted inputs.
3. **iMessage-side prompt injector** — sends content designed to manipulate the LLM into doing things the user didn't intend (exfiltrate data, send spam, run dangerous tools).
4. **Compromised contact** — someone on the allowlist whose Apple ID is compromised, now able to drive the bridge as that user.
5. **Supply chain** — malicious Python package, malicious dependency update.
6. **Local privilege user** — anyone with shell on the Mac; outside our threat model (game-over already), but we shouldn't make it worse.

## Attack surfaces

### S1. chat.db ingestion path
- **Surface:** Polling `chat.db` reads message rows. Body content is attacker-controlled (anyone who knows the user's number can send to them).
- **Threats:**
  - SQL injection — N/A, we use parameterized queries.
  - Malformed Unicode / oversized bodies crashing the parser.
  - Attribute-body parsing exploits (binary plist) — Apple-format complexity.
  - Sender-handle spoofing via SMS-relayed-through-iMessage gateways.
  - Edit/unsend mutation of rows after first read (iOS 16+ feature).
  - Attachments table, link-preview `summary_info` blob with attacker-controlled binary plist.
  - Tapbacks (reactions) reading as text in isolation, stripping context.
- **Mitigations:**
  - SQLite opened **read-only** (`?mode=ro` only — NOT `immutable=1`; chat.db is written to continuously by Apple's `imagent`, and the `immutable` flag would cause stale/corrupt reads).
  - **Filter to `handle.service = 'iMessage'` only.** Drop SMS-routed rows entirely. SMS caller-ID is trivially spoofable; iMessage is cryptographically authenticated by Apple. This single filter closes the spoofing attack on phone-number allowlist entries.
  - Hard cap on message body length we read (16 KB). Truncate beyond.
  - Parse `attributedBody` (binary plist) with `plistlib` from stdlib only — no third-party parsers. Wrap in try/except; on parse failure, fall back to the plain `text` column and log a warning.
  - Skip rows where `associated_message_type` indicates tapback/reaction. Skip rows whose `associated_message_guid` points at another message — we don't compose context across rows in v0.
  - Edit/unsend acknowledged but NOT mitigated in v0: rows can mutate after read. Audit log records first-seen content; document this in README ("the audit log shows what we processed, not what's currently in chat.db").
  - Strict allowlist check happens **before** any further processing.
  - Sender handle validated against expected pattern (E.164 phone or Apple-ID email).

### S2. Allowlist bypass
- **Surface:** Sender-handle string from chat.db.
- **Threats:**
  - Handle normalization mismatch — `+15551234567` vs `5551234567` treated differently.
  - Hidden Unicode characters in stored handle.
  - Group chats containing the allowlisted user — bridge sees a message from the user, replies, reply goes to whole group (data leak).
- **Mitigations:**
  - Normalize handles before comparison (strip whitespace, lowercase email, E.164-fy phone).
  - **Refuse to reply in group chats by default**; opt-in per group GUID only.
  - On startup, log the resolved allowlist; require explicit confirmation in config file.

### S3. Prompt injection via message content
- **Surface:** Message body is passed as a prompt to the Claude SDK.
- **Threats:**
  - User (or attacker on allowlist) sends "ignore previous instructions, run X" — claude complies.
  - Exfiltration via tools claude has access to: Bash, WebFetch, Skill (transitively loads other tools), Agent (spawns subagents), ToolSearch (re-enables denied tools), etc.
  - Indirect injection: a later run sees content that came in via a prior attacker-influenced message.
- **Mitigations (verified empirically by selftest at every daemon startup):**
  - **`--disallowed-tools` is the real deny mechanism.** `--allowed-tools` is additive — it never denies anything. Bash, Read, Write, etc. are available in `claude -p` by default unless explicitly denied via `--disallowed-tools`. The bridge passes a comprehensive comma-separated list (`HARD_DISALLOWED` in `src/claude_runner.py`) covering filesystem, network, scheduling, skills, agents, and tool-loading capabilities.
  - **Default `allowed_tools` is `[]` (empty).** With nothing user-opted-in, every tool in `HARD_DISALLOWED` is denied. Pure text chat.
  - **Empirical startup selftest:** the daemon spawns one `claude -p` call before any user messages, asks claude to invoke Bash, and asserts no file is created. If Bash is actually executable for any reason (CLI version drift, flag semantics change), the daemon refuses to start (`selftest_bash_denied()` in `src/claude_runner.py`). This makes the security boundary verified-on-every-boot, not assumed.
  - **Hermetic invocation:** dedicated empty sandbox cwd (no CLAUDE.md inheritance), `--strict-mcp-config` + empty MCP file, `--max-turns N` cap, scrubbed env, `--` separator before prompt argv, `start_new_session=True` + process-group kill on timeout.
  - **Anti-fabrication system prompt:** explicit "you have NO tools, do not emit `<tool_call>` blocks, do not pretend to read files" injected via `--append-system-prompt`.
  - **No `--dangerously-skip-permissions`** anywhere in argv; `_assert_safe_argv` enforces.
  - **Per-call cost cap** (`per_call_cost_cap_usd`) suppresses oversized replies.
  - **Daily cost cap** (`daily_cost_cap_usd`) integer-cents accounting.
  - **Per-handle minute rate limit** atomic via SQL transaction.
  - **Circuit breaker** auto-PAUSEs after N consecutive failures.
  - If a user opts in to a tool (e.g. `Read` in `allowed_tools`), it is removed from the active disallow list for that invocation. Anything in `HARD_FORBIDDEN_TOOLS` cannot be opted into — config load refuses to start with those.
  - Document clearly: "This is a chat surface, not an automation surface."

### S4. AppleScript send injection
- **Surface:** Constructing AppleScript text to pass to `osascript`.
- **Threats:**
  - Reply text contains AppleScript-meaningful characters (quotes, backslashes) — could escape the literal and execute attacker-controlled script.
  - BiDi / zero-width / control characters in reply body could make Messages render text differently from what we logged ("display attack").
- **Mitigations:**
  - **Never build AppleScript strings via concatenation.** Use `osascript -e "$SCRIPT" -- ARG1 ARG2`; arguments are passed to the script's `on run argv` handler and are NOT shell-interpreted.
  - Message body is written to a `0o600`-permissioned tempfile and read inside the AppleScript via `do shell script "cat …"` — never inlined into the script source.
  - Validate handle matches strict regex (E.164 phone or email) before passing as argv.
  - Strip BiDi format chars (U+202A–U+202E, U+2066–U+2069), zero-width chars (U+200B–U+200D, U+FEFF), and C0/C1 control bytes from outgoing bodies. The user sees what we logged.
  - Cap reply length to 8 KB so an LLM-generated reply can't construct an exotic payload.

### S5. Bridge-as-bot abuse (outbound spam)
- **Surface:** Compromised bridge sends iMessages to user's contacts at attacker's direction.
- **Threats:**
  - If S3 succeeds, attacker can prompt Claude to "send to all my contacts: <phishing>."
- **Mitigations:**
  - The bridge can only reply *to the sender of the inbound message*. There is no API surface to send to other handles.
  - Tool allowlist excludes anything that could re-trigger the bridge's own send path.
  - Strict per-minute send rate limit; daemon refuses to send more than N replies/min to any contact.

### S6. Open-source-specific risks
- **Surface:** Public repository, public dependency declarations.
- **Threats:**
  - Committed secrets (API keys, real session ids, sample chat.db contents).
  - Vulnerability in published code becomes a 0-day for every user.
  - Dependency confusion / typo-squatting.
- **Mitigations:**
  - `.gitignore` covers `.env*`, `config.yaml`, `*.db`, `*.sqlite*`, `logs/`, `samples/`.
  - Pre-commit hook with `detect-secrets` (or equivalent) blocking commits that match known secret patterns.
  - SECURITY.md with private disclosure address.
  - Pin all dependency versions; minimum dependency surface (stdlib-first where possible).
  - GitHub Dependabot enabled on the repo.
  - Periodic `bandit`/`semgrep` scan in CI.

### S7. Supply chain
- **Surface:** Python packages we depend on.
- **Threats:**
  - Compromised PyPI package executes code on user's machine on install.
- **Mitigations:**
  - Stdlib-only where reasonable (sqlite3, plistlib, subprocess all stdlib).
  - Required third-party libs (if any) pinned by version + hash via `requirements.txt` with `--require-hashes`.
  - Document the dependency list in README; small enough to audit.

### S8. Local file leakage
- **Surface:** Logs may contain message bodies, session content, handles.
- **Threats:**
  - User shares logs publicly for debugging without realizing they contain private content.
  - Backup tools include logs.
- **Mitigations:**
  - Default log level redacts message bodies (logs only "received message from <handle>" not the body).
  - `--debug` flag opts into body logging but adds a runtime warning.
  - Logs go to `~/.claude-imessage-bridge/logs/` not project repo.

### S9. Confused-deputy / FDA abuse
- **Surface:** Daemon has Full Disk Access (required for chat.db).
- **Threats:**
  - A compromised daemon (via S3 or S7) has FDA, can read anything in `~/Library/` and beyond — Messages attachments folder with full media, all WAL artifacts, mail caches, browser cookies (if not protected by app-specific entitlements), etc.
- **Mitigations:**
  - Document the FDA grant scope prominently in README; user opts in knowingly.
  - Run as the user, never with elevated privileges.
  - The bridge code itself reads only `~/Library/Messages/chat.db` and writes only to `~/.claude-imessage-bridge/`. Audited via tests.
  - (NB: "code-sign the binary" was suggested in v0 of this doc but is misleading for a `pip install`-distributed Python project — no signable binary exists. Removed.)

### S10. Session-content leaks via iMessage
- **Surface:** `/sessions` and similar commands send session snippets back through iMessage.
- **Threats:**
  - iMessage history syncs across Apple ID devices, including ones the user might share (family iPad, etc.).
  - Snippet contains customer names, deal info, PII.
- **Mitigations:**
  - Config flag `redact_snippets_in_listings` defaults to a conservative truncation.
  - `/sessions` shows only the snippet, never the full session body, by default.
  - To dump full session content over iMessage requires an explicit `/dump` opt-in command — not built in v0.

## Residual risks (accepted)

1. **The user can ask the bridge to do destructive things in their own work directory.** If the user types "delete all my files," the bridge could comply (within tool allowlist). We accept this — this is the user's authority over their own environment, not a security flaw.
2. **Apple ID compromise = bridge compromise.** If an attacker takes over the user's iCloud account, they can message the bridge as the user. We accept this; the user's account hygiene is their responsibility.
3. **Physical access to the Mac.** Outside scope.
4. **Claude API compromise** (Anthropic-side). Outside scope.
5. **Session-resume inherits the resumed session's tool authority.** `claude --resume <id>` against a session that has Gmail, Slack, Drive, computer-use, etc. MCPs configured gives the resumed conversation the same authority. An attacker who can drive the bridge (via Apple ID compromise or by being on the allowlist) inherits whatever the resumed session inherited. **We accept this as equivalent to laptop/Claude-login compromise.** Users with rich personal Claude setups should be aware and only use `/use` against sessions whose authority scope they're comfortable exposing.

   Future hardening options (not in v0): an "iMessage-exposed" session class with a marker file the bridge can filter on; per-tool confirmation round-trip before sensitive actions.

## Pre-public-release gates

- [ ] Independent adversarial review of this threat model (one Claude agent)
- [ ] Independent code review of every shipped phase
- [ ] `detect-secrets`, `bandit`, `pip-audit` clean
- [ ] README documents permissions clearly (FDA, Automation)
- [ ] SECURITY.md with disclosure address
- [ ] At minimum 1 week of soak under real load on author's machine before tagging v0.1
- [ ] Explicit `WARNING: research preview` in README until at least one external user has used it
