# claude-imessage-bridge — Threat Model

**Status:** Post-Phase-C, post-round-3 adversarial review. Resynced in Phase D
to describe shipped mitigations, not the v0 design. Subject to a final
independent adversarial review before any public release.

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
  - `attributedBody` (binary plist) parsing exploits — Apple-format complexity, sender-controlled fields (display name, contact card, link preview).
  - Sender-handle spoofing via SMS-relayed-through-iMessage gateways.
  - Edit/unsend mutation of rows after first read (iOS 16+ feature).
  - Attachments table, balloon-bundle apps (Apple Pay, Polls, Animoji) with attacker-controlled metadata in attributedBody.
  - Tapbacks (reactions) reading as text in isolation, stripping context.
- **Mitigations (shipped, see `src/imessage_reader.py`):**
  - SQLite opened **read-only** (`?mode=ro` only — NOT `immutable=1`; chat.db is written to continuously by Apple's `imagent`, and the `immutable` flag would cause stale/corrupt reads).
  - **Filter to `handle.service = 'iMessage'` only** at the SQL layer. Drop SMS-routed rows entirely. SMS caller-ID is trivially spoofable; iMessage is cryptographically authenticated by Apple. This single filter closes the spoofing attack on phone-number allowlist entries.
  - Hard cap on message body length (`MAX_BODY_BYTES = 16 KB`). Bodies above this are truncated on a UTF-8 boundary; truncation flag rides on the `Message` dataclass so downstream code can react.
  - `attributedBody` parsed with stdlib `plistlib` only — no third-party parsers. Hard 256 KB cap on the blob before parsing (`MAX_ATTRIBUTED_BODY_BYTES`). The extractor refuses any archive whose `$class` set includes anything outside an allowlist of "boring" NSAttributedString-family classnames (so rich content — mentions, link previews, contact cards — can't smuggle attacker-controlled fields in via `attributedBody`). Any plistlib exception is caught and logged, never raised.
  - SQL-layer filters drop `associated_message_guid IS NOT NULL` (tapbacks/edits), `is_emote = 1` (expressive effects), `item_type != 0` (participant-add/leave events), `balloon_bundle_id IS NOT NULL` (Apple Pay, Polls, Digital Touch, third-party iMessage apps), and `cache_has_attachments = 1` (attachment-bearing rows whose text column is often U+FFFC noise).
  - Edit/unsend acknowledged but NOT mitigated in v0: rows can mutate after read. Audit log records first-seen content; document this in README ("the audit log shows what we processed, not what's currently in chat.db").
  - Strict allowlist check happens **before** any further processing.
  - Sender handle validated against expected pattern (E.164 phone or Apple-ID email) via `imessage_sender.validate_handle`.

### S2. Allowlist bypass
- **Surface:** Sender-handle string from chat.db.
- **Threats:**
  - Handle normalization mismatch — `+15551234567` vs `5551234567` treated differently.
  - Hidden Unicode characters in stored handle.
  - Group chats containing the allowlisted user — bridge sees a message from the user, replies, reply goes to whole group (data leak).
- **Mitigations:**
  - `validate_handle` enforces a strict regex: E.164 phone (`^\+[1-9]\d{6,14}$`) or `local@domain` email. No whitespace, no Unicode escapes, no `0`-prefixed phones. Emails are lowercased before comparison; phones are compared verbatim.
  - **Group chats are refused by default.** A group chat (`chat.style = 43`) only gets a reply if its GUID is in `allow_group_chat_guids` — an explicit opt-in. The default config has this empty.
  - The allowlist is loaded once at startup; every entry is normalized through `validate_handle`. Any entry that doesn't normalize causes the daemon to refuse to start (the user fixes the config rather than getting silent partial coverage).

### S3. Prompt injection via message content
- **Surface:** Message body is passed as a prompt to the Claude SDK.
- **Threats:**
  - User (or attacker on allowlist) sends "ignore previous instructions, run X" — claude complies.
  - Exfiltration via tools claude has access to: Bash, WebFetch, Skill (transitively loads other tools), Agent (spawns subagents), ToolSearch (re-enables denied tools), etc.
  - Indirect injection: a later run sees content that came in via a prior attacker-influenced message.
  - Argument injection: a message body starting with `--something` getting reparsed as a CLI flag by claude.
- **Mitigations (shipped, see `src/claude_runner.py`):**
  - **`--disallowed-tools` is the real deny mechanism.** This was the critical finding from round-3 adversarial review: `--allowed-tools` is additive only — it never denies anything. `--tools ""` is a no-op despite the help text suggesting otherwise (verified empirically). Bash, Read, Write, etc. are available in `claude -p` by default unless explicitly denied via `--disallowed-tools <csv>`. The bridge passes a comprehensive comma-separated list (`HARD_DISALLOWED` in `src/claude_runner.py`) covering filesystem read/write/exec, network egress, scheduling, skills, agents, tool-loading, communication/out-of-band, plan/task/state modes, and MCP introspection.
  - **Default `allowed_tools` is `[]` (empty).** With nothing user-opted-in, every tool in `HARD_DISALLOWED` is denied. Pure text chat.
  - **Empirical startup selftest:** the daemon spawns one `claude -p` call before any user messages, asks claude to invoke Bash to write a canary file, and asserts no file is created. If Bash is actually executable for any reason (CLI version drift, flag semantics change, tool rename), the daemon refuses to start (`selftest_bash_denied()` in `src/claude_runner.py`, called from `daemon.main` immediately after preflight). The canary path is in a fresh `tempfile.TemporaryDirectory` whose name is unguessable, so a malicious model can't pre-create it elsewhere.
  - **Per-call hermetic sandbox:** every `run_claude` call creates a fresh `tempfile.TemporaryDirectory(prefix="cimb-call-")` and uses it as the child's cwd. This means:
    - The user's global `~/.claude/CLAUDE.md`, `.mcp.json`, skills, and `settings.json` do NOT load (cost dropped from $0.10 to $0.044 in verification testing).
    - There's no persistent sandbox directory between calls — nothing for an attacker to drop a `.mcp.json` or `CLAUDE.md` into between invocations.
    - The empty MCP config is written into the per-call tempdir using `os.open` with `O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW` (mode 0o600), so an attacker can't pre-create the path as a symlink to `~/.ssh/authorized_keys` and clobber it (`O_NOFOLLOW` refuses to open through a symlink; `O_EXCL` refuses if the path exists at all).
  - **`--strict-mcp-config` + empty MCP file** prevents MCP server discovery and startup (no Gmail/Slack/Drive process inheritance).
  - **Anti-fabrication system prompt** injected via `--append-system-prompt`: "you have NO tools, do not emit `<tool_call>` blocks, do not pretend to read files or run commands." Caught the observed pattern of the model emitting fabricated tool-call output when all tools are denied.
  - **`--` separator** placed immediately before the prompt argv. Prevents a body starting with `--` from being reparsed as additional CLI flags. `_assert_safe_argv` rejects any argv containing `--dangerously-skip-permissions`, `--bypass-permissions`, `--no-permissions`, `--permission-mode=bypassPermissions`, or `--permission-mode=acceptEdits` (exact or `=value` prefix forms).
  - **`--max-turns N`** (default 1) hard cap on per-call agent loop.
  - **Per-call cost cap** (`per_call_cost_cap_usd`, default $0.50, integer-cents math) suppresses oversized replies AFTER spend is already accounted for. The reply itself is dropped (the model may have spent the budget producing the very payload that ran up the bill).
  - **Daily cost cap** (`daily_cost_cap_usd`, default $5.00, integer-cents math in the `daily_cost` table, UTC bucket). Once met, claude isn't invoked at all that UTC day; the user gets a clear message.
  - **Per-handle minute rate limit** is atomic at the SQL layer: `reserve_reply_slot` does `INSERT ON CONFLICT DO UPDATE SET n=n+1`, reads back, conditionally rolls back if over the limit. No TOCTOU window between "is it under the limit?" and "I'm consuming a slot."
  - **Circuit breaker** auto-creates a `PAUSE` file after `circuit_breaker_failures` consecutive Claude failures (default 5). The daemon idles until the operator removes the file.
  - **Scrubbed child environment** — only `PATH`, `HOME`, `USER`, `LANG`, `LC_ALL`, `ANTHROPIC_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN` cross into the child. No `TMPDIR` inheritance (attacker-controlled `TMPDIR` could be a symlink ladder); claude defaults to `/tmp`. Only one OAuth env path is honored (avoids account confusion if both `ANTHROPIC_AUTH_TOKEN` and `CLAUDE_CODE_OAUTH_TOKEN` are set).
  - **`start_new_session=True`** at spawn + process-group kill on timeout — Node MCP children spawned by claude can't survive as orphans. `_kill_process_group` re-checks `proc.poll()` before each kill and resolves `pgid` via `os.getpgid(proc.pid)` to avoid PID-reuse races where the kernel has reassigned `proc.pid` to an unrelated process.
  - **Opt-in tools are filtered through `HARD_FORBIDDEN_TOOLS`** at config-load time. A user trying to set `allowed_tools: [Bash]` gets a config error; the daemon refuses to start. MCP-namespaced tools (`mcp__*`) are similarly rejected — the bridge can't vet their capabilities.
  - Document clearly: "This is a chat surface, not an automation surface."

### S4. AppleScript send injection
- **Surface:** Constructing the argv passed to `osascript`. The reply body is generated by Claude and contains arbitrary text.
- **Threats:**
  - Reply text contains AppleScript-meaningful characters (quotes, backslashes) — if interpolated into AppleScript source, could escape the literal and execute attacker-controlled script.
  - UTF-8 mojibake / encoding mangling if the body is round-tripped through `do shell script "cat"` (Mac Roman vs UTF-8). This was a real finding in round-2 review.
  - BiDi / zero-width / control characters in reply body could make Messages render text differently from what we logged ("display attack").
  - PATH shadow on `osascript` — `~/bin/osascript` intercepting the send.
- **Mitigations (shipped, see `src/imessage_sender.py`):**
  - **Argv-only AppleScript.** We never build AppleScript source via concatenation, and we do NOT use the `do shell script "cat <tempfile>"` pattern from earlier drafts. The script is a fixed literal containing `on run argv ... item 1 of argv ... item 2 of argv`. Arguments are passed via `osascript -e SCRIPT -- handle body`, which delivers them to `on run argv` as already-parsed UTF-8 NSStrings. No shell, no source-level interpolation, no Mac Roman conversion.
  - `osascript` is pinned to `/usr/bin/osascript` (`_OSASCRIPT_BIN`). A `$PATH` shadow can't intercept the send path. Preflight verifies the binary exists at the pinned path.
  - **Handle is strict-validated** by `validate_handle` BEFORE going into argv (E.164 phone or `local@domain` email regex; nothing else). A malicious sender can't smuggle a payload through their own handle.
  - **Body is run through `_strip_display_attacks`** before send. Removes BiDi format chars (U+202A–U+202E, U+2066–U+2069), zero-width chars (U+200B–U+200D, U+FEFF), and C0/C1 control bytes (preserving `\t \n \r`). What the recipient sees matches what we logged.
  - **Body is capped at `MAX_REPLY_BYTES = 8 KB`** on a UTF-8 boundary, with a `…[truncated]` marker appended. Defense-in-depth size cap plus a UX bound (iMessage truncates very long messages anyway).
  - `subprocess.run` is called with a list argv (never `shell=True`), `timeout=15`, and `capture_output=True` so stderr can be inspected without stdout-mixing.

### S5. Bridge-as-bot abuse (outbound spam)
- **Surface:** Compromised bridge sends iMessages to user's contacts at attacker's direction.
- **Threats:**
  - If S3 succeeds, attacker can prompt Claude to "send to all my contacts: <phishing>."
- **Mitigations:**
  - The bridge can only reply *to the sender of the inbound message*. There is no API surface to send to other handles; `_handle_one` builds the `SendRequest` with `handle=norm` (the normalized sender).
  - The default `HARD_DISALLOWED` denies every tool that could re-trigger the bridge's send path (no `Bash`, no `Skill`, no `Agent`, no MCPs, no `RemoteTrigger`, no `PushNotification`).
  - **Strict per-minute send rate limit** is enforced before claude is even invoked (`reserve_reply_slot`, atomic). Reservation is rolled back if denied so other callers see accurate state. Default 10 replies/min per handle.
  - The daily cost cap bounds total spend even if rate-limit is somehow saturated all day.

### S6. Open-source-specific risks
- **Surface:** Public repository, public dependency declarations.
- **Threats:**
  - Committed secrets (API keys, real session ids, sample chat.db contents).
  - Vulnerability in published code becomes a 0-day for every user.
  - Dependency confusion / typo-squatting.
- **Mitigations:**
  - `.gitignore` covers `.env*`, `config.yaml`, `state.db`, `*.sqlite*`, `logs/`, `samples/`, `chat.db`.
  - Pre-commit hook with `detect-secrets` (planned in Phase D CI).
  - SECURITY.md with private disclosure address.
  - Pin all dependency versions; minimum dependency surface (stdlib-first where possible; only `pyyaml` is third-party).
  - GitHub Dependabot enabled on the repo.
  - Periodic `bandit` + `pip-audit` scan in CI (Phase D).

### S7. Supply chain
- **Surface:** Python packages we depend on.
- **Threats:**
  - Compromised PyPI package executes code on user's machine on install.
- **Mitigations:**
  - Stdlib-only where reasonable (`sqlite3`, `plistlib`, `subprocess`, `tempfile`, `os` all stdlib).
  - Single third-party dep: `pyyaml`. Version-pinned in `pyproject.toml`.
  - Document the dependency list in README; small enough to audit.

### S8. Local file leakage
- **Surface:** Logs and state.db may contain message bodies, session content, handles.
- **Threats:**
  - User shares logs publicly for debugging without realizing they contain private content.
  - Backup tools include logs or state.db.
- **Mitigations:**
  - **Audit log NEVER contains raw bodies.** The `audit` row's `detail` field carries the classification reason (e.g., `sender-not-allowlisted`, `rate-limited`, `cmd=/sessions`), the command name, or a structured summary (`ok dur=1234ms cost_cents=5 sid=abc12345`). Raw body content is never persisted, even in debug mode.
  - **`--debug` opts into body logging — to stderr only.** Bodies are emitted at WARNING level so the user sees a runtime hint that bodies are being printed. They never reach state.db.
  - **User-facing error messages strip internal detail.** `_user_facing_error` returns one of four canned strings keyed off `error_category`. The original error string (which may contain file paths, MCP server names, traceback fragments) and the consecutive-failure count (which leaks the circuit-breaker threshold to a probing attacker) are logged server-side only.
  - state.db is created mode 0o600 inside a 0o700 directory. If it exists at startup with looser perms, the daemon tightens it and logs a warning.
  - Logs go to `~/.claude-imessage-bridge/logs/` (planned), not the project repo.
  - **`status.json` health sidecar** (`src/health.py`, Phase D) is written next to state.db every heartbeat. Atomic write via `tempfile.mkstemp` + `os.chmod(0o600)` + `os.replace`; tmp-file cleanup via `try/finally` so non-OSError exceptions (MemoryError, KeyboardInterrupt) don't leave `.status.*.tmp` orphans. The file contains: schema version, ts, pid, cursor, paused flag, stop-requested flag, consecutive-failure count, daily cost cents, daily cap, DB schema version, metrics counter snapshot. **No raw bodies, no session ids, no handles.** The metrics block uses non-PII labels (`msgs_in`, `replies`, `drops_<reason>`). The `consecutive_failures` field surfaces the circuit-breaker counter — a hostile local process with FDA can read it and infer breaker proximity, but FDA-local is already game-over territory per S9.

### S9. Confused-deputy / FDA abuse
- **Surface:** Daemon has Full Disk Access (required for chat.db).
- **Threats:**
  - A compromised daemon (via S3 or S7) has FDA, can read anything in `~/Library/` and beyond — Messages attachments folder with full media, all WAL artifacts, mail caches, browser cookies (if not protected by app-specific entitlements), etc.
  - State-corruption attacks: dropping a symlink at state.db path so a backup-restore overwrites a target file.
  - State-replay attacks: restoring an older state.db to reprocess already-handled messages.
- **Mitigations:**
  - Document the FDA grant scope prominently in README; user opts in knowingly.
  - Run as the user, never with elevated privileges.
  - The bridge code itself reads only `~/Library/Messages/chat.db` and writes only to `~/.claude-imessage-bridge/`. Audited via tests.
  - **`claude_binary` is validated** at config load (`_validate_claude_binary`): symlink chain is resolved; resolved target must be a regular file owned by root or the current uid; not group/world writable; parent directory and each directory on the symlink chain must not be group/world writable. Homebrew installs (symlink → Cellar) are accepted; an attacker swapping the symlink mid-chain is refused.
  - **state.db symlink refusal**: preflight checks `(state_dir / "state.db").is_symlink()` and refuses to run if true.
  - **Cursor regression guard**: `set_cursor` refuses to move a cursor strictly backward unless `allow_regression=True` is passed explicitly. Protects against a restored backup of state.db replaying historical messages. The operator must use `--reset-cursor` to acknowledge the regression.
  - (NB: "code-sign the binary" was suggested in v0 of this doc but is misleading for a `pip install`-distributed Python project — no signable binary exists. Removed.)

### S10. Session-content leaks via iMessage
- **Surface:** `/sessions`, `/use`, `/status` commands send session snippets back through iMessage.
- **Threats:**
  - iMessage history syncs across Apple ID devices, including ones the user might share (family iPad, etc.).
  - Snippet contains customer names, deal info, PII.
- **Mitigations:**
  - `/sessions` shows only the snippet (first ~60 chars of last user message), never the full session body. `/status` shows ~120 chars of the resumed session's last user message.
  - The numbered list survives at most `LAST_OPTIONS_TTL_SECONDS = 30 min` — a later `/pick` against a stale list returns "list aged out, run /sessions again" rather than resuming silently.
  - The bridge does not surface anything but `claude --resume <id>`'s reply. There is no `/dump` command that would emit transcript bodies.
  - README and config example flag this risk loudly; users with family-shared Apple IDs are told to use a dedicated Apple ID.

## Residual risks (accepted)

1. **The user can ask the bridge to do destructive things in their own work directory.** If the user types "delete all my files," the bridge could comply (within tool allowlist). We accept this — this is the user's authority over their own environment, not a security flaw. With the default `allowed_tools: []`, nothing destructive is even possible.
2. **Apple ID compromise = bridge compromise.** If an attacker takes over the user's iCloud account, they can message the bridge as the user. We accept this; the user's account hygiene is their responsibility.
3. **Physical access to the Mac.** Outside scope.
4. **Claude API compromise** (Anthropic-side). Outside scope.
5. **Edit/unsend on chat.db rows.** An attacker who can edit a sent message after we read it can produce an "audit says X, current chat says Y" gap. Documented; not mitigated. The audit row records first-seen content.
6. **Session-resume inherits the resumed session's tool authority.** `claude --resume <id>` against a session that has Gmail, Slack, Drive, computer-use, etc. MCPs configured gives the resumed conversation the same authority. An attacker who can drive the bridge (via Apple ID compromise or by being on the allowlist) inherits whatever the resumed session inherited. **We accept this as equivalent to laptop/Claude-login compromise.** Users with rich personal Claude setups should be aware and only use `/use` against sessions whose authority scope they're comfortable exposing.

   Note: even on resume, the bridge's `--disallowed-tools` still applies. So a resumed session that previously called Bash will NOT be able to call Bash from inside the bridge — the bridge's per-call deny list takes precedence over the resumed session's prior tool history. The risk is purely about the transcript content (which the resumed session sees) and any session-scoped MCP authority the model might attempt to re-engage if the bridge's deny list ever drifts.

   Future hardening options (not in v0): an "iMessage-exposed" session class with a marker file the bridge can filter on; per-tool confirmation round-trip before sensitive actions.

7. **Cost-exhaustion within caps.** An allowlisted attacker can burn the daily cap in roughly 60 seconds at the default 10 replies/min rate-limit and ~$0.044/call hermetic cost. Bounded loss, acknowledged. Lowering `daily_cost_cap_usd` or `reply_rate_limit_per_minute` is the user's lever.

8. **Per-message `cost_cents` in audit_log is a coarse length side-channel.** Per-row `cost_cents` (Phase D schema v1) correlates with prompt+reply token count, which correlates with content length. An attacker who exfiltrates state.db sees a column they can sort to identify "the long one" / "the data dump" etc. Combined with timestamps this is a re-identification side channel for what got discussed. We accept the trade-off: bucketing or zeroing the column would destroy the spending-forensics queries that are the column's reason to exist (see `docs/AUDIT_LOG_COOKBOOK.md`). state.db is already documented as sensitive (S8); the user controls its exposure.

9. **`_redact_handle` preserves the email domain verbatim.** `sa***@example.com` masks the local-part but keeps the domain. Rare or unique domains make this re-identifying. We accept the trade-off because the operator needs to read their own audit log to map redacted handles back to contacts; hashing the domain breaks that. Users on shared or company domains get more redaction than users on personal domains — a known asymmetry.

10. **Selftest verifies Bash specifically, not every other denied tool.** `selftest_bash_denied` checks the load-bearing case. A future Claude Code release that selectively allows e.g. `Write` while keeping Bash denied would slip through. The selftest is intentionally narrow to keep cost and runtime predictable; the rest of the deny list relies on `--disallowed-tools` semantics holding. If you suspect drift, extend the selftest before opting any new tool into `allowed_tools`.

## Pre-public-release gates

- [x] Round-3 independent adversarial review of code (closed all Tier 1 findings)
- [x] Hermetic per-call invocation verified (chat.db reader + sender + runner all live-tested)
- [x] Threat model resynced to ship state (this doc, Phase D)
- [ ] Test suite covering security-boundary modules (Phase D)
- [ ] `bandit -q -r src/`, `pip-audit`, `detect-secrets scan` clean in CI (Phase D)
- [ ] README documents permissions, family-Apple-ID risk, FDA scope, no-listener-but-outbound-traffic (already done; verify post-Phase-D)
- [ ] SECURITY.md disclosure address + triage SLOs (Phase D)
- [ ] Final independent adversarial + solver review pair on Phase D (last gate)
- [ ] At minimum 1 week of soak under real load on author's machine before tagging v0.1
- [ ] Explicit `WARNING: research preview` in README until at least one external user has used it
