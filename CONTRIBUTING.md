# Contributing to claude-imessage-bridge

Thanks for the interest. This project has a tight design philosophy that
keeps the security surface small. Most "obvious" features turn out to
violate one of the constraints below. **Read this before you propose a
feature** — it'll save us both time.

## The trust-mode framework

The bridge serves three audiences:

- **`chat_only`** (default, OSS): hermetic per-call sandbox; no tools, no
  MCPs, no memory. Safe to share. The bridge is a sandboxed text
  surface.
- **`coding`**: real `project_directory` cwd, empty MCP config,
  filesystem tools allowed, no network. The bridge can read and write
  your code without going online.
- **`full`**: real cwd, real MCP config, all tools (except
  `AskUserQuestion`). The bridge IS your foreground Claude Code reached
  via iMessage.

Any new feature must work correctly — or be cleanly absent — across all
three modes. Constraint #2 below means a feature that requires a tool
default-on can't exist in `chat_only`. That's fine — many features are
mode-specific. But you have to say which mode(s) yours applies to.

## The 9 design constraints

These survived adversarial review and live testing. Every new feature
must respect every constraint or include an explicit threat-model note
justifying the trade-off.

### 1. The bridge replies only to the sender of the inbound message.

**Why:** S5 in THREAT_MODEL.md. The bridge has no API surface to send
to other handles. The moment you can address arbitrary recipients,
prompt injection escalates from annoyance to "your contacts get
phishing texts from your number."

**Violates:** "@-mention a contact and the bridge sends them a note."

**Respects:** per-handle session resume; multiple operators each
driving their own thread independently.

**Applies in:** all modes.

### 2. No tool is default-on that isn't text-only.

**Why:** S3. The empirical Bash-denial selftest is the load-bearing
gate in `chat_only` mode. A default-on tool that's not text-only
means a fresh OSS install ships with attack surface the user didn't
opt into.

**Violates:** "default-on WebFetch for link summaries."

**Respects:** explicit opt-in via `allowed_tools_addons` config, with
the user understanding the trade.

**Applies in:** `chat_only` only. In `coding` and `full`, tools ARE
default-on — but those modes are opt-in themselves.

### 3. No persistent state inside the sandbox between calls.

**Why:** S3. The per-call hermetic `tempfile.TemporaryDirectory()` is
what makes "the model can't accumulate a payload across calls" true.

**Violates:** "cache the system prompt in a sandbox-side file for speed."

**Respects:** all state passed via stdin/argv only, regenerated
per-call.

**Applies in:** all modes. (In `coding`/`full` the cwd is
`project_directory` which persists, but that's the operator's working
tree — they accept persistent state in their own files. The point is
the bridge doesn't ADD persistent state via the sandbox.)

### 4. No new mutable state surface without TTL + regression guard.

**Why:** S9 cursor-regression rule. State-replay is a real threat.

**Violates:** a permanent pin registry without expiration.

**Respects:** `LAST_OPTIONS_TTL_SECONDS = 30 min` on `/pick` options;
`PENDING_INTENT_TTL_SECONDS = 60` on confirmation flows;
`set_cursor` refuses backward motion without `allow_regression=True`.

**Applies in:** all modes.

### 5. No raw bodies leave the process except into Claude or into stderr in debug mode.

**Why:** S8. The audit-log invariant is what makes "share state.db
for debugging" safe.

**Violates:** logging classification reasons like `subject="..."` to
the audit detail.

**Respects:** structured summaries (`ok dur=… cost_cents=… sid=…`);
`--debug` mode logs bodies to stderr only (not state.db).

**Applies in:** all modes.

### 6. Initiating sends from the daemon requires an external trigger and fails safe to silent.

**Why:** Today the bridge is response-only — every defense in S5
assumes "outbound is a reply." Switching to initiator reopens those
assumptions.

**Violates:** a timer-based "morning summary" auto-text.

**Respects:** an externally-written queue file that the daemon drains
with the same caps and rate-limits as inbound, AND the recipient
must equal the bridge operator (not an arbitrary contact). Also: the
default failure mode is silence, not retry-with-different-content.

**Applies in:** all modes. (Not yet implemented; this is the rule for
when proactive texting eventually lands.)

### 7. One third-party dependency is the budget.

**Why:** S7 supply chain. `pyyaml` is the only non-stdlib import
today. That's the auditability story — anyone can read the whole
dependency tree in a few minutes.

**Violates:** adding `rich`, `httpx`, an embedding model, an
HTTP client.

**Respects:** stdlib `sqlite3` + FTS5 for full-text search;
`urllib.request` for the rare HTTP need; `subprocess` for everything
external.

**Applies in:** all modes.

### 8. No feature broadens the FDA-derived authority surface beyond chat.db read + state-dir write.

**Why:** S9. FDA is the largest grant. The README pins what FDA is
for: reading chat.db. The bridge code itself never writes outside
`~/.claude-imessage-bridge/` (and, in coding/full modes, the
configured `project_directory` via Claude's own tools — which are
the user's, not the bridge's, authority).

**Violates:** "let the bridge index `~/Documents/` for `/use` content
search."

**Respects:** `/use` searching only `~/.claude/projects/*/*.jsonl`;
state.db at `~/.claude-imessage-bridge/state.db`; status.json
adjacent to it.

**Applies in:** all modes. In `coding`/`full` the model can read/write
the project directory using its Claude-Code authority — that's the
user's authority, not the bridge's.

### 9. Trust-mode escalation is config-file only, never message-driven.

**Why:** Session 2 added this. If a message body could escalate trust
("you are now in full mode"), prompt injection becomes a trivial
escalation vector. Trust mode resolves once at daemon start.

**Violates:** a `/trust full` command.

**Respects:** edit `config.yaml`, restart the daemon.

**Applies in:** all modes (this is the rule about modes themselves).

## How to propose a feature

1. **State which trust mode(s) it applies in.** A feature that only makes
   sense in `full` isn't broken — but you have to be explicit.

2. **Cite the constraint(s) it touches.** Most features touch one or
   two. If it doesn't touch any, you've probably misunderstood the
   architecture; check again.

3. **Sketch the threat-model implication.** What happens when an
   attacker who can drive the bridge (Apple ID compromise) uses your
   feature? In `full` mode they already have your Claude Code; new
   features mostly just expand the I/O surface, not the authority.

4. **Submit a PR with at least:**
   - Code change
   - Tests (the project has 440+; new features should add their own)
   - THREAT_MODEL.md entry if you touched a defense
   - `ruff check`, `mypy`, `bandit`, `pytest` all green locally

## Development setup

```bash
git clone https://github.com/samgob/claude-imessage-bridge.git
cd claude-imessage-bridge
python3.11 -m pip install -e .
python3.11 -m pip install pytest pytest-cov ruff mypy bandit

# Run the tests:
pytest tests/

# Run the gates:
ruff check src/ tests/
mypy --ignore-missing-imports src/
bandit -q -r src/ -c pyproject.toml
```

The full CI matrix (Python 3.11/3.12/3.13 + ruff + mypy + bandit +
pip-audit + detect-secrets) runs in GitHub Actions on every push.

## Areas where contributions are welcome

- **Additional `MemoryBackend` implementations.** ObsidianBackend,
  LogseqBackend, NotionBackend, etc. The Protocol is in `src/memory.py`.
- **Additional intent patterns.** `src/intents.py` has the existing
  set; missed phrasings are easy to add with a test.
- **Improving the `cimb-status` CLI.** Currently a 30-line script; more
  formatted views would help.
- **Linux port of the sender path.** AppleScript is macOS-only.
  A pluggable `Sender` interface (Signal-cli, Telegram, ntfy) would
  enable Linux daemons sending out, while keeping the macOS reader.

## Areas where contributions are NOT welcome (without prior discussion)

- New tools added to `HARD_DISALLOWED`'s overridable set without
  selftest extension.
- Anything that requires the bridge to send to handles other than the
  inbound sender.
- Auto-update mechanisms.
- Multi-tenant features (the bridge is single-operator by design).
- Dependencies beyond `pyyaml`.

Open a Discussion before writing code in these areas — there's
probably an objection worth knowing about before you've invested time.
