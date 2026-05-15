# Post-compact recovery plan — bridge loop fixes

**Created:** 2026-05-15
**Context:** Sam's bridge looped overnight in trust=full mode. Spent
$4.01 of the $5/day cap before the cap stopped it. Daemon is currently
killed (`pkill -f "src.daemon"` confirmed). DO NOT restart until these
fixes land.

## Latest known-good commit

`3ab87cf feat(daemon): permission relay — surface blocked edits to user for approval`

All fixes below build on top of this.

## What happened — diagnostic from the live run

Heartbeat metrics at end of run:
```
cost_cents=401 msgs_in=33 replies=14 cmd_replies=3
intent_pending_confirmation=3 intent_implicitly_cancelled=2
intent_executed_readonly=2 daily_cap_hits=4 rate_limit_hits=8
self_send_echoes_skipped=1
```

Two distinct bugs, both contributed:

### Bug A — Echo dedupe silently failed

Only **1 of ~14 outbound replies** got caught by the echo dedupe. iCloud
synced bridge replies back as `is_from_me=0` rows; dedupe should have
matched them; didn't. Likely cause: iMessage normalizes some chars
between send and sync-back (smart-quote autocorrect, link autodetection,
etc.), so the bytes the bridge recorded don't byte-match the bytes
iCloud delivered. Probably exacerbated by the 🔒 emoji or long file
paths in the permission-relay paraphrase.

### Bug B — 60s pending-intent TTL too short

I set `PENDING_INTENT_TTL_SECONDS = 60`. Real iMessage cadence is
minutes, not seconds. Sam took longer than 60s to reply "Yes" to the
permission-relay prompt → pending expired → "Yes" went to Claude as a
fresh message → Claude in trust=full resumed the session and asked
clarifying questions ("Did you write to the logs?") → those questions
echoed via iCloud, weren't deduped (Bug A), entered Claude again as
new prompts → loop.

### Bug C — attributedBody warnings flooded the log

Separate from the loop but compounded the symptom. In
`src/imessage_reader.py::fetch_new_messages`, when a row has
unparseable `attributedBody` AND empty `text` column, the iterator
`continue`s without yielding. The daemon advances cursor only for rows
it sees. If N consecutive rows all hit this skip condition, the cursor
stays at the value before them — every 3-second poll re-reads them and
re-logs the warning. Today's run hit ~25 such rows in a row, producing
~25 warnings per poll forever.

## The four fixes (in priority order)

### Fix 1 — Cursor-advance-on-skip (Bug C, easy, high impact)

**File:** `src/imessage_reader.py`, function `fetch_new_messages`.

**Current behavior:**
```python
for row in rows:
    body, truncated, warning = _row_body(row)
    if not body.strip():
        continue  # ← skips silently; daemon never sees this rowid
```

**New behavior:** yield a `Message` with empty body + an `<empty-skip>`
sender handle. The daemon's existing `_decide` path will reject it as
`invalid-handle-format`, audit it, and advance the cursor. No more
re-reading.

Also downgrade the `attributedBody plist parse failed` log from
WARNING to DEBUG — these are common-and-expected for newer iMessage
formats. The yield-as-skip path means we don't need the warning to be
loud to spot stuck cursors anymore.

**Test:** add a fake chat.db row with unparseable attributedBody + empty
text. `fetch_new_messages` should yield it (so cursor advances) but the
daemon should drop it as invalid-handle.

### Fix 2 — Bump PENDING_INTENT_TTL_SECONDS to 15 minutes (Bug B)

**File:** `src/state.py`, constant `PENDING_INTENT_TTL_SECONDS`.

```python
PENDING_INTENT_TTL_SECONDS = 60 * 15  # was 60
```

**Rationale:** 60s assumed a "computer-paced" confirmation cadence.
Reality is "phone messaging" cadence — minutes between messages is
normal. 15 minutes is generous without being so long that stale
confirmations leak into unrelated sessions.

**Existing tests:** `test_pending_intent_ttl_expires` uses
`PENDING_INTENT_TTL_SECONDS + 5` for the backdate, so the test
auto-adapts. No test breakage.

### Fix 3 — Harden echo dedupe (Bug A)

**File:** `src/daemon.py`, functions `_body_digest`, `_is_recent_self_send`.

**Current hash:** `sha256(body.utf-8).hexdigest()[:16]` — exact-bytes match.

**New hash:** normalize body before hashing.
- Collapse internal whitespace runs to single spaces
- Strip trailing whitespace
- Replace smart-quote variants (`'` `'` `"` `"` `–` `—`) with their
  ASCII equivalents
- Lowercase (already mostly safe; emoji case-fold to themselves)

```python
_QUOTE_NORMALIZE = str.maketrans({
    "‘": "'", "’": "'",  # curly singles
    "“": '"', "”": '"',  # curly doubles
    "–": "-", "—": "-",  # en/em dash → hyphen
})

def _normalize_for_dedupe(body: str) -> str:
    s = body.translate(_QUOTE_NORMALIZE)
    s = " ".join(s.split())  # collapse whitespace
    return s.strip().lower()

def _body_digest(body: str) -> str:
    return hashlib.sha256(
        _normalize_for_dedupe(body).encode("utf-8", errors="replace")
    ).hexdigest()[:16]
```

Also add a metric: `_metrics["self_send_echo_hash_miss"]` — incremented
when a body matches our recent-sends list by HANDLE but not by hash.
Helps diagnose whether normalization is enough or whether iMessage is
doing something we haven't accounted for.

Actually scratch that — without an alternative match heuristic, we
can't tell "hash miss" from "legitimately new message." Skip the
hash-miss metric for now; rely on the heartbeat
`self_send_echoes_skipped` count as the signal. If it stays
near-zero after this fix, we know dedupe is still broken and need a
different approach (rowid-based via chat.db `guid` column probably).

**Test:** `test_dedupe_handles_smart_quotes`,
`test_dedupe_handles_whitespace_variation`,
`test_dedupe_handles_case_difference`.

### Fix 4 — Outbound-rate auto-PAUSE safety net

**File:** `src/daemon.py`, in the outbound send path.

**Behavior:** track outbound sends per-handle per-minute in a module-
level deque (NOT in state.db — this is volatile loop-prevention, not
forensics). If a single handle exceeds **6 outbound messages in 60
seconds**, auto-create the PAUSE file with reason
`"auto: outbound rate exceeded for <redacted handle>"`. Daemon will
idle until operator clears PAUSE.

Why 6/min: typical human-paced reply burst caps at 2-3/min. Even
intentional rapid-fire (Sam saying "yes", "actually no", "yes again")
should stay under 5/min. 6/min is the "we're definitely in a loop"
threshold.

Note this is BELOW the existing reply rate limit of 10/min — the rate
limit drops messages but doesn't pause. This new safety net pauses the
daemon entirely, which is the right response to "we're in a loop."

**Test:** synthesize 7 outbound sends within 60s; assert PAUSE file is
created on the 7th.

## Order of work after compact

1. Set up TodoWrite tracking the 4 fixes
2. Build Fix 1 (smallest, highest impact) — commit + push
3. Build Fix 2 (one constant change + comment) — commit + push
4. Build Fix 3 — commit + push
5. Build Fix 4 — commit + push
6. Run full test suite + ruff + mypy + bandit between each fix
7. Send Sam restart instructions

Optionally roll Fixes 1+2 into a single commit since they're both very
small. Keep 3 and 4 separate.

## Sam's restart sequence (after all 4 fixes)

```bash
cd /Users/samgobrail/Desktop/Claude\ Homebase/Projects/forks/claude-imessage-bridge

# Verify no stale daemon:
pkill -f "src.daemon" 2>/dev/null
ps aux | grep "src.daemon" | grep -v grep   # should print nothing

# Clear any leftover PAUSE from the loop:
rm -f ~/.claude-imessage-bridge/PAUSE

# Start fresh:
/opt/homebrew/bin/python3.11 -m src.daemon
```

Expected startup signature (no change from current):
```
running selftest: allowlist + argv invariants…
selftest: allowlist enforced (synthetic +19998887766 rejected as sender-not-allowlisted)
selftest: argv invariants hold (6 dangerous flags rejected)
memory backend: claude_md
starting bridge: project_dir=... trust=full
```

Test message: send Sam's iPhone a short non-trigger message ("hello"),
verify reply comes back ONCE. Then try the permission-relay flow again
("update my peptides log"); take >60s to reply yes; verify the
pending-intent waits up to 15min now.

## Daily cost-cap state

Daily cap was $5; spent $4.01. Cap resets at 00:00 UTC = 8pm ET.
By the time Sam restarts, today's cap will have rolled. Doesn't need
manual reset.

## Memory state on disk (unchanged by the loop)

These files WERE updated during the loop and look correct from the
screenshots:
- `memory/projects/wesco_azure.md` — Azure confirmed (Changyun+Luna)
- `memory/MEMORY.md` — Wesco line updated
- `Personal/Health/health-log.md` — Thu 5/15 NAD+ skip logged

The bridge correctly DID NOT update `~/.claude/CLAUDE.md` (Active Deals
table Wesco row) — that's the protected file. Sam will need to update
the CLAUDE.md row manually at foreground or via Option 2 from earlier
discussion (add Edit permission for CLAUDE.md to settings.json).

## What I'm explicitly NOT changing

- Trust mode (stay at full)
- Memory backend (stay at claude_md)
- HARD_DISALLOWED set
- Allowlist
- Daily cost cap ($5)
- Rate limit (10/min)

The fixes above are all defensive — preventing the loop from happening
again. The product behavior in trust=full stays the same.

## Things still on the roadmap (not for now)

- Permission-relay redesign via MCP server (the architecturally right
  way to do permission interrupts; deferred from earlier discussion)
- Voice memo ingestion
- Image OCR via Upstage DP
- Pinned sessions / context profiles
- Proactive outbound texting

These are all good ideas but unrelated to the bug at hand. Don't
scope-creep them into this fix pass.
