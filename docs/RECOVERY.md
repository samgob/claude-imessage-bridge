# Recovery guide

What to do when the bridge is in a bad state. Most "stuck" scenarios are
solved by removing one file and restarting.

## Daemon won't start: selftest failure

**Symptom:**
```
SECURITY SELF-TEST FAILED: Bash WAS executed via claude despite --disallowed-tools …
```

**Meaning:** A Claude Code release changed tool-deny semantics. The bridge
will refuse to start until `HARD_DISALLOWED` in `src/claude_runner.py` is
audited and updated to cover whatever the new behavior is.

**Action:** Open a private issue with the maintainer (see SECURITY.md).
Do NOT comment out the selftest. It is the only empirical proof that
Phase B's security boundary is holding.

## Daemon won't start: schema too new

**Symptom:**
```
state.db schema error: state.db has user_version=2, but this code only
knows how to handle up to 1.
```

**Meaning:** You ran a newer bridge against this state.db, then downgraded
the code. Either re-upgrade or wipe state.db (you'll lose audit history).

**Action:**
```bash
# Option A: Re-upgrade the bridge code.
git pull
# Option B: Reset state (loses cursor + audit + sessions).
rm ~/.claude-imessage-bridge/state.db
# On next start, the daemon will seed cursor at chat.db MAX(rowid).
```

## Bridge is replying to old messages after a restore

**Symptom:** You restored an older `~/.claude-imessage-bridge/state.db`
from Time Machine; on start, the bridge refuses to advance the cursor.

**Meaning:** Cursor regression guard. The old DB's cursor points at an
older message than the current cursor — if it advanced, the bridge would
replay every iMessage between the two values.

**Action:** This is intentional. Restoring an old state.db means you want
to keep the old audit history. But you almost certainly do NOT want to
replay messages. The daemon will refuse to advance the cursor; logs will
include:

```
cursor chatdb_last_rowid regression: current=12345 new=12000 allow_regression=False
```

To proceed:
```bash
# Skip the backlog — start "from now."
python3 -m src.daemon --reset-cursor
```

This re-seeds the cursor at `MAX(rowid)` from chat.db, with
`allow_regression=True`. It deliberately requires a separate invocation
flag so accidental restore + restart can't silently reprocess history.

## Daemon stuck in PAUSE

**Symptom:** Logs say `PAUSE file present, idling` indefinitely.

**Meaning:** Either you created the PAUSE file manually, or the circuit
breaker tripped after N consecutive Claude failures.

**Check:**
```bash
cat ~/.claude-imessage-bridge/PAUSE
```

The first line is the reason. If it's `auto: N consecutive claude failures`,
look at the daemon logs to see why.

**Action:**
```bash
# Resolve the underlying issue (network, claude binary, API key), then:
rm ~/.claude-imessage-bridge/PAUSE
```

The daemon resumes on the next poll tick. The consecutive-failure counter
does NOT auto-reset — only a successful Claude call resets it. If you want
to manually clear, restart the daemon.

## Daemon won't exit cleanly

The daemon listens for SIGTERM and SIGINT. If it doesn't stop, drop a
STOP file:

```bash
touch ~/.claude-imessage-bridge/STOP
```

Next poll tick, the daemon exits cleanly. Remove the file before next
start.

## Audit log is huge

```sql
-- How much have we accumulated?
SELECT COUNT(*), MIN(ts), MAX(ts) FROM audit_log;
```

The bridge doesn't auto-rotate audit history. To trim:

```bash
# Trim everything older than 90 days, vacuum to reclaim space.
sqlite3 ~/.claude-imessage-bridge/state.db <<SQL
DELETE FROM audit_log WHERE ts < datetime('now', '-90 days');
VACUUM;
SQL
```

Run with the daemon **stopped** (state.db locks otherwise).

## state.db is corrupt

```bash
sqlite3 ~/.claude-imessage-bridge/state.db "PRAGMA integrity_check;"
```

If this returns anything but `ok`, the safest path is to back up and reset:

```bash
mv ~/.claude-imessage-bridge/state.db ~/.claude-imessage-bridge/state.db.corrupt.$(date +%s)
python3 -m src.daemon --reset-cursor  # fresh DB, fresh cursor
```

Open the `.corrupt` copy in `sqlite3` to extract anything you need
(conversations table, audit history). The fresh DB will rebuild schema
v1 on first start.

## "Something's wrong but I don't know what"

Read `status.json`:

```bash
cat ~/.claude-imessage-bridge/status.json | jq .
```

If `paused: true`, see "Daemon stuck in PAUSE" above.
If `consecutive_failures > 0`, claude is failing — check logs.
If `daily_cost_cents` is near `daily_cost_cap_cents`, you've hit the
spend cap (resets at 00:00 UTC).
If the file's `ts` is more than ~15 minutes old, the daemon isn't writing
heartbeats — it's hung or crashed.
