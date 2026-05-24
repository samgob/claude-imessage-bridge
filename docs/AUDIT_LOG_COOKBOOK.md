# Audit log cookbook

Every inbound message produces at least one row in `audit_log` (in
`~/.claude-imessage-bridge/state.db`). The audit log is the
forensics surface — what the bridge processed, why, and what it
spent doing so. Bodies are NEVER stored. Use these queries for
operations: incident response, cost attribution, debugging.

## Connect

```bash
sqlite3 -readonly ~/.claude-imessage-bridge/state.db
```

The `-readonly` flag is important: the daemon may be writing concurrently.

## Schema (v3)

The bridge has versioned schemas with automatic forward migrations.
The columns below reflect schema v3 (current); rows written under v1
or v2 will have NULL in any later-added column. See
`docs/RECOVERY.md` for migration internals and `src/state.py` for the
authoritative `SCHEMA_VERSION` constant.

```sql
CREATE TABLE audit_log (
    rowid INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,                -- ISO-8601 UTC
    handle_redacted TEXT NOT NULL,   -- e.g. "sa***@example.com"
    direction TEXT NOT NULL,         -- 'in' or 'out'
    kind TEXT NOT NULL,              -- 'command' / 'text' / 'reply' / 'drop'
    detail TEXT,                     -- never raw body
    reply_bytes INTEGER,
    chatdb_rowid INTEGER,            -- correlates to chat.db message.ROWID
    cost_cents INTEGER,              -- claude spend on this row (0 for non-claude)
    error_category TEXT              -- 'timeout' / 'exec_error' / 'json_parse' / 'claude_error' / NULL
);
```

## Common queries

### Was a specific iMessage processed?

You know the chat.db rowid (from `sqlite3 ~/Library/Messages/chat.db` or
similar). The bridge records that rowid on every audit row.

```sql
SELECT * FROM audit_log WHERE chatdb_rowid = 4823 ORDER BY rowid;
```

### What did the bridge drop, and why?

```sql
SELECT ts, handle_redacted, kind, detail
FROM audit_log
WHERE kind = 'drop'
ORDER BY ts DESC
LIMIT 50;
```

The `detail` column is the canonical reason: `sender-not-allowlisted`,
`group-chat-not-opted-in`, `rate-limited`, `daily-cap-reached`,
`per-call-cap`, `send-error:SendError`, `cmd-error:RuntimeError`, etc.

### Spending by day

```sql
SELECT
    substr(ts, 1, 10) AS day_utc,
    SUM(cost_cents) AS spent_cents,
    COUNT(*) FILTER (WHERE direction = 'out' AND kind = 'reply') AS replies
FROM audit_log
WHERE direction = 'out'
GROUP BY day_utc
ORDER BY day_utc DESC;
```

### Spending by handle

```sql
SELECT
    handle_redacted,
    SUM(cost_cents) AS spent_cents,
    COUNT(*) AS replies
FROM audit_log
WHERE direction = 'out' AND cost_cents > 0
GROUP BY handle_redacted
ORDER BY spent_cents DESC;
```

### Recent claude errors

```sql
SELECT ts, handle_redacted, error_category, detail
FROM audit_log
WHERE error_category IS NOT NULL
ORDER BY ts DESC
LIMIT 20;
```

### Reply latency from detail string

`detail` for successful replies looks like `ok dur=1234ms cost_cents=4 sid=abcd1234`.
The `dur=` field is the claude round-trip in milliseconds:

```sql
SELECT
    handle_redacted,
    detail,
    CAST(substr(detail,
        instr(detail, 'dur=') + 4,
        instr(detail, 'ms ') - instr(detail, 'dur=') - 4
    ) AS INTEGER) AS dur_ms
FROM audit_log
WHERE direction = 'out' AND kind = 'reply' AND detail LIKE 'ok dur=%';
```

### Were there gaps in cursor advance?

Compare `chatdb_rowid` values to spot iMessage rows the bridge silently
skipped (filtered at the SQL layer — SMS, attachments, tapbacks, etc.).

```sql
SELECT chatdb_rowid - LAG(chatdb_rowid) OVER (ORDER BY chatdb_rowid) AS gap,
       chatdb_rowid, kind, detail
FROM audit_log
WHERE direction = 'in'
ORDER BY chatdb_rowid;
```

A gap > 1 just means rows were filtered by the SQL layer (SMS, attachments,
balloon apps, edits). Investigate only if you expect a row to have been
visible to the bridge.

## What is NOT in the audit log

- **Message bodies.** Never persisted, even in debug mode.
- **The full session id.** Only the 8-character `sid=` prefix in `detail`.
- **The claude stderr / error string.** Logged to stderr server-side only.
- **The consecutive-failure count.** Server-side log only — leaking it to
  iMessage would let an attacker probe the circuit-breaker threshold.
