---
name: Bug report
about: Something works incorrectly or unexpectedly
labels: bug
---

## Before filing

- [ ] I'm running the latest `main` (or a tagged release ≤ 30 days old).
- [ ] My issue is **NOT a suspected security vulnerability** — those
      go to the address in [SECURITY.md](../../SECURITY.md), not a
      public issue.
- [ ] I've redacted any iMessage content, phone numbers, email
      addresses, or other PII from the logs and steps below.

## What happened

(A clear description of the actual behavior.)

## What I expected

(A clear description of the expected behavior.)

## Reproduction

Steps to reproduce, ideally on a fresh checkout:

1. ...
2. ...

## Environment

- macOS version:
- Python version (`python3 --version`):
- Bridge commit (`git rev-parse HEAD`):
- Claude Code CLI version (`claude --version`):
- Trust mode (`grep trust ~/.claude-imessage-bridge/config.yaml`):
- Memory backend (`grep "backend:" ~/.claude-imessage-bridge/config.yaml`):

## Relevant logs

Paste the daemon's stderr output. Redact handles and any PII first.

```
(paste here)
```

## Audit log snippet (optional)

If the bug is observable in the audit log, a redacted query result
helps a lot:

```bash
sqlite3 -readonly ~/.claude-imessage-bridge/state.db \
  "SELECT ts, direction, kind, detail FROM audit_log ORDER BY rowid DESC LIMIT 20"
```
