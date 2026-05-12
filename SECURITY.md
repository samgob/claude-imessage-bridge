# Security policy

This project gives a local daemon Full Disk Access to read your Messages
database AND the ability to send iMessages from your account. Treat it like
the privileged tool it is.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security problems.

**Preferred:** use [GitHub Private Vulnerability Reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository. Navigate to the **Security** tab → "Report a
vulnerability". This routes the report to the maintainer with the
correct privacy and creates a private advisory draft we can collaborate on.

**Fallback:** email the maintainer at the address listed on the GitHub
profile for [@samgob](https://github.com/samgob). If you don't hear
back within 7 days, also open a Private Vulnerability Report on the
repo (the email may have hit spam — the GitHub flow has stronger
delivery guarantees).

Include in either channel:

- The vulnerability and how to reproduce
- The version/commit you tested
- Whether you believe public users are exposed
- Your preferred attribution (or anonymous)

### Triage SLOs

These are targets, not contractual guarantees. This is a personal-time
project; please be patient.

| Stage | Target |
|---|---|
| Acknowledgment of report | within 3 business days |
| Initial severity assessment + plan | within 7 days |
| Patch + private notification to known operators | varies by severity, 30 days target |
| Public advisory (after patch) | within 90 days of report, or earlier if a patch shipped sooner |

If you don't hear back within a week, please re-send — the email may have
landed in spam.

### Disclosure timeline

A reasonable disclosure timeline (**90 days**, or earlier if a patch ships
sooner) is expected. We'd like to coordinate disclosure for any CVE-worthy
finding so that operators have a chance to update before details go public.

## CVE policy

A finding warrants a CVE assignment if **any one** of the following is true:

- A non-allowlisted sender can drive the bridge (allowlist bypass).
- The bridge can be coerced into actions beyond responding to the inbound
  sender (sending to other contacts, reading files outside the configured
  project directory, executing arbitrary shell, writing to disk, performing
  network requests).
- A prompt injection bypasses `--disallowed-tools` or the empirical bash
  selftest under any default configuration.
- A symlink, race, or path-traversal lets an attacker overwrite a file
  outside `~/.claude-imessage-bridge/` via the daemon's privileges.
- A secret (API key, OAuth token, session id, raw message body) is
  persisted to disk in a location not documented as containing it
  (state.db detail field, logs without `--debug`, status.json, etc.).
- A panic or crash takes down the daemon in a way that produces a
  forensic gap (lost cursor advance with a sent reply, or a sent reply
  with no audit row).

CVE assignments will go through GitHub's CVE Numbering Authority for
this repo.

## What's in scope

- Anything that lets an unauthorized sender drive the bridge (allowlist bypass).
- Anything that lets the bridge be coerced into actions beyond responding to
  the inbound sender (e.g., sending to other contacts, reading files outside
  the configured project directory, executing arbitrary shell).
- Prompt injection that leads to data exfiltration through the configured
  tool allowlist.
- Path traversal, command injection, AppleScript injection, symlink-write
  attacks on `empty-mcp.json`, `state.db`, or `status.json`.
- Secrets being logged, committed, or otherwise persisted unsafely.
- Cursor / audit / cost-cap accounting that lets an attacker bypass the
  caps via concurrency, race, or overflow.
- TOCTOU on rate limiting, daily-cost cap, or circuit breaker.
- Tool deny-list regression (e.g., a new tool added by a future Claude
  Code release that isn't covered by `HARD_DISALLOWED`).
- Cursor regression that lets a restore-from-backup re-process messages
  without operator opt-in.

## What's not in scope (accepted residual risk)

- The user themselves asking the bridge to do destructive things in their own
  workspace — the bridge is a remote control for the user, not a sandbox.
  With the default `allowed_tools: []`, nothing destructive is possible.
- Compromise of the user's Apple ID. If an attacker controls iCloud, they
  control the bridge.
- Local privilege escalation (the bridge runs as the user; attackers with
  shell already have everything we have).
- Edit/unsend on chat.db rows after the bridge has read them. The audit log
  records first-seen content; the bridge does not re-poll for edits.
- Cost-exhaustion **within** the configured caps. An allowlisted attacker
  can burn the daily cap by saturating the per-minute rate limit. Lower
  the caps if this is your threat model.

## Hardening expectations for contributors

- Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before touching any I/O.
- Run `pytest tests/`, `ruff check src/`, `bandit -q -r src/`, and
  `pip-audit` clean before any PR.
- New tools added to `allowed_tools` defaults — or anything removed from
  `HARD_DISALLOWED` / `HARD_FORBIDDEN_TOOLS` — require an entry in the
  threat model explaining why they're safe AND an updated `selftest`
  invariant.
- Changes to argv shape in `claude_runner.run_claude` must include
  regression tests in `tests/unit/test_claude_runner.py`.
- Changes to AppleScript send shape in `imessage_sender` must keep the
  argv-only pattern (`-e SCRIPT -- handle body`); the `do shell script`
  fallback was explicitly rejected in round-2 review.
- New audit-log columns require a schema migration (`PRAGMA user_version`
  bump + an entry in `_apply_schema`).
