# Security policy

This project gives a local daemon Full Disk Access to read your Messages
database AND the ability to send iMessages from your account. Treat it like
the privileged tool it is.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security problems.

Email the maintainer privately, briefly describing:
- The vulnerability and how to reproduce
- The version/commit you tested
- Whether you believe public users are exposed

A reasonable disclosure timeline (90 days, or earlier if a patch ships sooner)
is expected.

## What's in scope

- Anything that lets an unauthorized sender drive the bridge (allowlist bypass).
- Anything that lets the bridge be coerced into actions beyond responding to
  the inbound sender (e.g., sending to other contacts, reading files outside
  the configured project directory, executing arbitrary shell).
- Prompt injection that leads to data exfiltration through the configured
  tool allowlist.
- Path traversal, command injection, AppleScript injection.
- Secrets being logged, committed, or otherwise persisted unsafely.

## What's not in scope (accepted residual risk)

- The user themselves asking the bridge to do destructive things in their own
  workspace — the bridge is a remote control for the user, not a sandbox.
- Compromise of the user's Apple ID. If an attacker controls iCloud, they
  control the bridge.
- Local privilege escalation (the bridge runs as the user; attackers with
  shell already have everything we have).

## Hardening expectations for contributors

- Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before touching any I/O.
- Run `bandit -q -r src/`, `pip-audit`, and `detect-secrets scan` clean before
  any PR.
- New tools added to the default allowlist require an entry in the threat
  model explaining why they're safe.
