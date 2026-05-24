<!--
Thanks for the PR. Please skim this template before submitting.

If the change touches any of the security-boundary modules
(claude_runner.py, imessage_sender.py, imessage_reader.py, state.py,
trust.py, audio_transcribe.py), please flag that explicitly below.
-->

## Summary

(1–2 sentences. What does this PR change?)

## Motivation

(Why is this change needed?)

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor (no behavior change)
- [ ] Docs only
- [ ] CI / build / packaging

## Security surface

- [ ] **None** — this PR doesn't touch any security-boundary module
      or change a defensive invariant.
- [ ] **Touched but not weakened** — explain below which boundary you
      touched and why the defense is preserved.
- [ ] **Intentionally widens surface** — explain below. This needs an
      explicit acknowledgment in `docs/THREAT_MODEL.md`.

(Free-text explanation if either of the last two are checked.)

## Tests

- [ ] Unit tests added/updated for the new behavior
- [ ] `pytest` passes locally
- [ ] `ruff check src/ tests/` passes
- [ ] `mypy src/` passes
- [ ] `bandit -q -r src/ -c pyproject.toml` passes

## CHANGELOG

- [ ] Entry added under the appropriate `[Unreleased]` or current
      version heading. Skip for docs-only / CI-only changes.

## Other notes

(Anything else reviewers should know — design tradeoffs, follow-ups,
open questions.)
