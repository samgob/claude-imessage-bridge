"""Discover Claude Code sessions on disk for /sessions and /use commands.

Claude Code persists session transcripts as JSONL files under
``~/.claude/projects/<encoded-cwd>/<session-uuid>.jsonl``. Each transcript
embeds its original ``cwd`` in early records, which we extract
authoritatively rather than reversing the encoded directory name (the
encoding is lossy: both ``/`` and spaces become ``-``).

Ported from the Telegram fork's session_discovery module. Same data layer,
same keyword-search logic.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Final, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_PROJECTS_ROOT = Path.home() / ".claude" / "projects"

_SNIPPET_MAX = 120
_SCAN_RECORDS = 80
_DEEP_SEARCH_BYTES = 64 * 1024
_DEEP_SEARCH_CANDIDATES = 200

_STOPWORDS = frozenset({
    "a", "an", "the", "session", "sessions", "claude",
    "for", "with", "about", "from", "in", "of", "on", "my",
    "to", "and", "or",
    # recency hints — implied by default recency-first sort
    "latest", "recent", "newest", "last", "yesterday", "today",
})

_ROUTINE_PREFIX = "<scheduled-task"

# Prefixes that mark a session as bridge-internal (created by the bridge's
# own hermetic per-call sandbox or startup selftest). These are recorded
# in ~/.claude/projects/ under encoded tempdir names like
# `-private-var-folders-...-cimb-selftest-XXXX` or `cimb-call-XXXX`. They
# pollute the /sessions list with non-user content (the selftest is "Use
# the Bash tool right now to run: echo SELFTEST_FAIL > …", which is
# security plumbing not a real conversation). Excluded by default.
_BRIDGE_INTERNAL_CWD_MARKERS: Final = (
    "cimb-selftest-",  # startup security selftest
    "cimb-call-",      # hermetic per-call sandbox for normal replies
)


def _is_bridge_internal(cwd: Optional[Path]) -> bool:
    """True if the session was created inside one of the bridge's own
    per-call tempdirs (selftest or hermetic reply). These should NOT
    show up in /sessions by default — they're bridge plumbing, not
    user-meaningful conversations."""
    if cwd is None:
        return False
    s = str(cwd)
    return any(marker in s for marker in _BRIDGE_INTERNAL_CWD_MARKERS)


@dataclass(frozen=True)
class SessionInfo:
    session_id: str
    cwd: Optional[Path]
    last_modified: datetime
    snippet: str
    file_path: Path
    size_bytes: int
    is_routine: bool = False
    is_bridge_internal: bool = False

    @property
    def short_id(self) -> str:
        return self.session_id[:8]

    @property
    def age_seconds(self) -> float:
        return (datetime.now(timezone.utc) - self.last_modified).total_seconds()

    def relative_age(self) -> str:
        s = self.age_seconds
        if s < 60:
            return f"{int(s)}s"
        if s < 3600:
            return f"{int(s / 60)}m"
        if s < 86400:
            return f"{int(s / 3600)}h"
        return f"{int(s / 86400)}d"


def _extract_session_metadata(path: Path) -> tuple[Optional[Path], str]:
    cwd: Optional[Path] = None
    snippet = ""
    try:
        with path.open("r", errors="replace") as f:
            for i, line in enumerate(f):
                if i >= _SCAN_RECORDS:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if cwd is None:
                    candidate = rec.get("cwd")
                    if candidate:
                        cwd = Path(candidate)
                if not snippet:
                    snippet = _extract_user_text(rec)
                if cwd and snippet:
                    break
    except OSError as e:
        logger.debug("Failed to read session file %s: %s", path, e)
    return cwd, snippet[:_SNIPPET_MAX].replace("\n", " ").strip()


def _extract_user_text(rec: dict) -> str:
    msg = rec.get("message")
    if not isinstance(msg, dict) or msg.get("role") != "user":
        return ""
    content = msg.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        for chunk in content:
            if isinstance(chunk, dict) and chunk.get("type") == "text":
                txt = chunk.get("text", "")
                if isinstance(txt, str) and txt:
                    return txt
    return ""


def discover_sessions(
    limit: int = 20,
    *,
    projects_root: Path = DEFAULT_PROJECTS_ROOT,
    within_cwd: Optional[Path] = None,
    include_routines: bool = False,
    include_bridge_internal: bool = False,
) -> List[SessionInfo]:
    """List recent Claude Code sessions, newest first.

    Routines (scheduled-task transcripts) are excluded by default — they
    rarely make useful resume targets. Pass ``include_routines=True`` to
    include them.

    Bridge-internal sessions (the daemon's startup selftest and per-call
    hermetic sandboxes — cwd contains ``cimb-selftest-`` or ``cimb-call-``)
    are excluded by default. Selftests in particular pollute the list
    with security-plumbing prompts. Pass ``include_bridge_internal=True``
    to include them (the ``/sessions --all`` path opts in).
    """
    if not projects_root.exists():
        return []

    all_files: List[Path] = []
    for project_dir in projects_root.iterdir():
        if not project_dir.is_dir():
            continue
        all_files.extend(project_dir.glob("*.jsonl"))
    all_files.sort(key=lambda p: p.stat().st_mtime, reverse=True)

    # Scan-budget heuristic: with two default-on filters (routines +
    # bridge-internal) the candidate pool can be much larger than the
    # final limit, so widen the scan accordingly.
    expand = (4 if within_cwd else 1)
    expand *= (3 if not include_routines else 1)
    expand *= (2 if not include_bridge_internal else 1)
    scan_budget = max(limit * expand, 40)

    results: List[SessionInfo] = []
    for path in all_files[:scan_budget]:
        try:
            stat = path.stat()
        except OSError:
            continue
        cwd, snippet = _extract_session_metadata(path)
        is_routine = snippet.startswith(_ROUTINE_PREFIX)
        is_internal = _is_bridge_internal(cwd)
        if not include_routines and is_routine:
            continue
        if not include_bridge_internal and is_internal:
            continue
        if within_cwd is not None:
            if cwd is None:
                continue
            try:
                cwd.resolve().relative_to(within_cwd.resolve())
            except (ValueError, OSError):
                continue
        results.append(SessionInfo(
            session_id=path.stem,
            cwd=cwd,
            last_modified=datetime.fromtimestamp(stat.st_mtime, timezone.utc),
            snippet=snippet,
            file_path=path,
            size_bytes=stat.st_size,
            is_routine=is_routine,
            is_bridge_internal=is_internal,
        ))
        if len(results) >= limit:
            break
    return results


def _tokenize_query(query: str) -> list[str]:
    seen: set[str] = set()
    tokens: list[str] = []
    for raw in query.lower().split():
        t = raw.strip(".,!?:;\"'()[]")
        if not t or t in _STOPWORDS or len(t) < 2 or t in seen:
            continue
        seen.add(t)
        tokens.append(t)
    return tokens


def _content_contains_all(file_path: Path, tokens: list[str]) -> int:
    try:
        with file_path.open("rb") as f:
            blob = f.read(_DEEP_SEARCH_BYTES)
    except OSError:
        return 0
    text = blob.decode("utf-8", errors="replace").lower()
    counts = []
    for t in tokens:
        c = text.count(t)
        if c == 0:
            return 0
        counts.append(c)
    return sum(counts)


def search_sessions(
    query: str,
    *,
    limit: int = 5,
    projects_root: Path = DEFAULT_PROJECTS_ROOT,
    within_cwd: Optional[Path] = None,
    include_routines: bool = False,
    include_bridge_internal: bool = False,
    exclude_session_ids: Optional[set[str]] = None,
) -> List[SessionInfo]:
    """Find sessions matching a natural-language query, newest first.

    Tokenized query (stopwords + recency hints stripped). ALL tokens must
    appear in the transcript body. Recency-first sort. Relevance floor: if
    any match has 2+ hits, 1-hit incidentals are dropped.

    Excludes routines and bridge-internal sessions by default; mirror
    flags forwarded to ``discover_sessions``.
    """
    tokens = _tokenize_query(query)
    if not tokens:
        return []

    candidates = discover_sessions(
        limit=_DEEP_SEARCH_CANDIDATES,
        projects_root=projects_root,
        within_cwd=within_cwd,
        include_routines=include_routines,
        include_bridge_internal=include_bridge_internal,
    )
    excluded = exclude_session_ids or set()
    scored: list[tuple[int, float, SessionInfo]] = []
    for s in candidates:
        if s.session_id in excluded:
            continue
        hits = _content_contains_all(s.file_path, tokens)
        if hits == 0:
            continue
        scored.append((hits, s.last_modified.timestamp(), s))

    # Relevance floor
    max_hits = max((h for h, _, _ in scored), default=0)
    if max_hits >= 2:
        scored = [t for t in scored if t[0] >= 2]
    scored.sort(key=lambda x: x[1], reverse=True)
    return [s for _, _, s in scored[:limit]]


def find_by_id(
    session_id: str,
    *,
    projects_root: Path = DEFAULT_PROJECTS_ROOT,
) -> Optional[SessionInfo]:
    """Locate a session by full id. Returns None if not found."""
    if not session_id or not projects_root.exists():
        return None
    for project_dir in projects_root.iterdir():
        if not project_dir.is_dir():
            continue
        candidate = project_dir / f"{session_id}.jsonl"
        if candidate.is_file():
            stat = candidate.stat()
            cwd, snippet = _extract_session_metadata(candidate)
            return SessionInfo(
                session_id=session_id,
                cwd=cwd,
                last_modified=datetime.fromtimestamp(stat.st_mtime, timezone.utc),
                snippet=snippet,
                file_path=candidate,
                size_bytes=stat.st_size,
                is_routine=snippet.startswith(_ROUTINE_PREFIX),
                is_bridge_internal=_is_bridge_internal(cwd),
            )
    return None
