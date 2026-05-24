"""Memory backends — inject curated context into the system prompt.

Three backends ship in the initial cut:

- **NoneBackend** — returns empty string. Used in chat_only trust mode
  and as the safe OSS default. The bridge has no memory awareness.

- **ClaudeMdBackend** — loads CLAUDE.md (always, as the eager core) +
  lazy-resolves references to ``memory/projects/*.md``, ``memory/people/*.md``,
  ``memory/context/*.md`` based on token-match against each query.
  Returns up to ``max_bytes`` of context per call, cached for 5 minutes
  by query-hash. Used in coding and full trust modes.

- **CustomScriptBackend** — runs an operator-provided script with the
  inbound message on stdin; reads context from stdout. Exit timeout is
  configurable. Failures are logged at WARNING and return empty string —
  the bridge keeps working even if the script breaks.

Context text is appended to the runner's ``extra_system_prompt`` argument,
which becomes part of ``--append-system-prompt`` argv. The same prompt-
injection cost applies as with any system-prompt content; in trust modes
where memory backends fire (coding/full) the operator has already chosen
to trade hermeticity for utility — the threat model adds an explicit
trust-mode section noting the trade.

This module is import-light: stdlib only. No regex compilation at module
load; lazy where it matters.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Protocol, Tuple

logger = logging.getLogger(__name__)


# --- Public types ---------------------------------------------------------


@dataclass(frozen=True)
class MemoryLoadResult:
    """What ``MemoryBackend.context_for`` returns.

    Carries both the rendered context (which goes into the prompt) AND
    a structured listing of the source files (for the /sources command
    so the user can audit what got loaded).
    """

    text: str  # what gets injected via --append-system-prompt
    sources: List[Tuple[str, int]]  # [(path_str, bytes_loaded), ...]


class MemoryBackend(Protocol):
    """Backends produce per-query context to inject into Claude's prompt."""

    def context_for(self, query: str) -> MemoryLoadResult: ...


# Sentinel for the "no context this call" case so callers don't need to
# special-case empty strings.
EMPTY_RESULT: MemoryLoadResult = MemoryLoadResult(text="", sources=[])


# --- NoneBackend ----------------------------------------------------------


class NoneBackend:
    """Returns empty context for every query.

    Used in chat_only trust mode AND when ``memory.backend: none`` is
    explicitly configured. The default. Bridge behaves exactly as it did
    pre-memory.
    """

    def context_for(self, query: str) -> MemoryLoadResult:
        return EMPTY_RESULT


# --- ClaudeMdBackend ------------------------------------------------------

# Token-matching parameters. The eager core (CLAUDE.md itself) is always
# loaded; the lazy resolver picks the top-N reference files by score.
_DEFAULT_TOP_N_REFS: int = 3
_MIN_TOKEN_LENGTH: int = 3
_SCAN_HEADER_BYTES: int = 1024  # how many bytes from each candidate
# file to scan for the token-match
_CACHE_TTL_SECONDS: int = 300  # 5-minute query result cache

# Stopwords for tokenization. Match session_discovery's set so the same
# tokens that get stripped in /use are stripped here too.
_STOPWORDS = frozenset(
    {
        "a",
        "an",
        "the",
        "session",
        "sessions",
        "claude",
        "for",
        "with",
        "about",
        "from",
        "in",
        "of",
        "on",
        "my",
        "to",
        "and",
        "or",
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "latest",
        "recent",
        "newest",
        "last",
        "yesterday",
        "today",
        "what",
        "when",
        "where",
        "who",
        "whose",
        "how",
        "why",
        "this",
        "that",
        "these",
        "those",
        "i",
        "me",
        "you",
        "your",
        "do",
        "did",
        "does",
    }
)


def _tokenize(query: str) -> List[str]:
    """Lowercase, strip stopwords + short tokens, return distinct tokens."""
    seen: set = set()
    tokens: List[str] = []
    for raw in re.split(r"[\s\W]+", query.lower()):
        raw = raw.strip()
        if not raw or len(raw) < _MIN_TOKEN_LENGTH:
            continue
        if raw in _STOPWORDS or raw in seen:
            continue
        seen.add(raw)
        tokens.append(raw)
    return tokens


def _score_candidate(path: Path, tokens: List[str]) -> int:
    """Score a candidate memory file by token-match.

    Reads the filename + the first ``_SCAN_HEADER_BYTES`` of the file's
    text and counts matched tokens. Higher score = more relevant.
    A score of 0 means no match — caller drops the candidate entirely.
    """
    name = path.stem.lower()
    score = sum(1 for t in tokens if t in name)
    try:
        with path.open("r", errors="replace") as f:
            head = f.read(_SCAN_HEADER_BYTES).lower()
    except OSError:
        return score
    for t in tokens:
        if t in head:
            score += 1
    return score


class ClaudeMdBackend:
    """CLAUDE.md + lazy reference loader.

    On every query: load the eager core (CLAUDE.md), then walk a fixed
    set of subdirectories under the root's parent (``memory/projects``,
    ``memory/people``, ``memory/context``) and load the top-N files by
    token-match score.

    The reference walker is deliberately narrow — it does NOT recursively
    crawl the entire memory tree, and it does NOT follow markdown links
    inside CLAUDE.md (which would re-introduce the unbounded inheritance
    risk). The directories scanned are the ones a Sam-shape memory
    architecture conventionally uses.

    Results are cached for ``_CACHE_TTL_SECONDS`` keyed on the query-hash
    so repeated questions in quick succession don't re-stat the tree.
    """

    def __init__(
        self,
        *,
        root: Path,
        follow_references: bool = True,
        max_bytes: int = 32 * 1024,
        exclude: Optional[List[str]] = None,
    ):
        self.root = Path(root).expanduser()
        self.follow_references = follow_references
        self.max_bytes = max_bytes
        self._exclude_patterns: List[re.Pattern] = [re.compile(p) for p in (exclude or [])]
        # Query-hash → (timestamp, MemoryLoadResult)
        self._cache: Dict[str, Tuple[float, MemoryLoadResult]] = {}

    def _is_excluded(self, path: Path) -> bool:
        s = str(path)
        return any(p.search(s) for p in self._exclude_patterns)

    def _candidate_dirs(self) -> List[Path]:
        """The dirs we scan for reference files. Sam-conventional layout:

            ``<root>/../memory/projects/``
            ``<root>/../memory/people/``
            ``<root>/../memory/context/``

        ``root`` is typically ``~/.claude/CLAUDE.md`` — but the convention
        for the auto-memory file is ``~/.claude/projects/<encoded>/MEMORY.md``
        with the memory tree sitting next to it. Either way, we look in
        the parent dir for a ``memory/`` subdir.
        """
        parent = self.root.parent
        memory_dir = parent / "memory"
        if not memory_dir.is_dir():
            return []
        candidates: List[Path] = []
        for subname in ("projects", "people", "context"):
            sub = memory_dir / subname
            if sub.is_dir():
                candidates.append(sub)
        return candidates

    def _gather_reference_files(self) -> List[Path]:
        """All .md files under the candidate dirs (one level deep),
        minus excluded paths."""
        files: List[Path] = []
        for d in self._candidate_dirs():
            try:
                for entry in d.iterdir():
                    if entry.is_file() and entry.suffix == ".md":
                        if not self._is_excluded(entry):
                            files.append(entry)
            except OSError:
                continue
        return files

    def _load_eager_core(self) -> Tuple[str, int]:
        """Read CLAUDE.md (or whatever root points at). Returns
        ``(text, bytes_loaded)``. ``("", 0)`` if the file is missing."""
        try:
            text = self.root.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.warning(
                "ClaudeMdBackend: root %s could not be read (%s); "
                "memory backend will return empty context",
                self.root,
                e,
            )
            return ("", 0)
        return (text, len(text.encode("utf-8")))

    def _query_hash(self, query: str) -> str:
        return hashlib.sha256(query.lower().encode("utf-8")).hexdigest()[:16]

    def context_for(self, query: str) -> MemoryLoadResult:
        """Build context for one query. See module docstring for design."""
        # Cache check first.
        h = self._query_hash(query)
        now = time.time()
        cached = self._cache.get(h)
        if cached and (now - cached[0]) < _CACHE_TTL_SECONDS:
            return cached[1]

        sources: List[Tuple[str, int]] = []
        body_parts: List[str] = []
        bytes_used = 0

        # Eager core: CLAUDE.md (or configured root).
        core_text, core_bytes = self._load_eager_core()
        if core_text:
            # Truncate if the eager core alone exceeds the budget — better
            # to lose the tail than to drop it entirely.
            if core_bytes > self.max_bytes:
                truncated = core_text.encode("utf-8")[: self.max_bytes]
                core_text = truncated.decode("utf-8", errors="ignore") + "\n…[truncated]"
                core_bytes = len(core_text.encode("utf-8"))
            body_parts.append(core_text)
            sources.append((str(self.root), core_bytes))
            bytes_used = core_bytes

        # Lazy references.
        if self.follow_references and bytes_used < self.max_bytes:
            tokens = _tokenize(query)
            if tokens:
                candidates = self._gather_reference_files()
                scored: List[Tuple[int, Path]] = []
                for path in candidates:
                    s = _score_candidate(path, tokens)
                    if s > 0:
                        scored.append((s, path))
                # Highest score first; stable secondary sort by path for
                # determinism in tests.
                scored.sort(key=lambda t: (-t[0], str(t[1])))
                for _score, path in scored[:_DEFAULT_TOP_N_REFS]:
                    if bytes_used >= self.max_bytes:
                        break
                    try:
                        text = path.read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        continue
                    remaining = self.max_bytes - bytes_used
                    encoded = text.encode("utf-8")
                    if len(encoded) > remaining:
                        text = (
                            encoded[:remaining].decode("utf-8", errors="ignore") + "\n…[truncated]"
                        )
                    section = f"\n\n--- {path.name} ---\n{text}"
                    body_parts.append(section)
                    section_bytes = len(section.encode("utf-8"))
                    sources.append((str(path), section_bytes))
                    bytes_used += section_bytes

        result = MemoryLoadResult(
            text="".join(body_parts),
            sources=sources,
        )
        self._cache[h] = (now, result)
        return result


# --- CustomScriptBackend --------------------------------------------------


class CustomScriptBackend:
    """Operator-provided script. stdin: query. stdout: context. Best-effort.

    Failures (non-zero exit, timeout, OSError, non-utf8 output) all log
    a WARNING and return empty context. The bridge never crashes on
    backend failure — the next message just doesn't get memory injected.
    """

    def __init__(self, *, script: Path, timeout_seconds: int = 5):
        self.script = Path(script).expanduser()
        self.timeout_seconds = timeout_seconds

    def context_for(self, query: str) -> MemoryLoadResult:
        if not self.script.is_file() or not os.access(self.script, os.X_OK):
            logger.warning(
                "CustomScriptBackend: script %s is not an executable file; "
                "returning empty context",
                self.script,
            )
            return EMPTY_RESULT
        try:
            proc = subprocess.run(  # noqa: S603 — operator-controlled script path
                [str(self.script)],
                input=query.encode("utf-8"),
                capture_output=True,
                timeout=self.timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            logger.warning("CustomScriptBackend %s failed: %s", self.script, e)
            return EMPTY_RESULT
        if proc.returncode != 0:
            logger.warning(
                "CustomScriptBackend %s exit=%d stderr=%r",
                self.script,
                proc.returncode,
                (proc.stderr or b"")[-200:],
            )
            return EMPTY_RESULT
        try:
            text = proc.stdout.decode("utf-8", errors="replace")
        except UnicodeDecodeError:
            logger.warning("CustomScriptBackend %s produced non-utf8 output", self.script)
            return EMPTY_RESULT
        return MemoryLoadResult(
            text=text,
            sources=[(str(self.script), len(proc.stdout))],
        )


# --- Backend factory ------------------------------------------------------


def build_backend(
    *,
    backend_name: str,
    claude_md_params: Dict[str, object],
    custom_params: Dict[str, object],
) -> MemoryBackend:
    """Construct the configured backend from parsed config dicts.

    Returns ``NoneBackend`` for unknown backend names rather than raising,
    so a config-load slip-up doesn't take the daemon down — the daemon
    just runs without memory.
    """
    if backend_name == "none":
        return NoneBackend()
    if backend_name == "claude_md":
        root_obj = claude_md_params.get("root", "~/.claude/CLAUDE.md")
        exclude_obj = claude_md_params.get("exclude", [])
        max_bytes_obj = claude_md_params.get("max_bytes", 32 * 1024)
        if not isinstance(max_bytes_obj, int):
            max_bytes_obj = 32 * 1024
        return ClaudeMdBackend(
            root=Path(str(root_obj)),
            follow_references=bool(claude_md_params.get("follow_references", True)),
            max_bytes=max_bytes_obj,
            exclude=list(exclude_obj) if isinstance(exclude_obj, list) else [],
        )
    if backend_name == "custom":
        script_obj = custom_params.get("script", "")
        timeout_obj = custom_params.get("timeout_seconds", 5)
        if not isinstance(timeout_obj, int):
            timeout_obj = 5
        return CustomScriptBackend(
            script=Path(str(script_obj)),
            timeout_seconds=timeout_obj,
        )
    logger.warning(
        "build_backend: unknown backend name %r — falling back to NoneBackend",
        backend_name,
    )
    return NoneBackend()
