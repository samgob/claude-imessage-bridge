"""Tests for memory backends.

NoneBackend is the trivial control. ClaudeMdBackend is the interesting
one: lazy reference loading with token-match scoring + caching + byte-cap.
CustomScriptBackend exercises a subprocess for the OSS extension hatch.
"""

from __future__ import annotations

import stat
from pathlib import Path


from src import memory as memory_mod


# --- Helpers -------------------------------------------------------------

def _make_memory_tree(root_dir: Path) -> Path:
    """Build a fake CLAUDE.md + memory/ tree under ``root_dir``.

    Returns the CLAUDE.md path. The memory tree is structured like
    Sam's: memory/projects/, memory/people/, memory/context/, each
    with a few sample .md files.
    """
    claude_md = root_dir / "CLAUDE.md"
    claude_md.write_text(
        "# Sam\n\n"
        "EVP at Upstage. Active deals: Wesco, Samsung, LexisNexis.\n"
    )
    memory = root_dir / "memory"
    memory.mkdir()
    (memory / "projects").mkdir()
    (memory / "people").mkdir()
    (memory / "context").mkdir()
    (memory / "projects" / "wesco.md").write_text(
        "# Wesco POC\n\nUC1 94.3%, UC2 96.7%. Nidhi review call pending.\n"
    )
    (memory / "projects" / "samsung.md").write_text(
        "# Samsung Install 3\n\nDocker/firewall issues; kickoff May 6.\n"
    )
    (memory / "people" / "brian.md").write_text(
        "# Brian Lawing\n\nUpstage Sales/BD lead.\n"
    )
    (memory / "context" / "conferences.md").write_text(
        "# Conferences\n\nINTNY, MCEIF coming up.\n"
    )
    return claude_md


# --- NoneBackend ---------------------------------------------------------

def test_none_backend_returns_empty():
    backend = memory_mod.NoneBackend()
    r = backend.context_for("what's wesco status")
    assert r.text == ""
    assert r.sources == []


# --- _tokenize -----------------------------------------------------------

def test_tokenize_drops_stopwords_and_short():
    tokens = memory_mod._tokenize("What is the status of Wesco today?")
    # 'what', 'is', 'the', 'of', 'today' are stopwords (or <3 chars after split)
    assert "wesco" in tokens
    assert "status" in tokens
    assert "what" not in tokens
    assert "the" not in tokens


def test_tokenize_lowercases():
    tokens = memory_mod._tokenize("WESCO Status")
    assert "wesco" in tokens
    assert "WESCO" not in tokens


def test_tokenize_dedupes():
    tokens = memory_mod._tokenize("wesco wesco status wesco")
    assert tokens.count("wesco") == 1


# --- ClaudeMdBackend basic shape ----------------------------------------

def test_claude_md_loads_eager_core(tmp_path: Path):
    claude_md = _make_memory_tree(tmp_path)
    backend = memory_mod.ClaudeMdBackend(root=claude_md, max_bytes=32 * 1024)
    r = backend.context_for("hello")
    # Eager core always loads even on no-token-match queries.
    assert "EVP at Upstage" in r.text
    assert len(r.sources) >= 1
    assert r.sources[0][0] == str(claude_md)


def test_claude_md_loads_matched_reference(tmp_path: Path):
    claude_md = _make_memory_tree(tmp_path)
    backend = memory_mod.ClaudeMdBackend(root=claude_md, max_bytes=32 * 1024)
    r = backend.context_for("what's wesco status today")
    # CLAUDE.md + wesco.md should both be in the loaded sources.
    src_paths = [s[0] for s in r.sources]
    assert any("CLAUDE.md" in p for p in src_paths)
    assert any("wesco.md" in p for p in src_paths)
    # And the body should contain wesco-specific content.
    assert "UC1 94.3%" in r.text


def test_claude_md_no_match_no_reference_loaded(tmp_path: Path):
    """A query with no matching tokens loads only CLAUDE.md."""
    claude_md = _make_memory_tree(tmp_path)
    backend = memory_mod.ClaudeMdBackend(root=claude_md, max_bytes=32 * 1024)
    r = backend.context_for("xyzzy nothing matches this")
    src_paths = [s[0] for s in r.sources]
    assert any("CLAUDE.md" in p for p in src_paths)
    # No reference files matched.
    assert not any("wesco" in p or "samsung" in p for p in src_paths)


def test_claude_md_excluded_paths_skipped(tmp_path: Path):
    claude_md = _make_memory_tree(tmp_path)
    # Add a secret file under memory/projects/ that the exclude pattern
    # should keep out of context.
    (tmp_path / "memory" / "projects" / "wesco_secrets.md").write_text(
        "secret credentials for wesco\n"
    )
    backend = memory_mod.ClaudeMdBackend(
        root=claude_md, max_bytes=32 * 1024, exclude=[r"secrets"]
    )
    r = backend.context_for("wesco")
    src_paths = [s[0] for s in r.sources]
    assert not any("secrets" in p for p in src_paths)


def test_claude_md_max_bytes_cap(tmp_path: Path):
    """If the cumulative load exceeds max_bytes, it stops."""
    claude_md = _make_memory_tree(tmp_path)
    # Make one project file enormous so it triggers truncation.
    big = "x" * (50 * 1024)
    (tmp_path / "memory" / "projects" / "huge.md").write_text(
        f"# huge\n\n{big}\n"
    )
    backend = memory_mod.ClaudeMdBackend(root=claude_md, max_bytes=4 * 1024)
    r = backend.context_for("huge")
    # The total bytes loaded should not exceed the cap by more than the
    # truncation marker overhead.
    assert sum(b for _, b in r.sources) <= 4 * 1024 + 200


def test_claude_md_missing_root_returns_empty(tmp_path: Path):
    """A non-existent root produces empty context, with a warning."""
    backend = memory_mod.ClaudeMdBackend(
        root=tmp_path / "no_such_file.md", max_bytes=32 * 1024
    )
    r = backend.context_for("anything")
    assert r.text == ""
    assert r.sources == []


def test_claude_md_caches_results(tmp_path: Path):
    """Second call with same query returns the same MemoryLoadResult."""
    claude_md = _make_memory_tree(tmp_path)
    backend = memory_mod.ClaudeMdBackend(root=claude_md, max_bytes=32 * 1024)
    r1 = backend.context_for("wesco status")
    r2 = backend.context_for("wesco status")
    assert r1 is r2  # cache hit returns the SAME object


def test_claude_md_follow_references_disabled(tmp_path: Path):
    """``follow_references=False`` should only load the eager core."""
    claude_md = _make_memory_tree(tmp_path)
    backend = memory_mod.ClaudeMdBackend(
        root=claude_md, follow_references=False, max_bytes=32 * 1024
    )
    r = backend.context_for("wesco")
    src_paths = [s[0] for s in r.sources]
    assert any("CLAUDE.md" in p for p in src_paths)
    assert not any("wesco.md" in p for p in src_paths)


# --- CustomScriptBackend -------------------------------------------------

def test_custom_script_runs_and_captures_stdout(tmp_path: Path):
    script = tmp_path / "context.sh"
    script.write_text(
        "#!/bin/bash\n"
        'echo "context for: $(cat)"\n'
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    backend = memory_mod.CustomScriptBackend(script=script, timeout_seconds=5)
    r = backend.context_for("hello world")
    assert "context for: hello world" in r.text
    assert len(r.sources) == 1
    assert r.sources[0][0] == str(script)


def test_custom_script_non_executable_returns_empty(tmp_path: Path):
    script = tmp_path / "context.sh"
    script.write_text("#!/bin/bash\necho hi\n")
    # Don't chmod +x.
    backend = memory_mod.CustomScriptBackend(script=script)
    r = backend.context_for("query")
    assert r.text == ""
    assert r.sources == []


def test_custom_script_failure_returns_empty(tmp_path: Path):
    script = tmp_path / "context.sh"
    script.write_text("#!/bin/bash\nexit 17\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    backend = memory_mod.CustomScriptBackend(script=script)
    r = backend.context_for("query")
    assert r.text == ""


def test_custom_script_timeout_returns_empty(tmp_path: Path):
    script = tmp_path / "context.sh"
    script.write_text("#!/bin/bash\nsleep 10\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    backend = memory_mod.CustomScriptBackend(script=script, timeout_seconds=1)
    r = backend.context_for("query")
    assert r.text == ""


# --- build_backend factory -----------------------------------------------

def test_build_backend_none():
    b = memory_mod.build_backend(
        backend_name="none", claude_md_params={}, custom_params={},
    )
    assert isinstance(b, memory_mod.NoneBackend)


def test_build_backend_claude_md(tmp_path: Path):
    claude_md = _make_memory_tree(tmp_path)
    b = memory_mod.build_backend(
        backend_name="claude_md",
        claude_md_params={
            "root": str(claude_md),
            "follow_references": True,
            "max_bytes": 32768,
            "exclude": [],
        },
        custom_params={},
    )
    assert isinstance(b, memory_mod.ClaudeMdBackend)
    r = b.context_for("wesco")
    assert "wesco" in r.text.lower()


def test_build_backend_unknown_falls_back_to_none():
    b = memory_mod.build_backend(
        backend_name="invalid", claude_md_params={}, custom_params={},
    )
    assert isinstance(b, memory_mod.NoneBackend)
