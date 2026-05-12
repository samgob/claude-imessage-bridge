"""Tests for config.load + validation.

Config load is a security boundary: a misconfigured allowed_tools list
(or a swap-attack on the claude binary path) means the daemon's tool deny
guarantees evaporate. These tests verify the refuse-to-start preconditions.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
import yaml

from src import config as config_mod


def _write(path: Path, mapping: dict) -> None:
    path.write_text(yaml.safe_dump(mapping))


def _good_yaml(project_dir: Path, claude_bin: Path) -> dict:
    return {
        "project_directory": str(project_dir),
        "allowlist": ["+15551234567"],
        "allow_group_chat_guids": [],
        "allowed_tools": [],
        "forbidden_tools": [],
        "poll_interval_seconds": 3.0,
        "reply_rate_limit_per_minute": 10,
        "daily_cost_cap_usd": 5.0,
        "per_call_cost_cap_usd": 0.50,
        "per_call_max_turns": 1,
        "per_call_timeout_seconds": 90,
        "circuit_breaker_failures": 5,
        "claude_binary": str(claude_bin),
        "debug": False,
    }


# --- happy path --------------------------------------------------------

def test_load_happy_path(tmp_path: Path, fake_claude_binary: Path):
    cfg_path = tmp_path / "config.yaml"
    project = tmp_path / "proj"
    project.mkdir()
    _write(cfg_path, _good_yaml(project, fake_claude_binary))
    cfg = config_mod.load(cfg_path)
    assert cfg.project_directory == project
    assert cfg.allowlist == ["+15551234567"]
    assert cfg.allowed_tools == []
    assert cfg.daily_cost_cap_usd == 5.0


def test_load_normalizes_email_allowlist(tmp_path: Path, fake_claude_binary: Path):
    cfg_path = tmp_path / "config.yaml"
    project = tmp_path / "proj"
    project.mkdir()
    data = _good_yaml(project, fake_claude_binary)
    data["allowlist"] = ["User@Example.COM"]
    _write(cfg_path, data)
    cfg = config_mod.load(cfg_path)
    assert cfg.allowlist == ["user@example.com"]


# --- missing file ------------------------------------------------------

def test_load_missing_file(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        config_mod.load(tmp_path / "nope.yaml")


# --- allowed_tools validation -----------------------------------------

def test_load_refuses_missing_allowed_tools_key(tmp_path: Path, fake_claude_binary: Path):
    cfg_path = tmp_path / "config.yaml"
    project = tmp_path / "proj"
    project.mkdir()
    data = _good_yaml(project, fake_claude_binary)
    del data["allowed_tools"]
    _write(cfg_path, data)
    with pytest.raises(ValueError, match="allowed_tools"):
        config_mod.load(cfg_path)


def test_load_refuses_bash_in_allowed_tools(tmp_path: Path, fake_claude_binary: Path):
    cfg_path = tmp_path / "config.yaml"
    project = tmp_path / "proj"
    project.mkdir()
    data = _good_yaml(project, fake_claude_binary)
    data["allowed_tools"] = ["Bash"]
    _write(cfg_path, data)
    with pytest.raises(ValueError, match="hard-forbidden"):
        config_mod.load(cfg_path)


def test_load_refuses_mcp_tool_in_allowed_tools(tmp_path: Path, fake_claude_binary: Path):
    cfg_path = tmp_path / "config.yaml"
    project = tmp_path / "proj"
    project.mkdir()
    data = _good_yaml(project, fake_claude_binary)
    data["allowed_tools"] = ["mcp__personal__send_message"]
    _write(cfg_path, data)
    with pytest.raises(ValueError, match="MCP"):
        config_mod.load(cfg_path)


def test_load_refuses_overlap_allowed_and_forbidden(tmp_path: Path, fake_claude_binary: Path):
    cfg_path = tmp_path / "config.yaml"
    project = tmp_path / "proj"
    project.mkdir()
    data = _good_yaml(project, fake_claude_binary)
    data["allowed_tools"] = ["Read"]
    data["forbidden_tools"] = ["Read"]
    _write(cfg_path, data)
    with pytest.raises(ValueError, match="both"):
        config_mod.load(cfg_path)


# --- numeric bounds ----------------------------------------------------

def test_load_refuses_zero_cost_cap(tmp_path: Path, fake_claude_binary: Path):
    cfg_path = tmp_path / "config.yaml"
    project = tmp_path / "proj"
    project.mkdir()
    data = _good_yaml(project, fake_claude_binary)
    data["daily_cost_cap_usd"] = 0
    _write(cfg_path, data)
    with pytest.raises(ValueError, match="daily_cost_cap_usd"):
        config_mod.load(cfg_path)


def test_load_refuses_per_call_cap_exceeding_daily(tmp_path: Path, fake_claude_binary: Path):
    cfg_path = tmp_path / "config.yaml"
    project = tmp_path / "proj"
    project.mkdir()
    data = _good_yaml(project, fake_claude_binary)
    data["per_call_cost_cap_usd"] = 100.0
    data["daily_cost_cap_usd"] = 5.0
    _write(cfg_path, data)
    with pytest.raises(ValueError, match="per_call"):
        config_mod.load(cfg_path)


def test_load_refuses_rate_limit_out_of_range(tmp_path: Path, fake_claude_binary: Path):
    cfg_path = tmp_path / "config.yaml"
    project = tmp_path / "proj"
    project.mkdir()
    data = _good_yaml(project, fake_claude_binary)
    data["reply_rate_limit_per_minute"] = 0
    _write(cfg_path, data)
    with pytest.raises(ValueError, match="reply_rate_limit"):
        config_mod.load(cfg_path)


def test_load_refuses_poll_too_small(tmp_path: Path, fake_claude_binary: Path):
    cfg_path = tmp_path / "config.yaml"
    project = tmp_path / "proj"
    project.mkdir()
    data = _good_yaml(project, fake_claude_binary)
    data["poll_interval_seconds"] = 0.1
    _write(cfg_path, data)
    with pytest.raises(ValueError, match="poll_interval"):
        config_mod.load(cfg_path)


def test_load_refuses_max_turns_out_of_range(tmp_path: Path, fake_claude_binary: Path):
    cfg_path = tmp_path / "config.yaml"
    project = tmp_path / "proj"
    project.mkdir()
    data = _good_yaml(project, fake_claude_binary)
    data["per_call_max_turns"] = 50
    _write(cfg_path, data)
    with pytest.raises(ValueError, match="per_call_max_turns"):
        config_mod.load(cfg_path)


# --- allowlist ---------------------------------------------------------

def test_load_refuses_empty_allowlist(tmp_path: Path, fake_claude_binary: Path):
    cfg_path = tmp_path / "config.yaml"
    project = tmp_path / "proj"
    project.mkdir()
    data = _good_yaml(project, fake_claude_binary)
    data["allowlist"] = []
    _write(cfg_path, data)
    with pytest.raises(ValueError, match="allowlist"):
        config_mod.load(cfg_path)


def test_load_refuses_malformed_allowlist_entry(tmp_path: Path, fake_claude_binary: Path):
    cfg_path = tmp_path / "config.yaml"
    project = tmp_path / "proj"
    project.mkdir()
    data = _good_yaml(project, fake_claude_binary)
    data["allowlist"] = ["not-a-real-handle"]
    _write(cfg_path, data)
    with pytest.raises(ValueError, match="allowlist"):
        config_mod.load(cfg_path)


# --- project_directory -------------------------------------------------

def test_load_refuses_nonexistent_project_dir(tmp_path: Path, fake_claude_binary: Path):
    cfg_path = tmp_path / "config.yaml"
    data = _good_yaml(tmp_path / "doesnotexist", fake_claude_binary)
    _write(cfg_path, data)
    with pytest.raises(ValueError, match="project_directory"):
        config_mod.load(cfg_path)


def test_load_refuses_relative_project_dir(tmp_path: Path, fake_claude_binary: Path):
    cfg_path = tmp_path / "config.yaml"
    data = _good_yaml(tmp_path / "proj", fake_claude_binary)
    data["project_directory"] = "relative/path"
    _write(cfg_path, data)
    with pytest.raises(ValueError, match="absolute"):
        config_mod.load(cfg_path)


# --- claude_binary validation -----------------------------------------

def test_load_refuses_missing_claude_binary(tmp_path: Path):
    cfg_path = tmp_path / "config.yaml"
    project = tmp_path / "proj"
    project.mkdir()
    data = _good_yaml(project, tmp_path / "no-claude-here")
    _write(cfg_path, data)
    with pytest.raises(ValueError, match="claude_binary"):
        config_mod.load(cfg_path)


def test_load_refuses_world_writable_claude_binary(tmp_path: Path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    binary = bin_dir / "claude"
    binary.write_text("#!/bin/sh\n")
    os.chmod(binary, 0o777)  # world writable: refused
    cfg_path = tmp_path / "config.yaml"
    project = tmp_path / "proj"
    project.mkdir()
    data = _good_yaml(project, binary)
    _write(cfg_path, data)
    with pytest.raises(ValueError, match="writable"):
        config_mod.load(cfg_path)


def test_load_accepts_symlinked_claude_binary(tmp_path: Path):
    """Homebrew installs claude as a symlink; that must work."""
    real_dir = tmp_path / "Cellar"
    real_dir.mkdir()
    real_binary = real_dir / "claude"
    real_binary.write_text("#!/bin/sh\n")
    os.chmod(real_binary, 0o755)
    link_dir = tmp_path / "bin"
    link_dir.mkdir()
    link = link_dir / "claude"
    os.symlink(real_binary, link)

    cfg_path = tmp_path / "config.yaml"
    project = tmp_path / "proj"
    project.mkdir()
    data = _good_yaml(project, link)
    _write(cfg_path, data)
    cfg = config_mod.load(cfg_path)
    assert cfg.claude_binary == str(link)
