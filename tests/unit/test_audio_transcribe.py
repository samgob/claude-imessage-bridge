"""Tests for the whisper.cpp audio transcription wrapper.

We never spawn real whisper.cpp here — subprocess.run is monkeypatched
to a fake. The tests exercise the surface the daemon depends on:
  - is_audio_file() recognizes Apple voice-memo formats
  - transcribe() returns None when binary or model are missing
  - transcribe() returns the trimmed text on success
  - transcribe() falls back to the .txt sidecar when stdout is empty
  - transcribe() honors the file-size cap
  - transcribe() returns None on timeout / non-zero exit
  - transcript length is capped before return
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from src import audio_transcribe


# --- is_audio_file ------------------------------------------------------


def test_is_audio_file_recognizes_caf():
    assert audio_transcribe.is_audio_file("/tmp/voice.caf")


def test_is_audio_file_recognizes_m4a_mp3_wav():
    assert audio_transcribe.is_audio_file("/x/y.m4a")
    assert audio_transcribe.is_audio_file("/x/y.mp3")
    assert audio_transcribe.is_audio_file("/x/y.wav")


def test_is_audio_file_case_insensitive():
    assert audio_transcribe.is_audio_file("/x/y.CAF")
    assert audio_transcribe.is_audio_file("/x/y.M4A")


def test_is_audio_file_rejects_image():
    assert not audio_transcribe.is_audio_file("/x/y.jpeg")
    assert not audio_transcribe.is_audio_file("/x/y.png")
    assert not audio_transcribe.is_audio_file("/x/y.pdf")


def test_is_audio_file_rejects_unknown_ext():
    assert not audio_transcribe.is_audio_file("/x/y.txt")
    assert not audio_transcribe.is_audio_file("/x/y")


# --- resolve_binary -----------------------------------------------------


def test_resolve_binary_returns_none_when_missing(monkeypatch):
    monkeypatch.setattr(audio_transcribe.shutil, "which", lambda _name: None)
    assert audio_transcribe.resolve_binary() is None


def test_resolve_binary_finds_whisper_cli(monkeypatch):
    monkeypatch.setattr(
        audio_transcribe.shutil,
        "which",
        lambda name: "/opt/homebrew/bin/whisper-cli" if name == "whisper-cli" else None,
    )
    assert audio_transcribe.resolve_binary() == Path("/opt/homebrew/bin/whisper-cli")


def test_resolve_binary_honors_explicit_existing(tmp_path):
    bin_path = tmp_path / "main"
    bin_path.write_text("#!/bin/sh")
    bin_path.chmod(0o755)
    assert audio_transcribe.resolve_binary(str(bin_path)) == bin_path


def test_resolve_binary_explicit_missing_returns_none(tmp_path):
    assert audio_transcribe.resolve_binary(str(tmp_path / "nope")) is None


# --- transcribe ---------------------------------------------------------


def _make_audio(tmp_path: Path, name: str = "voice.wav", size: int = 100) -> Path:
    p = tmp_path / name
    p.write_bytes(b"\x00" * size)
    return p


def test_transcribe_returns_none_when_file_missing(tmp_path):
    result = audio_transcribe.transcribe(str(tmp_path / "ghost.caf"))
    assert result is None


def test_transcribe_returns_none_when_binary_missing(tmp_path, monkeypatch):
    audio = _make_audio(tmp_path)
    monkeypatch.setattr(audio_transcribe, "resolve_binary", lambda explicit=None: None)
    assert audio_transcribe.transcribe(str(audio)) is None


def test_transcribe_returns_none_when_model_missing(tmp_path, monkeypatch):
    audio = _make_audio(tmp_path)
    fake_bin = tmp_path / "bin"
    fake_bin.write_text("#")
    fake_bin.chmod(0o755)
    monkeypatch.setattr(audio_transcribe, "resolve_binary", lambda explicit=None: fake_bin)
    # Force model_path to a non-existent file:
    assert (
        audio_transcribe.transcribe(
            str(audio),
            model_path=str(tmp_path / "nope.bin"),
        )
        is None
    )


def test_transcribe_returns_text_from_stdout(tmp_path, monkeypatch):
    audio = _make_audio(tmp_path)
    fake_bin = tmp_path / "bin"
    fake_bin.write_text("#")
    fake_bin.chmod(0o755)
    model = tmp_path / "model.bin"
    model.write_bytes(b"x")
    monkeypatch.setattr(audio_transcribe, "resolve_binary", lambda explicit=None: fake_bin)

    class _Done:
        returncode = 0
        stdout = b"hello world this is a voice note"
        stderr = b""

    def fake_run(argv, **kwargs):
        # Sanity: the argv carries our paths, not shell.
        assert str(fake_bin) in argv
        assert "-m" in argv
        assert str(model) in argv
        assert "-f" in argv
        # WAV input is now staged into the per-call tempdir before
        # whisper sees it (to keep the -otxt sidecar out of the user's
        # iMessage attachments). So the argv carries the tempdir path,
        # not the original.
        f_idx = argv.index("-f")
        assert "cimb-audio-" in argv[f_idx + 1]
        return _Done()

    monkeypatch.setattr(audio_transcribe.subprocess, "run", fake_run)
    result = audio_transcribe.transcribe(str(audio), model_path=str(model))
    assert result == "hello world this is a voice note"


def test_transcribe_prefers_txt_sidecar_over_stdout(tmp_path, monkeypatch):
    audio = _make_audio(tmp_path, name="voice.wav")
    fake_bin = tmp_path / "bin"
    fake_bin.write_text("#")
    fake_bin.chmod(0o755)
    model = tmp_path / "model.bin"
    model.write_bytes(b"x")
    monkeypatch.setattr(audio_transcribe, "resolve_binary", lambda explicit=None: fake_bin)

    # whisper-cli with -otxt writes <input>.txt next to its input.
    # Since we stage WAV into a tempdir, the sidecar lands there too.
    # Simulate that: when fake whisper "runs", create the .txt next to
    # the tempdir path argv carried.
    class _Done:
        returncode = 0
        stdout = b"stdout-fallback should be ignored"
        stderr = b""

    def fake_run(argv, **_k):
        f_idx = argv.index("-f")
        whisper_input_path = Path(argv[f_idx + 1])
        sidecar = whisper_input_path.with_suffix(whisper_input_path.suffix + ".txt")
        sidecar.write_text("sidecar transcript wins\n")
        return _Done()

    monkeypatch.setattr(audio_transcribe.subprocess, "run", fake_run)
    assert (
        audio_transcribe.transcribe(
            str(audio),
            model_path=str(model),
        )
        == "sidecar transcript wins"
    )


def test_transcribe_returns_none_on_nonzero_exit(tmp_path, monkeypatch):
    audio = _make_audio(tmp_path)
    fake_bin = tmp_path / "bin"
    fake_bin.write_text("#")
    fake_bin.chmod(0o755)
    model = tmp_path / "model.bin"
    model.write_bytes(b"x")
    monkeypatch.setattr(audio_transcribe, "resolve_binary", lambda explicit=None: fake_bin)

    class _Done:
        returncode = 1
        stdout = b""
        stderr = b"error: cannot decode\n"

    monkeypatch.setattr(audio_transcribe.subprocess, "run", lambda *a, **k: _Done())
    assert audio_transcribe.transcribe(str(audio), model_path=str(model)) is None


def test_transcribe_returns_none_on_timeout(tmp_path, monkeypatch):
    audio = _make_audio(tmp_path)
    fake_bin = tmp_path / "bin"
    fake_bin.write_text("#")
    fake_bin.chmod(0o755)
    model = tmp_path / "model.bin"
    model.write_bytes(b"x")
    monkeypatch.setattr(audio_transcribe, "resolve_binary", lambda explicit=None: fake_bin)

    def fake_run(*_a, **_k):
        raise subprocess.TimeoutExpired(cmd="x", timeout=1)

    monkeypatch.setattr(audio_transcribe.subprocess, "run", fake_run)
    assert audio_transcribe.transcribe(str(audio), model_path=str(model)) is None


def test_transcribe_refuses_oversize_file(tmp_path, monkeypatch):
    audio = tmp_path / "huge.wav"
    # Sparse-write a file just over the cap. (write_bytes with the full
    # content would be slow; use seek to make a sparse file.)
    with audio.open("wb") as f:
        f.seek(audio_transcribe.MAX_AUDIO_BYTES + 100)
        f.write(b"\0")

    # resolve_binary must NOT be called — we short-circuit on size.
    def boom(explicit=None):  # noqa: ARG001
        raise AssertionError("size-cap should short-circuit before binary lookup")

    monkeypatch.setattr(audio_transcribe, "resolve_binary", boom)
    assert audio_transcribe.transcribe(str(audio)) is None


def test_transcribe_caps_transcript_length(tmp_path, monkeypatch):
    audio = _make_audio(tmp_path)
    fake_bin = tmp_path / "bin"
    fake_bin.write_text("#")
    fake_bin.chmod(0o755)
    model = tmp_path / "model.bin"
    model.write_bytes(b"x")
    monkeypatch.setattr(audio_transcribe, "resolve_binary", lambda explicit=None: fake_bin)

    huge = "x" * (audio_transcribe.MAX_TRANSCRIPT_BYTES + 5000)

    class _Done:
        returncode = 0
        stdout = huge.encode("utf-8")
        stderr = b""

    monkeypatch.setattr(audio_transcribe.subprocess, "run", lambda *a, **k: _Done())
    result = audio_transcribe.transcribe(str(audio), model_path=str(model))
    assert result is not None
    assert len(result.encode("utf-8")) <= audio_transcribe.MAX_TRANSCRIPT_BYTES + 50
    assert "truncated" in result


def test_transcribe_caf_runs_afconvert_before_whisper(tmp_path, monkeypatch):
    """Regression: 2026-05-19. Whisper.cpp's brew build only reads WAV.
    iMessage voice memos are .caf, so the transcribe path must invoke
    afconvert to produce a 16-kHz mono WAV first, then hand THAT to
    whisper-cli."""
    audio = _make_audio(tmp_path, name="voice.caf")
    fake_bin = tmp_path / "bin"
    fake_bin.write_text("#")
    fake_bin.chmod(0o755)
    model = tmp_path / "model.bin"
    model.write_bytes(b"x")
    monkeypatch.setattr(audio_transcribe, "resolve_binary", lambda explicit=None: fake_bin)

    calls: list = []

    def fake_run(argv, **_kwargs):
        calls.append(list(argv))
        # First call: afconvert. Create the destination WAV so the
        # transcode-success check passes.
        if argv[0].endswith("afconvert"):
            dst = Path(argv[-1])
            dst.write_bytes(b"RIFF" + b"\x00" * 100)

            class _Done:
                returncode = 0
                stdout = b""
                stderr = b""

            return _Done()
        # Second call: whisper-cli on the converted WAV.

        class _Done:
            returncode = 0
            stdout = b"hello world"
            stderr = b""

        return _Done()

    monkeypatch.setattr(audio_transcribe.subprocess, "run", fake_run)
    # Pretend afconvert exists.
    monkeypatch.setattr(
        type(audio_transcribe.AFCONVERT_BIN),
        "is_file",
        lambda _self: True,
    )

    result = audio_transcribe.transcribe(str(audio), model_path=str(model))
    assert result == "hello world"
    # Verify ordering: afconvert called first, then whisper-cli.
    assert len(calls) == 2
    assert calls[0][0].endswith("afconvert")
    # The whisper call's -f input must be a *.wav, NOT the original .caf
    f_idx = calls[1].index("-f")
    whisper_input = calls[1][f_idx + 1]
    assert whisper_input.endswith(".wav")
    assert str(audio) not in calls[1]


def test_transcribe_wav_staged_to_tempdir_not_processed_in_place(tmp_path, monkeypatch):
    """Regression: 2026-05-24 security review. Even when input is already
    WAV, whisper-cli with -otxt writes a `<input>.txt` sidecar adjacent
    to the input. If we passed the original ~/Library/Messages/Attachments
    path, whisper would litter sidecar .txt files in Apple's iMessage
    store (which iCloud Messages may sync). We must stage the WAV into
    our per-call tempdir so the sidecar lands in a directory we own and
    clean up."""
    audio = _make_audio(tmp_path, name="voice.wav")
    audio.write_bytes(b"RIFF" + b"\x00" * 100)  # plausible WAV bytes
    fake_bin = tmp_path / "bin"
    fake_bin.write_text("#")
    fake_bin.chmod(0o755)
    model = tmp_path / "model.bin"
    model.write_bytes(b"x")
    monkeypatch.setattr(audio_transcribe, "resolve_binary", lambda explicit=None: fake_bin)

    calls: list = []

    def fake_run(argv, **_kwargs):
        calls.append(list(argv))

        class _Done:
            returncode = 0
            stdout = b"text"
            stderr = b""

        return _Done()

    monkeypatch.setattr(audio_transcribe.subprocess, "run", fake_run)
    audio_transcribe.transcribe(str(audio), model_path=str(model))
    # One subprocess call (whisper only — no afconvert for WAV).
    assert len(calls) == 1
    assert calls[0][0].endswith("bin")
    # CRITICAL: whisper's -f input must NOT be the original audio file —
    # it must be a copy inside the cimb-audio-* tempdir.
    f_idx = calls[0].index("-f")
    whisper_input = calls[0][f_idx + 1]
    assert whisper_input != str(audio), (
        "WAV must be staged into the tempdir, not processed in place — "
        "otherwise whisper's -otxt sidecar leaks into the user's "
        "~/Library/Messages/Attachments directory."
    )
    assert "cimb-audio-" in whisper_input
    assert whisper_input.endswith(".wav")


def test_transcribe_returns_none_when_afconvert_fails(tmp_path, monkeypatch):
    """If the transcode step fails, transcribe returns None without
    invoking whisper."""
    audio = _make_audio(tmp_path, name="voice.caf")
    fake_bin = tmp_path / "bin"
    fake_bin.write_text("#")
    fake_bin.chmod(0o755)
    model = tmp_path / "model.bin"
    model.write_bytes(b"x")
    monkeypatch.setattr(audio_transcribe, "resolve_binary", lambda explicit=None: fake_bin)
    monkeypatch.setattr(
        audio_transcribe,
        "_transcode_to_wav",
        lambda *_a, **_k: False,
    )
    whisper_called = [False]

    def fake_run(*_a, **_k):
        whisper_called[0] = True

        class _Done:
            returncode = 0
            stdout = b""
            stderr = b""

        return _Done()

    monkeypatch.setattr(audio_transcribe.subprocess, "run", fake_run)
    assert audio_transcribe.transcribe(str(audio), model_path=str(model)) is None
    assert not whisper_called[0]


def test_transcribe_returns_none_on_empty_output(tmp_path, monkeypatch):
    audio = _make_audio(tmp_path)
    fake_bin = tmp_path / "bin"
    fake_bin.write_text("#")
    fake_bin.chmod(0o755)
    model = tmp_path / "model.bin"
    model.write_bytes(b"x")
    monkeypatch.setattr(audio_transcribe, "resolve_binary", lambda explicit=None: fake_bin)

    class _Done:
        returncode = 0
        stdout = b"   \n"
        stderr = b""

    monkeypatch.setattr(audio_transcribe.subprocess, "run", lambda *a, **k: _Done())
    assert audio_transcribe.transcribe(str(audio), model_path=str(model)) is None
