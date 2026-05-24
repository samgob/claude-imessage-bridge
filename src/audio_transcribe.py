"""Audio transcription via whisper.cpp.

iMessage voice memos arrive as Apple's CAF (Core Audio Format); other
attachments may be m4a / mp3 / wav. Claude Code's Read tool can't decode
audio. The bridge shells out to a locally-installed whisper.cpp binary
to produce a transcript, then inlines that transcript into the prompt
as plain text so the model sees the user's words.

This module is offline-by-design — no API calls, no network. The user
must install whisper.cpp themselves:
    brew install whisper-cpp
    bash ~/whisper.cpp/models/download-ggml-model.sh base.en  # or similar

When the binary or model is missing, ``transcribe`` returns None and
the daemon surfaces a setup-hint reply instead of confused silence.

Security model:
- We only invoke the discovered binary (shutil.which result) with a
  fixed argv shape — no shell, no user-supplied flags.
- Audio path comes from the chat.db attachment resolver, which already
  vets paths to live under ~/Library/Messages/Attachments/.
- Subprocess timeout caps wallclock time per call. Audio file size is
  capped before spawn to prevent a pathological file from running
  whisper.cpp for minutes.
- whisper.cpp's stdout is treated as untrusted text (the user's
  transcribed words); we do not interpret it as anything but text and
  enforce a length cap before returning.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path
from typing import Final, Optional

logger = logging.getLogger(__name__)

# Audio file extensions we'll attempt to transcribe. Apple's iMessage
# Voice Memos write .caf; sharing from Voice Memos.app writes .m4a.
AUDIO_EXTENSIONS: Final = frozenset({
    ".caf",
    ".m4a",
    ".mp3",
    ".wav",
    ".aac",
    ".ogg",
    ".flac",
})


def is_audio_file(path: str) -> bool:
    """True if the path's extension is in our audio allowlist."""
    return Path(path).suffix.lower() in AUDIO_EXTENSIONS


# Whisper.cpp binary candidates, in preference order. Homebrew installs
# `whisper-cli`; building from source typically produces `main` in the
# repo root.
_BIN_CANDIDATES: Final = ("whisper-cli", "main")

# Hard cap on audio file size we'll attempt. iMessage voice memos are
# typically <5MB; the 25MB ceiling guards against a pathologically
# large file (e.g. a shared 30-min .wav) running whisper for minutes.
MAX_AUDIO_BYTES: Final = 25 * 1024 * 1024

# Default whisper.cpp model. base.en is a good accuracy/speed tradeoff
# for short English voice notes (~150MB, ~1x realtime on Apple Silicon).
# Override via config (Config.whisper_model_path).
DEFAULT_MODEL_PATH: Final = (
    Path.home() / "whisper.cpp" / "models" / "ggml-base.en.bin"
)

# Cap on transcription wallclock time. Beyond this we kill the process.
TRANSCRIBE_TIMEOUT_SECONDS: Final = 60

# Cap on transcript length we return. whisper.cpp could in principle
# produce arbitrary text; we trim before returning so a malicious or
# pathological audio file can't blow out the claude prompt budget.
MAX_TRANSCRIPT_BYTES: Final = 16 * 1024


def resolve_binary(explicit: Optional[str] = None) -> Optional[Path]:
    """Find a whisper.cpp binary on PATH, or honor an explicit override.

    ``explicit`` lets the operator point at a non-PATH install (e.g. a
    locally-built binary at ``~/code/whisper.cpp/main``).

    Returns None if nothing usable is found.
    """
    if explicit:
        p = Path(explicit).expanduser()
        return p if p.is_file() else None
    for name in _BIN_CANDIDATES:
        found = shutil.which(name)
        if found:
            return Path(found)
    return None


def transcribe(
    audio_path: str,
    *,
    binary: Optional[str] = None,
    model_path: Optional[str] = None,
    timeout_seconds: int = TRANSCRIBE_TIMEOUT_SECONDS,
) -> Optional[str]:
    """Transcribe one audio file. Returns the transcript or None.

    None means: binary missing, model missing, file too large or missing,
    process error, timeout, or empty output. Caller decides how to
    surface the failure to the user.
    """
    p = Path(audio_path)
    if not p.is_file():
        logger.warning("audio file missing: %s", audio_path)
        return None
    try:
        size = p.stat().st_size
    except OSError as e:
        logger.warning("stat failed on audio file %s: %s", audio_path, e)
        return None
    if size > MAX_AUDIO_BYTES:
        logger.warning(
            "audio file %s exceeds size cap (%d > %d) — skipping",
            audio_path, size, MAX_AUDIO_BYTES,
        )
        return None

    bin_path = resolve_binary(binary)
    if bin_path is None:
        logger.warning(
            "whisper.cpp binary not found on PATH (tried %s). "
            "Install with `brew install whisper-cpp` and download a "
            "model with `bash ./models/download-ggml-model.sh base.en`.",
            list(_BIN_CANDIDATES),
        )
        return None

    model = Path(model_path or DEFAULT_MODEL_PATH).expanduser()
    if not model.is_file():
        logger.warning(
            "whisper.cpp model not found at %s. Set whisper_model_path "
            "in config.yaml or download a model with "
            "`bash ./models/download-ggml-model.sh base.en`.",
            model,
        )
        return None

    # Fixed argv — no shell, no user input. -nt: omit timestamps;
    # -otxt: also write transcript to <input>.txt as a fallback for
    # builds that don't print to stdout.
    argv = [
        str(bin_path),
        "-m", str(model),
        "-f", str(p),
        "-nt",
        "-otxt",
    ]
    try:
        result = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.error(
            "whisper.cpp timeout on %s after %ds",
            audio_path, timeout_seconds,
        )
        return None
    except OSError as e:
        logger.error("whisper.cpp spawn failed: %s", e)
        return None

    if result.returncode != 0:
        logger.warning(
            "whisper.cpp exit=%d on %s: %s",
            result.returncode, audio_path,
            result.stderr.decode("utf-8", errors="replace")[:400],
        )
        return None

    # Prefer the .txt sidecar (more reliable across builds). Fall back
    # to stdout.
    txt_path = p.with_suffix(p.suffix + ".txt")
    text: Optional[str] = None
    if txt_path.is_file():
        try:
            text = txt_path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError as e:
            logger.warning("failed to read sidecar %s: %s", txt_path, e)
    if not text:
        text = result.stdout.decode("utf-8", errors="replace").strip()

    if not text:
        return None

    # Cap untrusted output before handing to the daemon.
    encoded = text.encode("utf-8")
    if len(encoded) > MAX_TRANSCRIPT_BYTES:
        cut = MAX_TRANSCRIPT_BYTES
        while cut > 0 and (encoded[cut] & 0xC0) == 0x80:
            cut -= 1
        text = encoded[:cut].decode("utf-8", errors="ignore") + " […truncated]"
    return text
