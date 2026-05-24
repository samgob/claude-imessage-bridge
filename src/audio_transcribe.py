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
import tempfile
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

# whisper.cpp's Homebrew build only reads WAV. iMessage voice memos are
# CAF (Apple Core Audio Format), and other shares may be m4a/aac/mp3 —
# all of which we have to transcode to 16-kHz mono WAV first. macOS
# ships `afconvert` for free; it handles every iMessage-attachment
# audio format we expect to see, no extra dependency.
AFCONVERT_BIN: Final = Path("/usr/bin/afconvert")

# Whisper.cpp's wav reader handles these directly — no transcode needed.
_NATIVE_WAV_EXTS: Final = frozenset({".wav"})


def _transcode_to_wav(
    src: Path, dst: Path, timeout_seconds: int = 30,
) -> bool:
    """Convert ``src`` (any afconvert-supported format) to 16-kHz mono
    WAV at ``dst``. Returns True on success.

    16-kHz mono WAV matches whisper.cpp's expected input shape exactly,
    so no further resampling happens inside whisper.cpp.
    """
    if not AFCONVERT_BIN.is_file():
        logger.warning(
            "afconvert not found at %s — can't transcode %s to WAV. "
            "(afconvert ships with macOS; this should be impossible.)",
            AFCONVERT_BIN, src,
        )
        return False
    # Fixed argv. No shell. Source path comes from the chat.db
    # attachment resolver (already vetted); dst is operator-controlled
    # (a fresh tempfile in this module).
    argv = [
        str(AFCONVERT_BIN),
        str(src),
        "-f", "WAVE",
        "-d", "LEI16@16000",  # little-endian int16, 16 kHz
        "-c", "1",            # mono
        str(dst),
    ]
    try:
        proc = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.warning("afconvert failed on %s: %s", src, e)
        return False
    if proc.returncode != 0:
        logger.warning(
            "afconvert exit=%d on %s: %s",
            proc.returncode, src,
            proc.stderr.decode("utf-8", errors="replace")[:300],
        )
        return False
    return dst.is_file() and dst.stat().st_size > 0


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

    # whisper.cpp's brew build reads only WAV. iMessage voice memos are
    # .caf (Apple Core Audio); .m4a / .aac / .mp3 also need transcoding.
    # We hand off to afconvert (macOS-native) for anything non-WAV,
    # writing the converted file into a per-call tempdir so we always
    # clean up.
    #
    # Even when the input IS already WAV we route through the tempdir
    # rather than passing the original path: whisper-cli's -otxt flag
    # writes a `<input>.txt` sidecar adjacent to the input file. If we
    # passed the original path under ~/Library/Messages/Attachments/,
    # whisper would litter sidecar .txt files in the user's iMessage
    # attachment store (which Apple may sync via iCloud Messages). The
    # tempdir keeps the sidecar in a directory we own and clean up.
    cleanup_dir = tempfile.TemporaryDirectory(prefix="cimb-audio-")
    whisper_input = Path(cleanup_dir.name) / "in.wav"
    if p.suffix.lower() in _NATIVE_WAV_EXTS:
        # Cheap copy — the file is ≤ 25 MB by the cap above, and we
        # need it in our tempdir so the sidecar lands there too.
        try:
            shutil.copyfile(p, whisper_input)
        except OSError as e:
            logger.warning("failed to stage WAV %s into tempdir: %s", p, e)
            cleanup_dir.cleanup()
            return None
    else:
        if not _transcode_to_wav(p, whisper_input):
            cleanup_dir.cleanup()
            return None

    try:
        # Fixed argv — no shell, no user input. -nt: omit timestamps;
        # -otxt: also write transcript to <input>.txt as a fallback for
        # builds that don't print to stdout.
        argv = [
            str(bin_path),
            "-m", str(model),
            "-f", str(whisper_input),
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

        # Prefer the .txt sidecar (more reliable across builds). Fall
        # back to stdout.
        txt_path = whisper_input.with_suffix(whisper_input.suffix + ".txt")
        text: Optional[str] = None
        if txt_path.is_file():
            try:
                text = txt_path.read_text(encoding="utf-8", errors="replace").strip()
            except OSError as e:
                logger.warning("failed to read sidecar %s: %s", txt_path, e)
        if not text:
            text = result.stdout.decode("utf-8", errors="replace").strip()
    finally:
        cleanup_dir.cleanup()

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
