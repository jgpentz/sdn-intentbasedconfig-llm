"""Record a spoken network intent and transcribe it with local Whisper.

This uses the open-source Whisper model on this machine. It does not call
the paid OpenAI transcription API.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import numpy as np
import sounddevice as sd
import whisper
from scipy.io import wavfile

WHISPER_MODEL = os.environ.get("WHISPER_MODEL", "base.en")
SAMPLE_RATE = 16000
INITIAL_PROMPT = (
    "Network policy for hosts h1, h2, h3, and h4. "
    "Block all traffic from h1 to h3. "
    "Allow only ICMP traffic between h2 and h4. "
    "Block all traffic on port 80 from any host to h4."
)

_model = None


def capture_voice_intent(duration: float = 5.0) -> str:
    """Record from the microphone and return the transcribed text.

    ``duration`` is the recording length in seconds. The audio is saved as a
    temporary WAV file, transcribed with local Whisper, and then the file is
    removed.
    """

    if duration <= 0:
        raise ValueError("duration must be greater than zero.")

    frames = int(duration * SAMPLE_RATE)
    print(f"Recording for {duration:.0f} seconds. Speak a network policy now.")
    audio = sd.rec(frames, samplerate=SAMPLE_RATE, channels=1, dtype="float32")
    sd.wait()

    pcm = np.clip(audio, -1.0, 1.0)
    pcm = (pcm * 32767).astype(np.int16)

    handle = tempfile.NamedTemporaryFile(prefix="lab7-intent-", suffix=".wav", delete=False)
    path = Path(handle.name)
    handle.close()
    try:
        wavfile.write(path, SAMPLE_RATE, pcm)
        print(f"Saved recording to {path}")
        return transcribe_wav(path)
    finally:
        path.unlink(missing_ok=True)


def transcribe_wav(path: Path) -> str:
    """Transcribe a WAV file with the local Whisper model."""

    result = _load_model().transcribe(
        str(path),
        language="en",
        fp16=False,
        initial_prompt=INITIAL_PROMPT,
    )
    return result.get("text", "").strip()


def _load_model():
    global _model
    if _model is None:
        print(f"Loading local Whisper model {WHISPER_MODEL}.")
        _model = whisper.load_model(WHISPER_MODEL)
    return _model
