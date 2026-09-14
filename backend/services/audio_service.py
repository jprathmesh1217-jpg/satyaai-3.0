"""
SatyaAI 3.0 — Audio Transcription & Scam Analysis Service
Uses OpenAI Whisper for speech-to-text and NLP heuristics + Message Model
to detect fraudulent call center calls, vishing, and automated robocall scams.
"""

import os
import threading
from pathlib import Path
from typing import Optional, List, Dict, Any

_whisper_model = None
_whisper_lock = threading.Lock()

AUDIO_INDICATORS = {
    "Call center impersonation": [
        "customer service", "call center", "support agent", "representative",
        "amazon customer", "bank support", "executive", "technical department",
    ],
    "Robocall patterns": [
        "press 1", "press 2", "press 9", "automated message", "recorded line",
        "voice automated", "interactive response",
    ],
    "Credential / OTP request": [
        "otp", "one time password", "password", "pin", "credential",
        "security code", "cvv", "verification code",
    ],
    "Financial fraud attempt": [
        "bitcoin", "crypto", "wire transfer", "gift card", "send money",
        "arrest warrant", "irs", "fbi", "police department", "customs",
        "penalty", "court fine",
    ],
    "Urgency / Threats": [
        "suspended", "blocked", "deactivated", "immediate", "urgently",
        "within 24 hours", "legal action", "law enforcement",
    ],
}


def _load_whisper():
    global _whisper_model
    if _whisper_model is not None:
        return _whisper_model

    with _whisper_lock:
        if _whisper_model is not None:
            return _whisper_model
        try:
            import whisper
            _whisper_model = whisper.load_model("tiny")
            return _whisper_model
        except Exception as exc:
            raise RuntimeError(f"Failed to load Whisper audio model: {exc}") from exc


def transcribe_audio(audio_path: str) -> str:
    """Transcribe an audio file using OpenAI Whisper."""
    if not os.path.exists(audio_path):
        raise FileNotFoundError(f"Audio file not found: {audio_path}")

    model = _load_whisper()
    result = model.transcribe(audio_path, fp16=False)
    return (result.get("text") or "").strip()


def _extract_audio_indicators(text: str) -> List[str]:
    """Extract audio-specific fraud and vishing indicators from transcript."""
    text_lower = text.lower()
    found: List[str] = []

    for category, keywords in AUDIO_INDICATORS.items():
        if any(kw in text_lower for kw in keywords):
            found.append(category)

    return found


def _risk_level(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


def analyze_audio(audio_path: str) -> Dict[str, Any]:
    """
    Transcribe audio and analyze for scam / vishing patterns.
    """
    if not audio_path or not os.path.exists(audio_path):
        return {
            "transcript": "",
            "scam_probability": 0,
            "risk_level": "LOW",
            "prediction": "SAFE",
            "indicators": [],
            "explanation": "Audio file not found.",
            "error": f"Audio file not found: {audio_path}",
        }

    try:
        transcript = transcribe_audio(audio_path)
    except Exception as exc:
        return {
            "transcript": "",
            "scam_probability": 0,
            "risk_level": "UNKNOWN",
            "prediction": "UNKNOWN",
            "indicators": [],
            "explanation": "Audio transcription failed.",
            "error": str(exc),
        }

    audio_indicators = _extract_audio_indicators(transcript)

    # Use message analysis on transcript
    try:
        from backend.services.message_service import analyze_message
        msg_res = analyze_message(transcript)
        score = msg_res.get("scam_probability", 0)
        all_indicators = list(dict.fromkeys(audio_indicators + msg_res.get("indicators", [])))
    except Exception:
        score = min(len(audio_indicators) * 25, 95) if audio_indicators else 5
        all_indicators = audio_indicators

    if audio_indicators and score < 45:
        score = min(score + 15 * len(audio_indicators), 95)

    risk = _risk_level(score)
    prediction = "SCAM" if score >= 40 else "SAFE"

    explanation = (
        f"Audio transcript has a scam probability of {score}/100. "
        + (f"Detected indicators: {'; '.join(all_indicators)}." if all_indicators else "No high-risk speech patterns identified.")
    )

    return {
        "transcript": transcript,
        "scam_probability": score,
        "risk_level": risk,
        "prediction": prediction,
        "indicators": all_indicators,
        "explanation": explanation,
        "error": None,
    }