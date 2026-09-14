"""Tests for audio_service.py"""
import sys
import os
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.services.audio_service import _extract_audio_indicators


def _create_test_wav(duration_s: float = 1.0) -> str:
    """Create a minimal valid WAV file for testing."""
    import struct
    import math
    sample_rate = 16000
    num_samples = int(sample_rate * duration_s)
    # Generate simple sine wave
    samples = [int(32767 * math.sin(2 * math.pi * 440 * i / sample_rate)) for i in range(num_samples)]
    
    tmp = tempfile.NamedTemporaryFile(suffix=".wav", delete=False)
    
    # WAV header
    data_size = num_samples * 2
    header = struct.pack('<4sI4s4sIHHIIHH4sI',
        b'RIFF', 36 + data_size, b'WAVE', b'fmt ', 16,
        1, 1, sample_rate, sample_rate * 2, 2, 16, b'data', data_size
    )
    tmp.write(header)
    tmp.write(struct.pack(f'<{num_samples}h', *samples))
    tmp.close()
    return tmp.name


def test_audio_indicators_scam():
    text = "This is Amazon customer service. Your account has been suspended. Press 1 to verify your identity."
    indicators = _extract_audio_indicators(text)
    assert len(indicators) > 0
    assert "Call center impersonation" in indicators or "Robocall patterns" in indicators


def test_audio_indicators_safe():
    text = "Hi John, just calling to confirm the meeting tomorrow at 3pm."
    indicators = _extract_audio_indicators(text)
    assert len(indicators) == 0


def test_audio_indicators_otp():
    text = "Please share your OTP to verify your identity and unlock your bank account."
    indicators = _extract_audio_indicators(text)
    assert "Credential / OTP request" in indicators


def test_audio_indicators_financial():
    text = "Send money via bitcoin immediately to avoid arrest warrant from the IRS."
    indicators = _extract_audio_indicators(text)
    assert "Financial fraud attempt" in indicators


def test_analyze_audio_missing_file():
    from backend.services.audio_service import analyze_audio
    result = analyze_audio("/nonexistent/audio_file.wav")
    assert result["error"] is not None
    assert "not found" in result["error"].lower() or "Audio" in result["error"]


def test_analyze_audio_result_structure():
    """Test that analyze_audio returns correct structure even on error."""
    from backend.services.audio_service import analyze_audio
    result = analyze_audio("/nonexistent/file.wav")
    assert "transcript" in result
    assert "scam_probability" in result
    assert "risk_level" in result
    assert "prediction" in result
    assert "indicators" in result
    assert "explanation" in result
    assert "error" in result


def test_analyze_audio_with_wav():
    """Integration: transcribe a real (silent) WAV. May fail gracefully if Whisper isn't loaded."""
    wav_path = _create_test_wav(duration_s=0.5)
    try:
        from backend.services.audio_service import analyze_audio
        result = analyze_audio(wav_path)
        # Even silence should return a valid structure
        assert isinstance(result["transcript"], str)
        assert 0 <= result["scam_probability"] <= 100
    except RuntimeError as e:
        # Whisper model may not be cached yet — acceptable
        assert "Whisper" in str(e) or "whisper" in str(e).lower()
    finally:
        try:
            os.unlink(wav_path)
        except Exception:
            pass
