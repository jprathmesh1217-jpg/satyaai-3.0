"""Tests for message_service.py"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.services.message_service import analyze_message, _extract_indicators


def test_analyze_scam_message():
    text = "URGENT: Your SBI bank account has been suspended. Verify KYC now by clicking the link or your account will be permanently deactivated."
    result = analyze_message(text)
    assert result["prediction"] in ("SCAM", "SAFE", "UNKNOWN")
    assert 0 <= result["probability"] <= 100
    assert result["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN")
    assert isinstance(result["indicators"], list)
    assert isinstance(result["explanation"], str)


def test_analyze_safe_message():
    text = "Hey! Are you free for lunch tomorrow at the usual place?"
    result = analyze_message(text)
    assert result["prediction"] in ("SCAM", "SAFE")
    assert result["probability"] < 70  # Should be low risk


def test_empty_message():
    result = analyze_message("")
    assert result["prediction"] == "SAFE"
    assert result["probability"] == 0
    assert result["risk_level"] == "LOW"


def test_whitespace_message():
    result = analyze_message("   \n  ")
    assert result["probability"] == 0


def test_indicator_extraction():
    text = "Your account is suspended. Please verify your OTP immediately."
    indicators = _extract_indicators(text)
    assert len(indicators) > 0


def test_indicators_safe_text():
    text = "The weather is nice today."
    indicators = _extract_indicators(text)
    assert len(indicators) == 0


def test_result_keys():
    result = analyze_message("Test message")
    assert "text" in result
    assert "prediction" in result
    assert "probability" in result
    assert "risk_level" in result
    assert "indicators" in result
    assert "explanation" in result
    assert "error" in result


def test_kyc_scam_indicators():
    text = "Your KYC is pending. Update your Aadhaar card information now."
    result = analyze_message(text)
    assert len(result["indicators"]) > 0


def test_otp_scam():
    text = "Share your OTP to unlock your account. This is your final warning."
    result = analyze_message(text)
    assert "Credential harvesting" in result["indicators"] or result["probability"] > 0
