"""Unit and Integration tests for Email Threat and Call Threat endpoints."""
import os
import sys
import io
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from backend.main import app

client = TestClient(app)


# ── Health Endpoint ─────────────────────────────────────────────────────────

def test_health_reports_email_and_call_models():
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "models" in data
    models = data["models"]
    assert "email" in models
    assert "call" in models
    assert models["email"] is True
    assert models["call"] is True


# ── Email Threat Endpoint (/api/analyze/email) ───────────────────────────────

def test_analyze_email_phishing():
    payload = {
        "subject": "URGENT: Your SBI Bank Account Has Been Suspended",
        "sender": "security-alert@sbi-fraud-verification.com",
        "body": "Dear customer, your SBI account is locked due to incomplete KYC. Click http://192.168.1.100/verify-sbi to enter your OTP and password immediately.",
    }
    resp = client.post("/api/analyze/email", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["type"] == "email"
    assert "analysis_id" in data
    assert "analysis" in data
    assert "risk_assessment" in data
    assert "final_analysis" in data

    analysis = data["analysis"]
    assert analysis["ml"]["result"] == "PHISHING"
    assert analysis["ml"]["phishing_probability"] > 50.0
    assert data["risk_assessment"]["final_score"] >= 60
    assert data["risk_assessment"]["risk_level"] in ["HIGH", "CRITICAL"]


def test_analyze_email_safe():
    payload = {
        "subject": "Project Meeting Tomorrow",
        "sender": "coordinator@company.org",
        "body": "The project meeting will be held tomorrow at 10 AM. Please bring your project documentation.",
    }
    resp = client.post("/api/analyze/email", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    analysis = data["analysis"]
    assert analysis["ml"]["result"] == "LEGITIMATE"
    assert analysis["ml"]["legitimate_probability"] > 50.0
    assert data["risk_assessment"]["risk_level"] in ["LOW", "MEDIUM"]


def test_analyze_email_validation_error():
    # Empty body
    resp = client.post("/api/analyze/email", json={"subject": "Test", "body": ""})
    assert resp.status_code == 422


# ── Email File Endpoint (/api/analyze/email/file) ────────────────────────────

def test_analyze_email_file_valid_eml():
    raw_eml = (
        b"From: security@fake-bank.com\r\n"
        b"To: victim@example.com\r\n"
        b"Subject: Immediate action required: Verify Account\r\n"
        b"Date: Fri, 11 Sep 2026 10:00:00 +0000\r\n"
        b"Reply-To: attacker-inbox@phish-drop.net\r\n"
        b"Authentication-Results: spf=fail; dkim=none; dmarc=fail\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Your account will be suspended. Visit http://evil-login-verify.com/bank to submit your OTP.\r\n"
    )
    files = {"file": ("suspicious_mail.eml", io.BytesIO(raw_eml), "message/rfc822")}
    resp = client.post("/api/analyze/email/file", files=files)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["type"] == "email"
    assert "analysis_id" in data
    analysis = data["analysis"]
    assert "headers" in analysis
    headers = analysis["headers"]
    assert headers["subject"] == "Immediate action required: Verify Account"
    assert headers["authentication"]["spf"] == "fail"
    assert headers["authentication"]["dmarc"] == "fail"
    assert analysis["ml"]["result"] == "PHISHING"
    assert data["risk_assessment"]["final_score"] >= 60


def test_analyze_email_file_invalid_extension():
    files = {"file": ("malicious.exe", io.BytesIO(b"MZ..."), "application/octet-stream")}
    resp = client.post("/api/analyze/email/file", files=files)
    assert resp.status_code == 400
    assert "Unsupported file type" in resp.json()["detail"]


# ── Call Threat Text Endpoint (/api/analyze/call/text) ───────────────────────

def test_analyze_call_text_scam():
    payload = {
        "transcript": "Hello, I am calling from the bank fraud department. Your account is compromised. Tell me the OTP you just received to cancel the transaction."
    }
    resp = client.post("/api/analyze/call/text", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["type"] == "call"
    assert "analysis_id" in data
    analysis = data["analysis"]
    assert analysis["ml"]["result"] == "SCAM"
    assert analysis["ml"]["scam_probability"] > 50.0
    assert "OTP_REQUEST" in analysis["behavioral_signals"] or "BANK_IMPERSONATION" in analysis["behavioral_signals"]
    assert data["risk_assessment"]["final_score"] >= 60


def test_analyze_call_text_safe():
    payload = {
        "transcript": "Hello everyone, this is a reminder about tomorrow's department meeting at 10 AM."
    }
    resp = client.post("/api/analyze/call/text", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    analysis = data["analysis"]
    assert analysis["ml"]["result"] == "NON-SCAM"
    assert analysis["ml"]["non_scam_probability"] > 50.0
    assert data["risk_assessment"]["risk_level"] in ["LOW", "MEDIUM"]


def test_analyze_call_text_validation_error():
    resp = client.post("/api/analyze/call/text", json={"transcript": ""})
    assert resp.status_code == 422


# ── Call Audio File Endpoint (/api/analyze/call) ─────────────────────────────

def test_analyze_call_audio_invalid_extension():
    files = {"file": ("notes.pdf", io.BytesIO(b"%PDF..."), "application/pdf")}
    resp = client.post("/api/analyze/call", files=files)
    assert resp.status_code == 400
    assert "Unsupported file type" in resp.json()["detail"]
