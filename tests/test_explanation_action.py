"""
Tests for SATYA AI 3.0 — Explanation & Recommended Action Engines.
Validates the 10 required scenarios, deterministic grounding, and the FastAPI explanation endpoint.
"""

import os
import sys
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.main import app
from backend.services.explanation_service import generate_explanation
from backend.services.action_service import generate_actions
from backend.services.analysis_response_service import build_final_analysis

client = TestClient(app)


# ── Scenario 1: Safe message ──────────────────────────────────────────────────

def test_safe_message():
    input_data = {
        "risk_score": 10,
        "risk_level": "LOW",
        "evidence": [],
        "indicators": [],
    }
    final = build_final_analysis(input_data)
    assert final["risk_score"] == 10
    assert final["risk_level"] == "LOW"
    assert final["classification"] == "SAFE"
    assert len(final["evidence"]) == 0
    assert any("Continue with caution" in act for act in final["immediate_actions"])
    assert any("Do not share sensitive information" in av for av in final["avoid"])
    assert len(final["verification_steps"]) > 0


# ── Scenario 2: Suspicious banking message ────────────────────────────────────

def test_suspicious_banking_message():
    input_data = {
        "risk_score": 75,
        "risk_level": "HIGH",
        "signals": [
            {"type": "banking", "evidence": "SBI alert: Account blocked today"}
        ],
    }
    final = build_final_analysis(input_data)
    assert final["risk_score"] == 75
    assert final["risk_level"] == "HIGH"
    assert final["classification"] == "SUSPICIOUS"
    # Check banking indicator present
    assert any("Bank" in ev["indicator"] for ev in final["evidence"])
    # Check banking verification guidance present
    assert any("bank" in step.lower() for step in final["verification_steps"])
    assert any("Do not share OTP" in av for av in final["avoid"])


# ── Scenario 3: OTP scam ──────────────────────────────────────────────────────

def test_otp_scam():
    input_data = {
        "risk_score": 92,
        "risk_level": "CRITICAL",
        "indicators": ["Credential harvesting"],
    }
    final = build_final_analysis(input_data)
    assert final["risk_score"] == 92
    assert final["risk_level"] == "CRITICAL"
    assert final["classification"] == "MALICIOUS"
    assert any("Credential" in ev["indicator"] for ev in final["evidence"])
    assert any("OTP" in goal for goal in final["attacker_goal"])
    assert any("Never share OTP" in av for av in final["avoid"])


# ── Scenario 4: KYC scam ──────────────────────────────────────────────────────

def test_kyc_scam():
    input_data = {
        "risk_score": 85,
        "risk_level": "CRITICAL",
        "signals": [
            {"type": "kyc", "evidence": "Update KYC details immediately or SIM blocked"}
        ],
    }
    final = build_final_analysis(input_data)
    assert final["risk_score"] == 85
    assert final["risk_level"] == "CRITICAL"
    assert any("KYC" in ev["indicator"] for ev in final["evidence"])
    assert any("identity" in goal.lower() or "aadhaar" in goal.lower() for goal in final["attacker_goal"])
    assert any("identity documents" in av.lower() for av in final["avoid"])
    assert any("kyc" in step.lower() or "contact details" in step.lower() for step in final["verification_steps"])


# ── Scenario 5: UPI scam ──────────────────────────────────────────────────────

def test_upi_scam():
    input_data = {
        "risk_score": 70,
        "risk_level": "HIGH",
        "signals": [
            {"type": "upi", "evidence": "Approve UPI collect request to receive $500 cashback"}
        ],
    }
    final = build_final_analysis(input_data)
    assert final["risk_score"] == 70
    assert final["risk_level"] == "HIGH"
    assert any("UPI" in ev["indicator"] for ev in final["evidence"])
    assert any("UPI PIN" in av for av in final["avoid"])
    assert any("recipient" in step.lower() for step in final["verification_steps"])


# ── Scenario 6: Suspicious URL ────────────────────────────────────────────────

def test_suspicious_url():
    input_data = {
        "risk_score": 88,
        "risk_level": "CRITICAL",
        "modality": "url",
        "signals": [
            {"type": "suspicious_url", "evidence": "http://192.168.1.1/paypal-verify"}
        ],
    }
    final = build_final_analysis(input_data)
    assert final["risk_score"] == 88
    assert any("URL" in ev["indicator"] or "Phishing" in ev["indicator"] for ev in final["evidence"])
    assert any("website" in goal.lower() or "credential" in goal.lower() for goal in final["attacker_goal"])
    assert any("links" in act.lower() for act in final["immediate_actions"])


# ── Scenario 7: High-risk message ─────────────────────────────────────────────

def test_high_risk_message():
    input_data = {
        "risk_score": 68,
        "risk_level": "HIGH",
        "evidence": ["Urgency / Threat language", "Financial manipulation"],
    }
    final = build_final_analysis(input_data)
    assert final["risk_level"] == "HIGH"
    assert final["classification"] == "SUSPICIOUS"
    assert any("Do not click suspicious links" in act for act in final["immediate_actions"])
    assert any("Do not transfer money" in av for av in final["avoid"])
    assert len(final["evidence"]) == 2


# ── Scenario 8: Critical-risk message ─────────────────────────────────────────

def test_critical_risk_message():
    input_data = {
        "risk_score": 95,
        "risk_level": "CRITICAL",
        "signals": [
            {"type": "urgency", "evidence": "Account terminated in 1 hour"},
            {"type": "credential_request", "evidence": "Send OTP now"},
            {"type": "suspicious_url", "evidence": "http://scam.ru/login"},
        ],
    }
    final = build_final_analysis(input_data)
    assert final["risk_score"] == 95
    assert final["risk_level"] == "CRITICAL"
    assert final["classification"] == "MALICIOUS"
    assert len(final["evidence"]) == 3
    assert any("Stop interacting with the sender immediately" in act for act in final["immediate_actions"])
    assert any("Do not continue the conversation" in av for av in final["avoid"])


# ── Scenario 9: Missing evidence / Optional fields ────────────────────────────

def test_missing_evidence():
    # Empty input dictionary must not crash
    final_empty = build_final_analysis({})
    assert final_empty["risk_score"] == 0
    assert final_empty["risk_level"] == "LOW"
    assert final_empty["classification"] == "SAFE"
    assert isinstance(final_empty["immediate_actions"], list)
    assert isinstance(final_empty["avoid"], list)
    assert isinstance(final_empty["verification_steps"], list)

    # Input with None values
    final_none = build_final_analysis({
        "risk_score": None,
        "risk_level": None,
        "signals": None,
        "evidence": None,
    })
    assert final_none["risk_score"] == 0
    assert final_none["risk_level"] == "LOW"

    # Explanation and action generators directly
    exp = generate_explanation({})
    assert exp["summary"] != ""
    act = generate_actions({})
    assert len(act["immediate_actions"]) > 0


# ── Scenario 10: Unknown scam category ────────────────────────────────────────

def test_unknown_scam_category():
    input_data = {
        "risk_score": 45,
        "risk_level": "MEDIUM",
        "indicators": ["Quantum Teleportation Anomaly 404"],
    }
    final = build_final_analysis(input_data)
    assert final["risk_score"] == 45
    assert final["risk_level"] == "MEDIUM"
    assert final["classification"] == "SUSPICIOUS"
    assert any("Quantum Teleportation" in ev["indicator"] for ev in final["evidence"])
    # Falls back gracefully to medium baseline actions
    assert any("Verify the sender" in act for act in final["immediate_actions"])
    assert len(final["verification_steps"]) > 0


# ── FastAPI Endpoint: POST /api/analyze/explanation ───────────────────────────

def test_api_explanation_endpoint():
    payload = {
        "risk_score": 91,
        "risk_level": "HIGH",
        "signals": [
            {
                "type": "urgency",
                "score": 0.92,
                "evidence": "Your account will be blocked today"
            },
            {
                "type": "credential_request",
                "score": 0.95,
                "evidence": "Share your OTP and KYC details"
            },
            {
                "type": "suspicious_url",
                "score": 0.89,
                "evidence": "https://example.com/verify"
            }
        ]
    }
    resp = client.post("/api/analyze/explanation", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    analysis = data["analysis"]
    assert analysis["risk_score"] == 91
    assert analysis["risk_level"] == "HIGH"
    assert analysis["classification"] == "SUSPICIOUS"
    assert len(analysis["why_suspicious"]) >= 3
    assert len(analysis["evidence"]) == 3
    assert len(analysis["attacker_goal"]) >= 2
    assert len(analysis["immediate_actions"]) > 0
    assert len(analysis["avoid"]) > 0
    assert len(analysis["verification_steps"]) > 0
