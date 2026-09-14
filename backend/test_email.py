"""
SatyaAI 3.0 — Email Threat Model Standalone Verification Script
Tests email threat classification and signal extraction on phishing vs legitimate samples.
"""

import sys
import os
import json
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.services.email_service import analyze_email


def run_email_tests():
    print("========================================")
    print("SATYAAI 3.0 — EMAIL THREAT MODEL VERIFICATION")
    print("========================================")

    # EMAIL TEST 1: Phishing & KYC urgency
    t1_subject = "URGENT: Your bank account will be suspended"
    t1_body = "Your account requires immediate KYC verification. Provide your OTP immediately to prevent suspension."
    print("\n--- Running Email Test 1 (Phishing Candidate) ---")
    print(f"Subject: {t1_subject}")
    print(f"Body   : {t1_body}")

    res1 = analyze_email(subject=t1_subject, body=t1_body, sender="security@sbi-update-kyc.com")
    ml1 = res1["analysis"]["ml"]
    risk1 = res1["analysis"]["risk"]

    print("Result                :", ml1.get("result"))
    print("Phishing Probability  :", f"{ml1.get('phishing_probability')}%")
    print("Legitimate Probability:", f"{ml1.get('legitimate_probability')}%")
    print("Risk Level            :", risk1.get("risk_level"))
    print("Risk Score            :", f"{risk1.get('risk_score')}/100")
    print("Evidence Signals      :", [s["type"] for s in res1["analysis"]["signals"]])

    assert ml1["prediction"] == 1, f"Expected phishing prediction (1), got {ml1['prediction']}"
    assert ml1["result"] == "PHISHING"
    assert ml1["phishing_probability"] > 50.0

    # EMAIL TEST 2: Benign workplace communication
    t2_subject = "Project Meeting Tomorrow"
    t2_body = "The project meeting will be held tomorrow at 10 AM. Please bring your project documentation."
    print("\n--- Running Email Test 2 (Legitimate Candidate) ---")
    print(f"Subject: {t2_subject}")
    print(f"Body   : {t2_body}")

    res2 = analyze_email(subject=t2_subject, body=t2_body, sender="coordinator@company.org")
    ml2 = res2["analysis"]["ml"]
    risk2 = res2["analysis"]["risk"]

    print("Result                :", ml2.get("result"))
    print("Phishing Probability  :", f"{ml2.get('phishing_probability')}%")
    print("Legitimate Probability:", f"{ml2.get('legitimate_probability')}%")
    print("Risk Level            :", risk2.get("risk_level"))
    print("Risk Score            :", f"{risk2.get('risk_score')}/100")
    print("Evidence Signals      :", [s["type"] for s in res2["analysis"]["signals"]])

    assert ml2["prediction"] == 0, f"Expected legitimate prediction (0), got {ml2['prediction']}"
    assert ml2["result"] == "LEGITIMATE"
    assert ml2["legitimate_probability"] > 50.0

    print("\n========================================")
    print("ALL EMAIL TESTS PASSED SUCCESSFULLY! ✓")
    print("========================================")


if __name__ == "__main__":
    run_email_tests()
