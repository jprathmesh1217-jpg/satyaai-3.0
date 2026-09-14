"""
SatyaAI 3.0 — Call Threat Model Standalone Verification Script
Tests call transcript scam classification and behavioral deception signal extraction.
"""

import sys
import os
import json
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.services.call_service import analyze_call_transcript


def run_call_tests():
    print("========================================")
    print("SATYAAI 3.0 — CALL THREAT MODEL VERIFICATION")
    print("========================================")

    # CALL TEST 1: Vishing, OTP extortion & KYC threat
    c1_transcript = "Hello, I am calling from your bank. Your account will be suspended today. Please provide your OTP immediately to complete KYC verification."
    print("\n--- Running Call Test 1 (Scam Candidate) ---")
    print(f"Transcript: {c1_transcript}")

    res1 = analyze_call_transcript(c1_transcript)
    ml1 = res1["analysis"]["ml"]
    risk1 = res1["analysis"]["risk"]

    print("Result                :", ml1.get("result"))
    print("Scam Probability      :", f"{ml1.get('scam_probability')}%")
    print("Non-Scam Probability  :", f"{ml1.get('non_scam_probability')}%")
    print("Risk Level            :", risk1.get("risk_level"))
    print("Risk Score            :", f"{risk1.get('risk_score')}/100")
    print("Evidence Signals      :", [s["type"] for s in res1["analysis"]["signals"]])

    assert ml1["prediction"] == 1, f"Expected scam prediction (1), got {ml1['prediction']}"
    assert ml1["result"] == "SCAM"
    assert ml1["scam_probability"] > 50.0

    # CALL TEST 2: Benign reminder
    c2_transcript = "Hello everyone, this is a reminder about tomorrow's department meeting at 10 AM."
    print("\n--- Running Call Test 2 (Non-Scam Candidate) ---")
    print(f"Transcript: {c2_transcript}")

    res2 = analyze_call_transcript(c2_transcript)
    ml2 = res2["analysis"]["ml"]
    risk2 = res2["analysis"]["risk"]

    print("Result                :", ml2.get("result"))
    print("Scam Probability      :", f"{ml2.get('scam_probability')}%")
    print("Non-Scam Probability  :", f"{ml2.get('non_scam_probability')}%")
    print("Risk Level            :", risk2.get("risk_level"))
    print("Risk Score            :", f"{risk2.get('risk_score')}/100")
    print("Evidence Signals      :", [s["type"] for s in res2["analysis"]["signals"]])

    assert ml2["prediction"] == 0, f"Expected non-scam prediction (0), got {ml2['prediction']}"
    assert ml2["result"] == "NON-SCAM"
    assert ml2["non_scam_probability"] > 50.0

    print("\n========================================")
    print("ALL CALL TESTS PASSED SUCCESSFULLY! ✓")
    print("========================================")


if __name__ == "__main__":
    run_call_tests()
