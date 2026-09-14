"""
SATYA AI 3.0 — Explainable Fraud Analysis Engine
Explains WHY content is suspicious, WHAT indicators were detected with severity and source,
and WHAT the attacker may be trying to achieve, strictly grounded in actual analysis results.
"""

from typing import Any, Dict, List, Optional


# ─── Knowledge & Mapping Taxonomy ───────────────────────────────────────────

INDICATOR_METADATA: Dict[str, Dict[str, Any]] = {
    "urgency": {
        "title": "Urgency & Threat Pressure",
        "severity": "HIGH",
        "explanation": "The content creates artificial pressure by threatening immediate account suspension, deactivation, or deadline penalties.",
        "goals": ["Rush the victim into acting without verifying authenticity"],
        "default_source": "message_model",
    },
    "credential_request": {
        "title": "Credential & OTP Request",
        "severity": "CRITICAL",
        "explanation": "The content requests sensitive authentication details such as OTPs, passwords, PINs, or card numbers.",
        "goals": ["Steal account credentials or OTP to gain unauthorized access"],
        "default_source": "message_model",
    },
    "credential_harvesting": {
        "title": "Credential Harvesting",
        "severity": "CRITICAL",
        "explanation": "The content attempts to solicit confidential authentication credentials or security codes.",
        "goals": ["Steal account credentials or OTP to hijack accounts"],
        "default_source": "message_model",
    },
    "kyc": {
        "title": "KYC Verification Trap",
        "severity": "HIGH",
        "explanation": "The content asks for identity documents or personal verification under threat of service disruption.",
        "goals": ["Obtain sensitive identity documents (Aadhaar, PAN) for identity theft or fraudulent loans"],
        "default_source": "message_model",
    },
    "banking": {
        "title": "Bank Impersonation",
        "severity": "HIGH",
        "explanation": "The communication mimics a recognized financial institution or regulatory body to fabricate authority.",
        "goals": ["Exploit trust in financial institutions to induce compliance"],
        "default_source": "message_model",
    },
    "financial_manipulation": {
        "title": "Financial Manipulation",
        "severity": "HIGH",
        "explanation": "Offers unrealistic lottery rewards, fake cashbacks, or demands upfront payment for non-existent benefits.",
        "goals": ["Deceive the victim into making unauthorized financial transfers"],
        "default_source": "message_model",
    },
    "suspicious_url": {
        "title": "Suspicious / Phishing URL",
        "severity": "HIGH",
        "explanation": "The URL exhibits deceptive patterns, IP-based hosting, excessive subdomains, or known shortener redirection.",
        "goals": ["Redirect the victim to a fraudulent lookalike website to harvest credentials"],
        "default_source": "url_model",
    },
    "phishing": {
        "title": "Phishing Deception",
        "severity": "HIGH",
        "explanation": "Deceptive prompts designed to capture login information or redirect to illicit destinations.",
        "goals": ["Steal user login credentials and session tokens"],
        "default_source": "url_model",
    },
    "upi": {
        "title": "UPI Payment Trap",
        "severity": "HIGH",
        "explanation": "Requests payment approval, PIN entry for receiving money, or fraudulent QR code scanning.",
        "goals": ["Trick the victim into authorizing an outgoing UPI money transfer"],
        "default_source": "message_model",
    },
    "job_scam": {
        "title": "Employment / Recruitment Fraud",
        "severity": "HIGH",
        "explanation": "Offers high-paying work with little effort while soliciting security deposits or processing fees.",
        "goals": ["Extort advance fees under the guise of application or security deposits"],
        "default_source": "message_model",
    },
    "investment_scam": {
        "title": "Investment / High-Return Trap",
        "severity": "HIGH",
        "explanation": "Guarantees unrealistic trading profits or daily returns on cryptocurrency or stock schemes.",
        "goals": ["Induce large upfront capital deposits into untraceable fraudulent accounts"],
        "default_source": "message_model",
    },
    "courier_scam": {
        "title": "Parcel / Customs Scam",
        "severity": "HIGH",
        "explanation": "Claims a package is detained or requires clearance charges, delivery fees, or penalty payments.",
        "goals": ["Demand payment for fictitious parcel customs or delivery charges"],
        "default_source": "message_model",
    },
    "impersonation": {
        "title": "Authority / Identity Impersonation",
        "severity": "HIGH",
        "explanation": "Falsely represents law enforcement, customs officials, government agencies, or well-known brands.",
        "goals": ["Intimidate the victim using authority to force immediate compliance"],
        "default_source": "message_model",
    },
    "romance_scam": {
        "title": "Romance / Relationship Deception",
        "severity": "MEDIUM",
        "explanation": "Builds fake emotional trust to fabricate emergency financial distress or travel crises.",
        "goals": ["Solicit emergency money transfers under emotional manipulation"],
        "default_source": "message_model",
    },
    "voice_clone": {
        "title": "Synthetic Voice / Audio Spoofing",
        "severity": "HIGH",
        "explanation": "Acoustic or spectral patterns suggest artificial speech synthesis or voice cloning.",
        "goals": ["Deceive the recipient into believing they are speaking with a trusted individual"],
        "default_source": "audio_model",
    },
    "deepfake": {
        "title": "Synthetic Facial Manipulation",
        "severity": "HIGH",
        "explanation": "Visual or spectral frequency anomalies detected, suggesting synthetic facial replacement or generation.",
        "goals": ["Fabricate video evidence of a person's presence or identity"],
        "default_source": "video_model",
    },
}


def _match_indicator_type(raw_str: str) -> Optional[str]:
    """Resolve a raw indicator string or signal key to our standardized catalog."""
    norm = raw_str.lower().strip()
    if any(k in norm for k in ["urgenc", "threat", "immediate", "blocked", "suspended", "deadline", "locked"]):
        return "urgency"
    if any(k in norm for k in ["credential_request", "credential harvesting", "credential", "otp", "password", "pin", "cvv"]):
        return "credential_request"
    if any(k in norm for k in ["kyc", "aadhaar", "pan card", "identity verification"]):
        return "kyc"
    if any(k in norm for k in ["bank impersonation", "bank", "rbi", "sbi", "hdfc", "icici"]):
        return "banking"
    if any(k in norm for k in ["financial manipulation", "lottery", "prize", "cashback", "wire transfer"]):
        return "financial_manipulation"
    if any(k in norm for k in ["suspicious_url", "suspicious link", "phishing url", "shortened url", "ip address host", "url"]):
        return "suspicious_url"
    if "upi" in norm:
        return "upi"
    if any(k in norm for k in ["job", "recruitment", "part time", "salary"]):
        return "job_scam"
    if any(k in norm for k in ["invest", "guaranteed return", "crypto", "forex", "trading"]):
        return "investment_scam"
    if any(k in norm for k in ["courier", "parcel", "customs", "delivery fee"]):
        return "courier_scam"
    if any(k in norm for k in ["impersonation", "police", "cbi", "customs officer", "government"]):
        return "impersonation"
    if any(k in norm for k in ["romance", "dating", "relationship"]):
        return "romance_scam"
    if any(k in norm for k in ["voice clone", "voice", "audio clone", "synthetic voice"]):
        return "voice_clone"
    if any(k in norm for k in ["deepfake", "face manipulation", "synthetic video", "gan frequency"]):
        return "deepfake"
    return None


def _calculate_confidence(risk_score: int, evidence_count: int) -> str:
    """Calibrate confidence from risk magnitude and breadth of supporting evidence."""
    if evidence_count >= 2 or risk_score >= 80:
        return "HIGH"
    if evidence_count == 1 or risk_score >= 35:
        return "MEDIUM"
    return "LOW"


def generate_explanation(analysis_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate a structured, explainable fraud report from detector / risk engine output.

    Args:
        analysis_result: Dictionary containing any of:
            - "risk_score" or "final_score" (int)
            - "risk_level" (str: "LOW", "MEDIUM", "HIGH", "CRITICAL")
            - "signals": list of dicts [{"type": ..., "score": ..., "evidence": ...}]
            - "evidence": list of indicator strings
            - "indicators": list of indicator strings
            - "analysis": nested analysis dictionary
            - "risk_assessment": nested risk engine output

    Returns:
        {
            "summary": str,
            "why_suspicious": list[str],
            "evidence": list[dict],
            "attacker_goal": list[str],
            "confidence": str
        }
    """
    if not isinstance(analysis_result, dict):
        return {
            "summary": "Unable to determine threat status due to missing analysis data.",
            "why_suspicious": [],
            "evidence": [],
            "attacker_goal": [],
            "confidence": "LOW",
        }

    # Extract score and level with fallbacks
    risk_score = analysis_result.get("risk_score")
    if risk_score is None:
        risk_score = analysis_result.get("final_score")
    if risk_score is None and isinstance(analysis_result.get("risk_assessment"), dict):
        risk_score = analysis_result["risk_assessment"].get("final_score")
    if risk_score is None and isinstance(analysis_result.get("analysis"), dict):
        risk_score = analysis_result["analysis"].get("probability") or analysis_result["analysis"].get("scam_probability")
    try:
        risk_score = int(risk_score) if risk_score is not None else 0
    except (ValueError, TypeError):
        risk_score = 0

    risk_level = analysis_result.get("risk_level")
    if not risk_level and isinstance(analysis_result.get("risk_assessment"), dict):
        risk_level = analysis_result["risk_assessment"].get("risk_level")
    if not risk_level:
        if risk_score >= 80:
            risk_level = "CRITICAL"
        elif risk_score >= 60:
            risk_level = "HIGH"
        elif risk_score >= 35:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
    risk_level = str(risk_level).upper()

    # Collect raw signals and indicators
    raw_signals: List[Dict[str, Any]] = []
    if isinstance(analysis_result.get("signals"), list):
        for s in analysis_result["signals"]:
            if isinstance(s, dict):
                raw_signals.append(s)
            elif isinstance(s, str):
                raw_signals.append({"type": s, "evidence": s})

    raw_indicators: List[str] = []
    for key in ["indicators", "evidence", "all_indicators"]:
        val = analysis_result.get(key)
        if isinstance(val, list):
            for item in val:
                if isinstance(item, str) and item.strip():
                    raw_indicators.append(item.strip())
                elif isinstance(item, dict) and "type" in item:
                    raw_signals.append(item)

    # Also check nested risk_assessment and analysis
    if isinstance(analysis_result.get("risk_assessment"), dict):
        for item in analysis_result["risk_assessment"].get("evidence", []):
            if isinstance(item, str) and item.strip() and item not in raw_indicators:
                raw_indicators.append(item.strip())

    if isinstance(analysis_result.get("analysis"), dict):
        for item in analysis_result["analysis"].get("indicators", []):
            if isinstance(item, str) and item.strip() and item not in raw_indicators:
                raw_indicators.append(item.strip())

    structured_evidence: List[Dict[str, Any]] = []
    why_suspicious: List[str] = []
    attacker_goals: List[str] = []
    seen_indicator_types = set()

    # 1. Process explicit signals
    for s in raw_signals:
        sig_type = s.get("type", "")
        matched_key = _match_indicator_type(sig_type) or _match_indicator_type(s.get("evidence", ""))
        custom_evidence = s.get("evidence")
        custom_score = s.get("score")
        source = s.get("source")

        if matched_key and matched_key not in seen_indicator_types:
            meta = INDICATOR_METADATA[matched_key]
            seen_indicator_types.add(matched_key)
            explanation_text = meta["explanation"]
            if custom_evidence and len(str(custom_evidence)) < 120:
                explanation_text = f"{explanation_text} (Evidence: \"{custom_evidence}\")"

            structured_evidence.append({
                "indicator": meta["title"],
                "severity": meta["severity"],
                "explanation": explanation_text,
                "source": source or meta["default_source"],
                "score": custom_score,
            })
            why_suspicious.append(meta["explanation"])
            for g in meta["goals"]:
                if g not in attacker_goals:
                    attacker_goals.append(g)

    # 2. Process indicator strings
    for ind in raw_indicators:
        # Ignore generic non-indicator strings
        if any(skip in ind.lower() for skip in ["analysis completed", "no significant", "no analysis data"]):
            continue

        matched_key = _match_indicator_type(ind)
        if matched_key:
            if matched_key not in seen_indicator_types:
                meta = INDICATOR_METADATA[matched_key]
                seen_indicator_types.add(matched_key)
                structured_evidence.append({
                    "indicator": meta["title"],
                    "severity": meta["severity"],
                    "explanation": meta["explanation"],
                    "source": meta["default_source"],
                })
                why_suspicious.append(meta["explanation"])
                for g in meta["goals"]:
                    if g not in attacker_goals:
                        attacker_goals.append(g)
        else:
            # Custom detector-returned indicator
            if ind not in seen_indicator_types:
                seen_indicator_types.add(ind)
                sev = "HIGH" if risk_level in ("HIGH", "CRITICAL") else "MEDIUM"
                structured_evidence.append({
                    "indicator": ind,
                    "severity": sev,
                    "explanation": f"Detected: {ind}.",
                    "source": "detector",
                })
                why_suspicious.append(f"The system detected patterns consistent with {ind.lower()}.")

    # 3. Clean content / Low risk case
    if not why_suspicious:
        if risk_level == "LOW" or risk_score < 35:
            summary = "No significant scam or cyber threat indicators were detected in the analyzed content."
            why_suspicious = ["The content does not exhibit typical deception, credential harvesting, or urgency patterns."]
            confidence = "HIGH"
        else:
            summary = f"The content has an elevated risk score of {risk_score}/100, but detailed threat signals were inconclusive."
            why_suspicious = ["Statistical model evaluation flagged linguistic or behavioral anomalies."]
            confidence = "MEDIUM"
    else:
        if len(why_suspicious) == 1:
            summary = f"This content shows a potential fraud indicator commonly observed in cyber scams (Risk Level: {risk_level})."
        else:
            summary = f"This content exhibits {len(why_suspicious)} distinct indicators commonly associated with cyber fraud and social engineering."
        confidence = _calculate_confidence(risk_score, len(why_suspicious))

    return {
        "summary": summary,
        "why_suspicious": why_suspicious,
        "evidence": structured_evidence,
        "attacker_goal": attacker_goals,
        "confidence": confidence,
    }
