"""
SATYA AI 3.0 — Final Analysis Response Service
Orchestrates Risk Engine scores with Explainable AI and Action Recommendation services
to construct a unified, production-grade threat intelligence payload.
"""

from typing import Any, Dict

from backend.services.action_service import generate_actions
from backend.services.explanation_service import generate_explanation


def _determine_classification(risk_score: int, risk_level: str) -> str:
    """Classify overall threat into standard taxonomy: SAFE, SUSPICIOUS, or MALICIOUS."""
    if risk_level == "CRITICAL":
        return "MALICIOUS"
    if risk_level in ("HIGH", "MEDIUM"):
        return "SUSPICIOUS"
    if risk_level == "LOW":
        return "SAFE"

    if risk_score >= 80:
        return "MALICIOUS"
    if risk_score >= 35:
        return "SUSPICIOUS"
    return "SAFE"


def _generate_digital_dna(analysis_result: Dict[str, Any], risk_score: int, risk_level: str, evidence_list: list) -> Dict[str, Any]:
    """Generate compact Scam Digital DNA fingerprint strictly from actual findings."""
    raw_text = ""
    if isinstance(analysis_result.get("signals"), list):
        for s in analysis_result["signals"]:
            raw_text += f" {s.get('type', '')} {s.get('evidence', '')}"
    for k in ["indicators", "evidence", "all_indicators"]:
        val = analysis_result.get(k)
        if isinstance(val, list):
            raw_text += " " + " ".join(str(x) for x in val)
    if isinstance(analysis_result.get("analysis"), dict):
        for k in ["indicators", "prediction", "scam_type", "detected_category"]:
            v = analysis_result["analysis"].get(k)
            if v:
                raw_text += f" {v}"
    if isinstance(analysis_result.get("risk_assessment"), dict):
        raw_text += " " + " ".join(str(x) for x in analysis_result["risk_assessment"].get("evidence", []))

    modality = str(analysis_result.get("modality") or analysis_result.get("input_type") or "").lower()
    raw_text = (raw_text + " " + modality).lower()

    # Detect patterns
    patterns: list[str] = []
    tokens: list[str] = []

    has_urgency = any(k in raw_text for k in ["urgenc", "threat", "immediate", "blocked", "suspended", "deadline", "locked"])
    has_bank = any(k in raw_text for k in ["bank", "sbi", "hdfc", "icici", "axis", "rbi", "account blocked"])
    has_kyc = any(k in raw_text for k in ["kyc", "aadhaar", "pan card", "identity verification"])
    has_otp = any(k in raw_text for k in ["otp", "credential", "password", "pin", "cvv"])
    has_url = any(k in raw_text for k in ["url", "phish", "link", "http", "domain"]) or modality == "url"
    has_upi = "upi" in raw_text or "collect request" in raw_text
    has_invest = any(k in raw_text for k in ["invest", "crypto", "bitcoin", "forex", "trading", "return"])
    has_job = any(k in raw_text for k in ["job", "recruit", "part time", "salary", "hiring"])
    has_courier = any(k in raw_text for k in ["courier", "parcel", "fedex", "dhl", "customs"])
    has_impersonation = any(k in raw_text for k in ["impersonat", "police", "cbi", "officer", "court"])
    has_deepfake = any(k in raw_text for k in ["deepfake", "face manipulation", "synthetic video", "gan frequency"]) or modality == "video"
    has_voice = any(k in raw_text for k in ["voice clone", "voice spoof", "audio clone"]) or modality == "audio"
    has_financial = any(k in raw_text for k in ["financial manipulation", "lottery", "prize", "cashback", "wire transfer"])

    if has_urgency:
        patterns.append("Urgency")
        tokens.append("URGENT")
    if has_bank:
        patterns.append("Impersonation")
        tokens.append("BANK")
    elif has_impersonation:
        patterns.append("Impersonation")
        tokens.append("AUTH")
    if has_kyc:
        patterns.append("Social Engineering")
        tokens.append("KYC")
    if has_otp:
        patterns.append("Credential Request")
        patterns.append("OTP Request")
        tokens.append("OTP")
    if has_url:
        patterns.append("Suspicious URL")
        tokens.append("URL")
    if has_upi:
        patterns.append("Financial Manipulation")
        tokens.append("UPI")
    if has_invest:
        patterns.append("Financial Manipulation")
        tokens.append("INVEST")
    if has_job:
        patterns.append("Social Engineering")
        tokens.append("JOB")
    if has_courier:
        patterns.append("Social Engineering")
        tokens.append("COURIER")
    if has_deepfake:
        patterns.append("Synthetic Media")
        tokens.append("DEEPFAKE")
    if has_voice:
        patterns.append("Synthetic Media")
        tokens.append("VOICE")
    if has_financial and "Financial Manipulation" not in patterns:
        patterns.append("Financial Manipulation")
        tokens.append("FIN")

    # Primary Scam Type
    if has_kyc and has_bank:
        scam_type = "Banking / KYC Scam"
    elif has_bank:
        scam_type = "Banking Impersonation"
    elif has_upi:
        scam_type = "UPI Payment Scam"
    elif has_kyc:
        scam_type = "KYC Verification Trap"
    elif has_otp:
        scam_type = "OTP & Credential Harvesting"
    elif has_invest:
        scam_type = "Investment Scam"
    elif has_job:
        scam_type = "Job / Recruitment Scam"
    elif has_courier:
        scam_type = "Courier / Customs Scam"
    elif has_deepfake:
        scam_type = "Deepfake Media Scam"
    elif has_voice:
        scam_type = "Voice Clone Scam"
    elif has_url:
        scam_type = "Phishing URL Scam"
    elif has_impersonation:
        scam_type = "Authority Impersonation"
    elif risk_level == "LOW" or risk_score < 35:
        scam_type = "Verified Safe Content"
    else:
        scam_type = "Social Engineering Scam"

    # DNA ID code
    if risk_level == "LOW" or not tokens:
        dna_id = "SAFE-VERIFIED-01"
        if not patterns:
            patterns = ["Clean Verification"]
    else:
        # Deduplicate tokens while preserving order
        unique_tokens = list(dict.fromkeys(tokens))[:4]
        dna_id = "-".join(unique_tokens)

    # Clean Evidence Checkmarks
    clean_evidence: list[str] = []
    if evidence_list:
        for ev in evidence_list:
            title = ev.get("indicator") if isinstance(ev, dict) else str(ev)
            if title and not title.lower().startswith("analysis completed"):
                clean_evidence.append(f"✓ {title} detected")
    elif has_urgency or has_otp or has_kyc or has_url or has_upi:
        if has_urgency: clean_evidence.append("✓ Urgency language detected")
        if has_kyc: clean_evidence.append("✓ KYC information requested")
        if has_url: clean_evidence.append("✓ Suspicious URL detected")
        if has_otp: clean_evidence.append("✓ OTP request detected")
        if has_upi: clean_evidence.append("✓ Unverified payment request detected")
    else:
        clean_evidence.append("✓ No significant fraud indicators detected")

    return {
        "dna_id": dna_id,
        "scam_type": scam_type,
        "attack_patterns": list(dict.fromkeys(patterns)),
        "risk_level": risk_level,
        "risk_score": risk_score,
        "evidence": clean_evidence,
    }


def _generate_attack_flow(analysis_result: Dict[str, Any], risk_score: int, risk_level: str, dna: Dict[str, Any]) -> list[Dict[str, Any]]:
    """Generate visual step-by-step attack progression strictly based on detected stages."""
    if risk_level == "LOW" or risk_score < 35:
        return [
            {"stage": 1, "title": "Content Ingestion", "desc": "Message, link, or media received for verification", "icon": "📥"},
            {"stage": 2, "title": "Heuristic & ML Scan", "desc": "Evaluated against phishing, urgency, and forgery models", "icon": "🔬"},
            {"stage": 3, "title": "Authenticity Confirmed", "desc": "No deceptive markers or credential theft indicators detected", "icon": "✅"},
        ]

    patterns = dna.get("attack_patterns", [])
    stages: list[Dict[str, Any]] = []
    step_num = 1

    # Stage 1: Approach / Impersonation
    if "Impersonation" in patterns:
        stages.append({
            "stage": step_num,
            "title": "Impersonation",
            "desc": "Sender mimics a trusted bank, company, or government authority",
            "icon": "🏦",
        })
    elif "Synthetic Media" in patterns:
        stages.append({
            "stage": step_num,
            "title": "Synthetic Identity",
            "desc": "Uses AI-generated deepfake facial manipulation or voice clone",
            "icon": "🎭",
        })
    else:
        stages.append({
            "stage": step_num,
            "title": "Initial Contact",
            "desc": "Unsolicited text, phishing link, or suspicious media reaches the victim",
            "icon": "📩",
        })
    step_num += 1

    # Stage 2: Pressure / Pretext
    if "Urgency" in patterns:
        stages.append({
            "stage": step_num,
            "title": "Urgency Pressure",
            "desc": "Fabricates imminent account suspension, penalty, or deadline to panic victim",
            "icon": "🚨",
        })
        step_num += 1

    # Stage 3: Deceptive Vector
    if "Suspicious URL" in patterns:
        stages.append({
            "stage": step_num,
            "title": "Deceptive Link",
            "desc": "Redirects victim to a spoofed external website designed to harvest inputs",
            "icon": "🔗",
        })
        step_num += 1
    elif "Social Engineering" in patterns:
        stages.append({
            "stage": step_num,
            "title": "KYC / Service Trap",
            "desc": "Requests personal identity verification or document uploads",
            "icon": "🪪",
        })
        step_num += 1
    elif "Financial Manipulation" in patterns:
        stages.append({
            "stage": step_num,
            "title": "Payment Lure",
            "desc": "Promises cashback, lottery winnings, or requires collect request approval",
            "icon": "💳",
        })
        step_num += 1

    # Stage 4: Credential Extraction
    if "Credential Request" in patterns or "OTP Request" in patterns:
        stages.append({
            "stage": step_num,
            "title": "Credential / OTP Request",
            "desc": "Demands passwords, PINs, or one-time passcodes to breach security",
            "icon": "🔐",
        })
        step_num += 1

    # Final Stage: Consequence
    stages.append({
        "stage": step_num,
        "title": "Account Compromise / Financial Loss",
        "desc": "Attacker attempts unauthorized fund transfer or personal identity theft",
        "icon": "💸",
    })

    return stages


def _extract_multimodal_evidence(analysis_result: Dict[str, Any]) -> list[Dict[str, Any]]:
    """Gather all modalities actually analyzed and their verified outcomes."""
    multimodal_list = []
    active_modalities = analysis_result.get("modalities_used") or analysis_result.get("modalities_analyzed") or []

    # If single modality provided
    single_modality = analysis_result.get("modality") or analysis_result.get("input_type")
    if single_modality and single_modality not in active_modalities:
        active_modalities = [single_modality]

    breakdown = analysis_result.get("breakdown") or {}
    if isinstance(analysis_result.get("risk_assessment"), dict):
        if not breakdown:
            breakdown = analysis_result["risk_assessment"].get("breakdown", {})
        if not active_modalities:
            active_modalities = analysis_result["risk_assessment"].get("modalities_used", [])

    indiv_results = analysis_result.get("individual_results") or {}

    for mod in active_modalities:
        m_lower = str(mod).lower()
        score = None
        result_label = "Analyzed"

        if m_lower in breakdown:
            score = breakdown[m_lower].get("score")
        elif m_lower in indiv_results:
            score = indiv_results[m_lower].get("probability") or indiv_results[m_lower].get("scam_probability")
        elif m_lower == single_modality:
            score = analysis_result.get("risk_score") or analysis_result.get("final_score")
            if score is None and isinstance(analysis_result.get("analysis"), dict):
                score = analysis_result["analysis"].get("probability") or analysis_result["analysis"].get("scam_probability")

        try:
            score_int = int(score) if score is not None else None
        except (ValueError, TypeError):
            score_int = None

        if score_int is not None:
            if score_int >= 80:
                result_label = f"CRITICAL ({score_int}/100)"
                level = "CRITICAL"
            elif score_int >= 60:
                result_label = f"HIGH ({score_int}/100)"
                level = "HIGH"
            elif score_int >= 35:
                result_label = f"MEDIUM ({score_int}/100)"
                level = "MEDIUM"
            else:
                result_label = f"LOW ({score_int}/100)"
                level = "LOW"
        else:
            level = "ANALYZED"

        mod_display = {
            "message": "Message / SMS",
            "url": "URL / Phishing",
            "image": "Image / OCR",
            "audio": "Audio Recording",
            "video": "Video Deepfake",
        }.get(m_lower, m_lower.capitalize())

        multimodal_list.append({
            "modality": mod_display,
            "status": "✓ Analyzed",
            "result": result_label,
            "score": score_int,
            "risk_level": level,
        })

    return multimodal_list


def build_final_analysis(analysis_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build the complete, explainable final analysis response including Digital DNA and Attack Flow.
    """
    if not isinstance(analysis_result, dict):
        analysis_result = {}

    # Extract score with robust fallbacks
    risk_score = analysis_result.get("risk_score")
    if risk_score is None:
        risk_score = analysis_result.get("final_score")
    if risk_score is None and isinstance(analysis_result.get("risk_assessment"), dict):
        risk_score = analysis_result["risk_assessment"].get("final_score")
    if risk_score is None and isinstance(analysis_result.get("analysis"), dict):
        risk_score = analysis_result["analysis"].get("probability") or analysis_result["analysis"].get("scam_probability")
    try:
        risk_score = int(round(float(risk_score))) if risk_score is not None else 0
    except (ValueError, TypeError):
        risk_score = 0
    risk_score = max(0, min(100, risk_score))

    # Extract risk level with existing threshold rules
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

    classification = _determine_classification(risk_score, risk_level)

    # Generate Explanation & Actions
    explanation = generate_explanation(analysis_result)
    actions = generate_actions(analysis_result)

    # Generate Scam Digital DNA & Attack Flow
    digital_dna = _generate_digital_dna(analysis_result, risk_score, risk_level, explanation.get("evidence", []))
    attack_flow = _generate_attack_flow(analysis_result, risk_score, risk_level, digital_dna)
    multimodal_evidence = _extract_multimodal_evidence(analysis_result)

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "classification": classification,
        "summary": explanation.get("summary", ""),
        "why_suspicious": explanation.get("why_suspicious", []),
        "evidence": explanation.get("evidence", []),
        "attacker_goal": explanation.get("attacker_goal", []),
        "immediate_actions": actions.get("immediate_actions", []),
        "avoid": actions.get("avoid", []),
        "verification_steps": actions.get("verification_steps", []),
        "confidence": explanation.get("confidence", "LOW"),
        "digital_dna": digital_dna,
        "attack_flow": attack_flow,
        "multimodal_evidence": multimodal_evidence,
    }
