"""
SatyaAI 3.0 — Call Threat Intelligence Service
Uses scikit-learn Logistic Regression + TF-IDF Vectorizer trained on vishing and scam call transcripts.
Performs audio transcription via Whisper, extracts call behavioral deception signals,
evaluates embedded links/numbers, and synthesizes unified risk scoring.
"""

import re
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional

from backend.services.url_service import analyze_url
from backend.services.forensic_correlation_service import correlate_forensics
from backend.services.risk_engine import compute_risk
from backend.services.audio_service import transcribe_audio

BASE_DIR = Path(__file__).resolve().parents[2]
MODEL_DIR = BASE_DIR / "models"
CALL_MODEL_PATH = MODEL_DIR / "call_threat_model.pkl"
CALL_VEC_PATH = MODEL_DIR / "call_tfidf_vectorizer.pkl"

_model = None
_vectorizer = None
_lock = threading.Lock()


def _load_call_models():
    """Load call classification model and TF-IDF vectorizer once."""
    global _model, _vectorizer
    if _model is not None and _vectorizer is not None:
        return _model, _vectorizer

    with _lock:
        if _model is not None and _vectorizer is not None:
            return _model, _vectorizer

        import joblib

        if not CALL_MODEL_PATH.exists():
            raise FileNotFoundError(f"Call threat model not found at {CALL_MODEL_PATH}")
        if not CALL_VEC_PATH.exists():
            raise FileNotFoundError(f"Call TF-IDF vectorizer not found at {CALL_VEC_PATH}")

        try:
            _model = joblib.load(CALL_MODEL_PATH)
            _vectorizer = joblib.load(CALL_VEC_PATH)
        except Exception as exc:
            raise RuntimeError(f"Failed to load call threat model: {exc}") from exc

    return _model, _vectorizer


CALL_SIGNAL_PATTERNS = {
    "OTP_REQUEST": {
        "keywords": ["otp", "one time password", "verification code", "security code", "tell me the otp", "share the code"],
        "description": "Caller requested a one-time password or authentication code",
    },
    "PIN_REQUEST": {
        "keywords": ["pin", "atm pin", "upi pin", "secret pin", "enter your pin"],
        "description": "Caller requested an ATM or UPI security PIN",
    },
    "CVV_REQUEST": {
        "keywords": ["cvv", "card verification", "3 digit number", "security digits", "expiry date and cvv"],
        "description": "Caller requested payment card CVV or security digits",
    },
    "PASSWORD_REQUEST": {
        "keywords": ["password", "netbanking password", "login password", "share your password"],
        "description": "Caller requested banking or portal password",
    },
    "KYC_REQUEST": {
        "keywords": ["kyc", "know your customer", "kyc verification", "update your kyc", "kyc pending", "kyc expired"],
        "description": "Caller demanded urgent KYC verification under threat of deactivation",
    },
    "AADHAAR_PAN_REQUEST": {
        "keywords": ["aadhaar", "pan card", "pan number", "social security", "identity number"],
        "description": "Caller requested personal identity card details (Aadhaar/PAN)",
    },
    "BANK_IMPERSONATION": {
        "keywords": ["calling from your bank", "sbi branch", "hdfc security", "icici bank", "rbi official", "bank manager", "customer care manager"],
        "description": "Caller claimed to represent an official banking institution",
    },
    "UPI_REQUEST": {
        "keywords": ["upi", "collect request", "scan qr", "gpay", "phonepe", "paytm", "accept request"],
        "description": "Caller instructed to approve a UPI collect request or scan QR code",
    },
    "MONEY_TRANSFER": {
        "keywords": ["wire transfer", "send money", "transfer funds", "deposit money", "processing charge", "courier fee"],
        "description": "Caller demanded an immediate money transfer or upfront fee",
    },
    "URGENCY_THREATS": {
        "keywords": ["account suspended", "blocked today", "immediate arrest", "police warrant", "legal action", "within 1 hour"],
        "description": "Caller used urgent deadlines and intimidation tactics",
    },
    "PRIZE_REWARD": {
        "keywords": ["lottery", "won a car", "cash prize", "lucky draw", "claim reward", "congratulations you won"],
        "description": "Caller claimed the victim won an unsolicited prize or lottery",
    },
    "INVESTMENT_SCAM": {
        "keywords": ["guaranteed return", "daily income", "double money", "crypto investment", "forex trading profit"],
        "description": "Caller pitched an unrealistic guaranteed investment scheme",
    },
    "GOVERNMENT_IMPERSONATION": {
        "keywords": ["cbi officer", "police department", "customs department", "narcotics bureau", "supreme court", "trai authority"],
        "description": "Caller falsely impersonated law enforcement or regulatory agency (Digital Arrest)",
    },
}


def extract_call_signals(transcript: str) -> List[Dict[str, str]]:
    """Extract behavioral deception and extortion signals from call transcript."""
    text_lower = transcript.lower()
    signals = []

    for sig_type, config in CALL_SIGNAL_PATTERNS.items():
        if any(kw in text_lower for kw in config["keywords"]):
            signals.append({
                "type": sig_type,
                "description": config["description"],
            })

    return signals


def analyze_call_transcript(transcript: str) -> Dict[str, Any]:
    """
    Classify a call transcript using call_threat_model.pkl,
    extract forensic signals, detect links, and generate unified risk assessment.
    """
    if not transcript or not transcript.strip():
        return {
            "status": "success",
            "type": "call",
            "analysis": {
                "transcript": "",
                "ml": {
                    "prediction": 0,
                    "result": "NON-SCAM",
                    "scam_probability": 0.0,
                    "non_scam_probability": 100.0,
                    "probability_available": True,
                },
                "signals": [],
                "urls": [],
                "iocs": [],
                "evidence": [],
                "risk": {
                    "risk_score": 0,
                    "risk_level": "LOW",
                    "evidence": [],
                    "recommended_action": "No call transcript provided.",
                },
            },
        }

    transcript = transcript.strip()

    # 1. ML Model Inference
    model, vectorizer = _load_call_models()
    tfidf_vec = vectorizer.transform([transcript])

    pred = int(model.predict(tfidf_vec)[0])
    result_label = "SCAM" if pred == 1 else "NON-SCAM"

    has_proba = hasattr(model, "predict_proba")
    if has_proba:
        probs = model.predict_proba(tfidf_vec)[0]
        non_scam_prob = round(float(probs[0] * 100), 2)
        scam_prob = round(float(probs[1] * 100), 2)
        ml_data = {
            "prediction": pred,
            "prediction_label": result_label,
            "result": result_label,
            "probability": scam_prob,
            "scam_probability": scam_prob,
            "non_scam_probability": non_scam_prob,
            "probability_available": True,
        }
        ml_score = int(round(scam_prob))
    else:
        ml_data = {
            "prediction": pred,
            "prediction_label": result_label,
            "result": result_label,
            "probability": 85.0 if pred == 1 else 15.0,
            "probability_available": False,
        }
        ml_score = 85 if pred == 1 else 15

    # 2. Extract Deception Signals
    signals = extract_call_signals(transcript)
    evidence_descriptions = [s["description"] for s in signals]

    # 3. URL Extraction from transcript
    raw_urls = re.findall(r'https?://[^\s<>"\'{}|\\^`]+', transcript)
    url_results = []
    highest_url_score = 0

    for u in list(dict.fromkeys(raw_urls))[:10]:
        u_res = analyze_url(u)
        is_phish = u_res.get("prediction") == "PHISHING"
        u_score = u_res.get("probability", 0)
        highest_url_score = max(highest_url_score, u_score)

        url_results.append({
            "url": u,
            "result": "SUSPICIOUS" if (is_phish or u_score >= 40) else "LEGITIMATE",
            "prediction": u_res.get("prediction", "SAFE"),
            "probability": u_score,
            "indicators": u_res.get("indicators", []),
        })

        if is_phish or u_score >= 40:
            evidence_descriptions.append(f"Suspicious URL mentioned in call: {u}")

    # 4. Forensic Correlation
    forensic_data = correlate_forensics(
        text=transcript,
        urls=[u["url"] for u in url_results],
        source_label="Voice Call Audio Transcript",
    )

    # 5. Risk Assessment
    all_evidence = list(dict.fromkeys(evidence_descriptions))
    risk_data = compute_risk(
        call_score=ml_score,
        url_score=highest_url_score if raw_urls else None,
        all_indicators=all_evidence,
        all_modalities=["call"],
    )

    return {
        "status": "success",
        "type": "call",
        "analysis": {
            "transcript": transcript,
            "ml": ml_data,
            "signals": signals,
            "behavioral_signals": [s["type"] for s in signals],
            "urls": url_results,
            "iocs": forensic_data.get("iocs", []),
            "forensic_iocs": forensic_data.get("forensic_iocs", forensic_data.get("iocs", {})),
            "correlation_chains": forensic_data.get("correlation_chains", []),
            "evidence": all_evidence,
            "risk": {
                "risk_score": risk_data.get("final_score", 0),
                "final_score": risk_data.get("final_score", 0),
                "score": risk_data.get("final_score", 0),
                "risk_level": risk_data.get("risk_level", "LOW"),
                "level": risk_data.get("risk_level", "LOW"),
                "evidence": risk_data.get("evidence", []),
                "recommendation": risk_data.get("recommendation", ""),
                "recommended_action": risk_data.get("recommendation", ""),
            },
        },
    }


def analyze_call_audio(audio_path: str) -> Dict[str, Any]:
    """
    Full Audio Call Threat Pipeline:
    Audio File -> Whisper Transcription -> Call Threat Classifier -> Signals & Forensics -> Risk Assessment.
    """
    try:
        transcript = transcribe_audio(audio_path)
    except Exception as exc:
        return {
            "status": "partial",
            "type": "call",
            "message": f"Audio transcription failed: {exc}",
            "analysis": {
                "transcript": "",
                "ml": {
                    "prediction": 0,
                    "result": "UNKNOWN",
                    "probability_available": False,
                },
                "signals": [],
                "urls": [],
                "iocs": [],
                "evidence": [],
                "risk": {
                    "risk_score": 0,
                    "risk_level": "UNKNOWN",
                    "evidence": [],
                    "recommended_action": "Unable to transcribe audio. Verify file format and clarity.",
                },
            },
        }

    return analyze_call_transcript(transcript)
