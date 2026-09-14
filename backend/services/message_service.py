"""
SatyaAI 3.0 — Message Scam Detection Service
Analyzes text messages using TF-IDF + Logistic Regression model
with explainable AI indicators.
"""

import threading
from pathlib import Path
from typing import Optional

BASE_DIR = Path(__file__).resolve().parents[2]
MODEL_PATH = BASE_DIR / "models" / "message_model.pkl"

_model = None
_model_lock = threading.Lock()

# ─── Explainable AI: Scam indicator patterns ───────────────────────────────

INDICATORS = {
    "Urgency / Threat language": [
        "urgent", "immediately", "right now", "within 24", "within 48",
        "account suspended", "account locked", "account blocked",
        "action required", "last warning", "final notice", "expire",
        "suspended", "terminate", "deactivate",
    ],
    "KYC / Verification request": [
        "kyc", "know your customer", "verify your account", "verification required",
        "update your details", "confirm your identity", "id proof",
        "aadhaar", "pan card", "submit documents",
    ],
    "Credential harvesting": [
        "otp", "one time password", "pin", "password", "enter your password",
        "share your otp", "never share otp", "cvv", "credit card number",
        "debit card", "card number", "enter pin",
    ],
    "Bank / Financial impersonation": [
        "rbi", "reserve bank", "sbi", "hdfc", "icici", "axis bank",
        "bank of india", "government", "income tax", "tax refund",
        "irs", "hmrc", "customs", "neft", "imps", "rtgs",
    ],
    "Financial manipulation": [
        "won", "winner", "lottery", "prize", "reward", "cashback",
        "bonus", "free money", "double your money", "invest now",
        "earn daily", "guaranteed return", "crypto bonus", "bitcoin",
        "wire transfer", "send money", "pay now", "transaction failed",
    ],
    "Suspicious link / Phishing": [
        "click here", "click the link", "visit link", "open link",
        "download", "http://", "bit.ly", "tinyurl", "short url",
        "login here", "sign in now",
    ],
}


def _load_model():
    """Load scam detection model once and cache it."""
    global _model
    if _model is not None:
        return _model

    with _model_lock:
        if _model is not None:
            return _model

        if not MODEL_PATH.exists():
            raise FileNotFoundError(f"Model not found: {MODEL_PATH}")

        try:
            import joblib
            _model = joblib.load(MODEL_PATH)
        except Exception as exc:
            raise RuntimeError(f"Failed to load message model: {exc}") from exc

    return _model


def _extract_indicators(text: str) -> list[str]:
    """Return list of scam indicator categories found in text."""
    text_lower = text.lower()
    found = []
    for category, keywords in INDICATORS.items():
        for kw in keywords:
            if kw in text_lower:
                found.append(category)
                break
    return found


def _risk_level(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


def analyze_message(text: str) -> dict:
    """
    Analyze a text message for scam indicators.

    Returns:
        {
            "text": str,
            "prediction": "SCAM" | "SAFE",
            "probability": 0–100,
            "risk_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
            "indicators": [...],
            "explanation": str,
        }
    """
    if not text or not text.strip():
        return {
            "text": text or "",
            "prediction": "SAFE",
            "probability": 0,
            "risk_level": "LOW",
            "indicators": [],
            "explanation": "No text provided for analysis.",
            "error": None,
        }

    try:
        model = _load_model()
        proba = float(model.predict_proba([text])[0][1])
        score = round(proba * 100)
        label_int = int(model.predict([text])[0])
        prediction = "SCAM" if label_int == 1 else "SAFE"
        indicators = _extract_indicators(text)
        risk = _risk_level(score)

        # Boost score from heuristics if model is underconfident
        if indicators and score < 40:
            boost = min(15 * len(indicators), 30)
            score = min(score + boost, 99)
            risk = _risk_level(score)

        explanation = _build_explanation(prediction, score, indicators)

        return {
            "text": text,
            "prediction": prediction,
            "probability": score,
            "risk_level": risk,
            "indicators": indicators,
            "explanation": explanation,
            "error": None,
        }

    except Exception as exc:
        return {
            "text": text,
            "prediction": "UNKNOWN",
            "probability": 0,
            "risk_level": "UNKNOWN",
            "indicators": [],
            "explanation": "Analysis failed due to a service error.",
            "error": str(exc),
        }


def _build_explanation(prediction: str, score: int, indicators: list[str]) -> str:
    if not indicators:
        if prediction == "SCAM":
            return f"The message has linguistic patterns consistent with scam communications (score: {score}/100)."
        return "No significant scam indicators detected."

    joined = "; ".join(indicators)
    if prediction == "SCAM":
        return (
            f"This message has a scam probability of {score}/100. "
            f"Detected threat categories: {joined}. "
            "Do not click links, share OTPs, or provide personal information."
        )
    return (
        f"Some caution words detected ({joined}), but overall risk is low (score: {score}/100). "
        "Verify through official channels before acting."
    )