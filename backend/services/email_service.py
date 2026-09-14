"""
SatyaAI 3.0 — Email Threat Detection Service
Uses scikit-learn Logistic Regression + TF-IDF Vectorizer trained on phishing email corpora.
Extracts email-specific heuristic signals, analyzes embedded URLs via url_service,
and synthesizes forensic IOCs into unified risk intelligence.
"""

import re
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional

from backend.services.url_service import analyze_url
from backend.services.forensic_correlation_service import correlate_forensics
from backend.services.risk_engine import compute_risk

BASE_DIR = Path(__file__).resolve().parents[2]
MODEL_DIR = BASE_DIR / "models"
EMAIL_MODEL_PATH = MODEL_DIR / "email_threat_model.pkl"
EMAIL_VEC_PATH = MODEL_DIR / "email_tfidf_vectorizer.pkl"

_model = None
_vectorizer = None
_lock = threading.Lock()


def _load_email_models():
    """Load email classification model and TF-IDF vectorizer once."""
    global _model, _vectorizer
    if _model is not None and _vectorizer is not None:
        return _model, _vectorizer

    with _lock:
        if _model is not None and _vectorizer is not None:
            return _model, _vectorizer

        import joblib

        if not EMAIL_MODEL_PATH.exists():
            raise FileNotFoundError(f"Email threat model not found at {EMAIL_MODEL_PATH}")
        if not EMAIL_VEC_PATH.exists():
            raise FileNotFoundError(f"Email TF-IDF vectorizer not found at {EMAIL_VEC_PATH}")

        try:
            _model = joblib.load(EMAIL_MODEL_PATH)
            _vectorizer = joblib.load(EMAIL_VEC_PATH)
        except Exception as exc:
            raise RuntimeError(f"Failed to load email threat model: {exc}") from exc

    return _model, _vectorizer


# Heuristic patterns for Email Security Signals
SIGNAL_PATTERNS = {
    "URGENCY": {
        "keywords": ["urgent", "immediately", "right now", "within 24 hours", "action required", "final notice", "immediate response"],
        "description": "Urgent or threatening language detected",
    },
    "ACCOUNT_SUSPENSION": {
        "keywords": ["account suspended", "account blocked", "permanently closed", "deactivated", "access revoked", "terminate your account"],
        "description": "Threat of account deactivation or suspension",
    },
    "OTP_REQUEST": {
        "keywords": ["otp", "one time password", "verification code", "security token", "send your code"],
        "description": "One-time password or security token requested",
    },
    "PASSWORD_REQUEST": {
        "keywords": ["password", "current password", "enter your password", "reset your credentials", "change password immediately"],
        "description": "Direct password or secret credential requested",
    },
    "CREDENTIAL_REQUEST": {
        "keywords": ["credit card", "debit card", "cvv", "card number", "social security", "aadhaar", "pan card", "id proof"],
        "description": "Sensitive payment card or personal identity details requested",
    },
    "KYC_REQUEST": {
        "keywords": ["kyc", "know your customer", "kyc verification", "update kyc", "kyc non-compliance", "re-verify"],
        "description": "Urgent KYC or regulatory compliance document requested",
    },
    "BANKING_TERM": {
        "keywords": ["bank", "sbi", "hdfc", "icici", "axis", "rbi", "chase", "wells fargo", "citi", "checking account"],
        "description": "Financial or banking institution referenced",
    },
    "PAYMENT_REQUEST": {
        "keywords": ["wire transfer", "bitcoin", "crypto", "gift card", "pay now", "processing fee", "transfer funds"],
        "description": "Direct payment, processing fee, or wire transfer requested",
    },
    "UPI_TERM": {
        "keywords": ["upi", "collect request", "upi pin", "scan qr", "gpay", "phonepe", "paytm"],
        "description": "UPI payment or authorization terminology used",
    },
    "REFUND_SCAM": {
        "keywords": ["refund", "tax rebate", "cashback won", "lottery winner", "unclaimed funds", "compensation payout"],
        "description": "Unsolicited refund, prize, or compensation payout claim",
    },
    "SUSPICIOUS_ATTACHMENT": {
        "keywords": ["invoice.pdf", "receipt.zip", "attached file", "download attachment", "open the attachment", ".exe", ".iso", ".scr"],
        "description": "References to opening an external file attachment or script",
    },
}


def extract_email_signals(text: str) -> List[Dict[str, str]]:
    """Extract granular email-specific security signals and evidence without fake probabilities."""
    text_lower = text.lower()
    signals = []

    for sig_type, config in SIGNAL_PATTERNS.items():
        if any(kw in text_lower for kw in config["keywords"]):
            signals.append({
                "type": sig_type,
                "description": config["description"],
            })

    # Check for IP address in email body
    if re.search(r'https?://(?:\d{1,3}\.){3}\d{1,3}', text_lower) or re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text_lower):
        signals.append({
            "type": "IP_IN_EMAIL",
            "description": "Raw IP address found inside email text or link target",
        })

    # Check for multiple URLs
    urls_found = re.findall(r'https?://[^\s<>"\'{}|\\^`]+', text)
    if len(urls_found) > 2:
        signals.append({
            "type": "MULTIPLE_URLS",
            "description": f"Multiple external links ({len(urls_found)}) embedded in email message",
        })

    return signals


def analyze_email(
    subject: str = "",
    body: str = "",
    sender: str = "",
    headers_data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Comprehensive Email Threat Analysis:
    1. ML Inference via Logistic Regression + TF-IDF Vectorizer
    2. Email Security Signal Heuristics
    3. URL Phishing Model Evaluation
    4. Header Forensics & Sender Domain Mismatch Check
    5. Unified Multimodal Risk Scoring
    """
    combined_text = f"{subject}\n\n{body}".strip() if subject else body.strip()
    if not combined_text:
        return {
            "status": "success",
            "type": "email",
            "analysis": {
                "ml": {
                    "prediction": 0,
                    "result": "LEGITIMATE",
                    "phishing_probability": 0.0,
                    "legitimate_probability": 100.0,
                    "probability_available": True,
                },
                "headers": headers_data or {},
                "urls": [],
                "iocs": [],
                "evidence": [],
                "risk": {
                    "risk_score": 0,
                    "risk_level": "LOW",
                    "evidence": [],
                    "recommended_action": "No content provided to analyze.",
                },
                "threat_origin": {
                    "status": "unavailable",
                    "markers": [],
                    "message": "No content provided to analyze.",
                },
            },
            "threat_origin": {
                "status": "unavailable",
                "markers": [],
                "message": "No content provided to analyze.",
            },
        }

    # 1. ML Classification
    model, vectorizer = _load_email_models()
    tfidf_vec = vectorizer.transform([combined_text])

    pred = int(model.predict(tfidf_vec)[0])
    result_label = "PHISHING" if pred == 1 else "LEGITIMATE"

    has_proba = hasattr(model, "predict_proba")
    if has_proba:
        probs = model.predict_proba(tfidf_vec)[0]
        legit_prob = round(float(probs[0] * 100), 2)
        phish_prob = round(float(probs[1] * 100), 2)
        ml_data = {
            "prediction": pred,
            "prediction_label": result_label,
            "result": result_label,
            "probability": phish_prob,
            "phishing_probability": phish_prob,
            "legitimate_probability": legit_prob,
            "probability_available": True,
        }
        ml_score = int(round(phish_prob))
    else:
        ml_data = {
            "prediction": pred,
            "prediction_label": result_label,
            "result": result_label,
            "probability": 85.0 if pred == 1 else 15.0,
            "probability_available": False,
        }
        ml_score = 85 if pred == 1 else 15

    # 2. Extract Security Signals
    signals = extract_email_signals(combined_text)
    evidence_descriptions = [s["description"] for s in signals]

    # Include header signals if available from .eml parsing
    if headers_data and "header_signals" in headers_data:
        for hs in headers_data["header_signals"]:
            signals.append(hs)
            evidence_descriptions.append(hs["description"])

    # 3. URL Extraction & Analysis
    raw_urls = re.findall(r'https?://[^\s<>"\'{}|\\^`]+', combined_text)
    url_results = []
    highest_url_score = 0

    for u in list(dict.fromkeys(raw_urls))[:10]:
        u_res = analyze_url(u)
        is_phish = u_res.get("prediction") == "PHISHING"
        url_score = u_res.get("probability", 0)
        highest_url_score = max(highest_url_score, url_score)

        url_results.append({
            "url": u,
            "result": "SUSPICIOUS" if (is_phish or url_score >= 40) else "LEGITIMATE",
            "prediction": u_res.get("prediction", "SAFE"),
            "probability": url_score,
            "indicators": u_res.get("indicators", []),
            "geolocation": u_res.get("geolocation", {}),
        })

        if is_phish or url_score >= 40:
            evidence_descriptions.append(f"Suspicious URL: {u} ({url_score}% risk)")

    # 4. Forensic Correlation & IOCs
    sender_domain = ""
    if sender and "@" in sender:
        sender_domain = sender.split("@")[-1].lower()
    elif headers_data and headers_data.get("from", {}).get("domain"):
        sender_domain = headers_data["from"]["domain"]

    header_ips = []
    if headers_data and "received_ips" in headers_data:
        header_ips = headers_data["received_ips"].get("all", [])

    forensic_data = correlate_forensics(
        text=combined_text,
        urls=[u["url"] for u in url_results],
        header_ips=header_ips,
        sender_domain=sender_domain,
        source_label="Email Threat Vector",
    )

    # 5. Risk Engine Scoring
    all_evidence = list(dict.fromkeys(evidence_descriptions))
    risk_data = compute_risk(
        email_score=ml_score,
        url_score=highest_url_score if raw_urls else None,
        all_indicators=all_evidence,
        all_modalities=["email"],
    )

    # 6. Extract Infrastructure & Build Standardized Threat Origin Markers
    from backend.services.geolocation_service import build_threat_origin_markers
    final_score = risk_data.get("final_score", ml_score)
    threat_label = "Phishing Email" if result_label == "PHISHING" else "Email Infrastructure"

    infra_candidates: List[Dict[str, Any]] = []

    # Dedicated originating IP or first hop
    orig_ip = ""
    if headers_data and headers_data.get("infrastructure"):
        orig_ip = headers_data["infrastructure"].get("originating_ip", "")
    if orig_ip:
        infra_candidates.append({
            "type": "originating_ip",
            "ip": orig_ip,
            "label": f"Originating IP ({orig_ip})",
            "risk_score": final_score,
            "threat_type": threat_label,
            "source": "Email Analysis",
        })

    # Mail servers
    if headers_data and headers_data.get("infrastructure"):
        for ms in headers_data["infrastructure"].get("mail_servers", []):
            infra_candidates.append({
                "type": "mail_server",
                "domain": ms,
                "label": f"Mail Server ({ms})",
                "risk_score": final_score,
                "threat_type": threat_label,
                "source": "Email Analysis",
            })

    # Public Received IP hops
    if headers_data and headers_data.get("infrastructure"):
        for rip in headers_data["infrastructure"].get("received_ips", []):
            if rip != orig_ip:
                infra_candidates.append({
                    "type": "received_hop",
                    "ip": rip,
                    "label": f"Mail Relay ({rip})",
                    "risk_score": final_score,
                    "threat_type": threat_label,
                    "source": "Email Analysis",
                })

    # Domains (Sender, Reply-To, DKIM)
    candidate_domains = []
    if sender_domain:
        candidate_domains.append((sender_domain, f"Sender Domain ({sender_domain})"))
    if headers_data and headers_data.get("infrastructure"):
        r_dom = headers_data["infrastructure"].get("reply_to_domain")
        if r_dom and r_dom != sender_domain:
            candidate_domains.append((r_dom, f"Reply-To Domain ({r_dom})"))
        dkim_d = headers_data["infrastructure"].get("dkim_domain")
        if dkim_d and dkim_d != sender_domain:
            candidate_domains.append((dkim_d, f"DKIM Domain ({dkim_d})"))

    free_mail = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "icloud.com"}
    for dom, dom_label in candidate_domains:
        if dom and dom not in free_mail:
            infra_candidates.append({
                "type": "domain",
                "domain": dom,
                "label": dom_label,
                "risk_score": final_score,
                "threat_type": threat_label,
                "source": "Email Analysis",
            })

    # Embedded URLs
    for u in url_results:
        from urllib.parse import urlparse
        try:
            parsed_u = urlparse(u.get("url", ""))
            host_u = parsed_u.netloc.split(":")[0] if parsed_u.netloc else ""
        except Exception:
            host_u = ""
        if host_u and host_u not in [c.get("domain") for c in infra_candidates]:
            infra_candidates.append({
                "type": "url_host",
                "domain": host_u,
                "label": f"Embedded URL Host ({host_u})",
                "risk_score": u.get("probability", final_score),
                "threat_type": "Embedded URL Infrastructure",
                "source": "Email Analysis",
            })

    threat_origin = build_threat_origin_markers(
        infra_candidates,
        default_threat_type=threat_label,
        default_risk_score=final_score,
        source="Email Analysis",
    )

    return {
        "status": "success",
        "type": "email",
        "threat_origin": threat_origin,
        "analysis": {
            "ml": ml_data,
            "headers": headers_data or {
                "subject": subject,
                "sender": sender,
            },
            "signals": signals,
            "security_signals": [s["type"] for s in signals],
            "urls": url_results,
            "iocs": forensic_data.get("iocs", []),
            "forensic_iocs": forensic_data.get("forensic_iocs", forensic_data.get("iocs", {})),
            "correlation_chains": forensic_data.get("correlation_chains", []),
            "threat_origin": threat_origin,
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
