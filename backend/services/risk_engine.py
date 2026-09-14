"""
SatyaAI 3.0 — Multimodal Risk Assessment Engine
Aggregates threat probabilities from multiple intelligence layers
(NLP, URL, OCR, Whisper Audio, Deepfake Vision) and calculates unified risk scores.
"""

import re
from typing import Optional, List, Dict, Any

try:
    from backend.services.message_service import analyze_message
    from backend.services.url_service import analyze_url
except ImportError:
    from services.message_service import analyze_message
    from services.url_service import analyze_url


def extract_urls(text: str) -> List[str]:
    """Extract and deduplicate URLs from text."""
    pattern = r'https?://[^\s]+'
    urls = re.findall(pattern, text)
    return list(dict.fromkeys(urls))


def calculate_final_score(message_score: int, url_scores: List[int]) -> int:
    """Calculate combined score for message and URL modalities."""
    if url_scores:
        highest_url_score = max(url_scores)
        final_score = message_score * 0.55 + highest_url_score * 0.45
    else:
        final_score = message_score
    return round(final_score)


def get_risk_level(score: int) -> str:
    """Map a 0-100 numerical score to standard risk tiers."""
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 35:
        return "MEDIUM"
    return "LOW"


def compute_risk(
    message_score: Optional[int] = None,
    url_score: Optional[int] = None,
    image_score: Optional[int] = None,
    audio_score: Optional[int] = None,
    video_score: Optional[int] = None,
    email_score: Optional[int] = None,
    call_score: Optional[int] = None,
    all_indicators: Optional[List[str]] = None,
    all_modalities: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Compute unified risk assessment across single or multiple modalities.
    Integrates message, URL, image, audio, video, email, and call signals.
    """
    scores = [
        s for s in [message_score, url_score, image_score, audio_score, video_score, email_score, call_score]
        if s is not None
    ]

    if message_score is not None and url_score is not None:
        final_score = round(message_score * 0.55 + url_score * 0.45)
    elif email_score is not None and url_score is not None:
        final_score = round(email_score * 0.60 + url_score * 0.40)
    elif call_score is not None and url_score is not None:
        final_score = round(call_score * 0.65 + url_score * 0.35)
    elif scores:
        final_score = max(scores)
    else:
        final_score = 0

    indicators = list(dict.fromkeys(all_indicators or []))

    # Boost if strong deception indicators identified
    if indicators and final_score < 40:
        boost = min(12 * len(indicators), 35)
        final_score = min(final_score + boost, 95)

    risk_level = get_risk_level(final_score)

    if risk_level == "CRITICAL":
        rec = "CRITICAL THREAT: Immediately cease interaction. Do NOT click links, enter passwords/OTPs, or send money. Block the source and file an official complaint."
    elif risk_level == "HIGH":
        rec = "HIGH RISK: Strong deception indicators detected. Do NOT share sensitive information, banking credentials, or OTPs. Verify independently."
    elif risk_level == "MEDIUM":
        rec = "MEDIUM RISK: Suspicious patterns detected. Exercise caution and verify identity through official customer care channels."
    else:
        rec = "LOW RISK: No significant threat indicators detected. Continue to follow standard digital hygiene."

    return {
        "risk_score": final_score,
        "final_score": final_score,
        "risk_level": risk_level,
        "evidence": indicators,
        "recommended_action": rec,
        "recommendation": rec,
        "modalities": all_modalities or [],
    }