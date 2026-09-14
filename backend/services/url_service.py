"""
SatyaAI 3.0 — URL Phishing Detection Service
Uses RandomForestClassifier with 12 engineered features and real-time Geolocation Intelligence.
Loads models/url_phishing_model.pkl (with fallback to url_model.pkl).
"""

import json
import ipaddress
import re
import socket
import threading
import urllib.request
from pathlib import Path
from typing import Optional, Dict, Any
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parents[2]
PHISHING_MODEL_PATH = BASE_DIR / "models" / "url_phishing_model.pkl"
FALLBACK_MODEL_PATH = BASE_DIR / "models" / "url_model.pkl"
FEATURES_PATH = BASE_DIR / "models" / "url_features.pkl"

MODEL_PATH = PHISHING_MODEL_PATH if PHISHING_MODEL_PATH.exists() else FALLBACK_MODEL_PATH

_model = None
_feature_names: list[str] = []
_lock = threading.Lock()
_geo_cache: Dict[str, Dict[str, Any]] = {}
_geo_lock = threading.Lock()

# Known URL shortening services
SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "rebrand.ly",
    "cutt.ly", "short.io", "tiny.cc", "is.gd", "buff.ly", "adf.ly",
    "bc.vc", "clk.sh", "shorten.me",
}

# Suspicious words commonly used in phishing URLs
SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "account", "secure", "update", "confirm",
    "banking", "paypal", "amazon", "apple", "google", "microsoft", "netflix",
    "support", "helpdesk", "password", "credential", "wallet", "kyc",
    "suspended", "blocked", "urgent", "free", "win", "prize", "bonus",
]

# High-risk Top-Level Domains (TLDs) frequently abused for phishing
SUSPICIOUS_TLDS = {
    "top", "xyz", "club", "work", "ru", "cn", "tk", "ml", "ga", "cf", "gq",
    "click", "rest", "cam", "fit", "buzz", "country", "live", "kim", "loan",
    "men", "party", "stream", "download", "racing", "win", "bid"
}


def _load_models():
    global _model, _feature_names, MODEL_PATH
    if _model is not None:
        return _model, _feature_names

    with _lock:
        if _model is not None:
            return _model, _feature_names

        import joblib

        # Prefer url_phishing_model.pkl if present
        if PHISHING_MODEL_PATH.exists():
            MODEL_PATH = PHISHING_MODEL_PATH
        elif FALLBACK_MODEL_PATH.exists():
            MODEL_PATH = FALLBACK_MODEL_PATH
        else:
            raise FileNotFoundError(f"URL model not found: neither {PHISHING_MODEL_PATH} nor {FALLBACK_MODEL_PATH} exist.")

        if not FEATURES_PATH.exists():
            raise FileNotFoundError(f"URL features not found: {FEATURES_PATH}")

        try:
            _model = joblib.load(MODEL_PATH)
            _feature_names = joblib.load(FEATURES_PATH)
        except Exception as exc:
            raise RuntimeError(f"Failed to load URL model ({MODEL_PATH.name}): {exc}") from exc

    return _model, _feature_names


def _has_ip(url: str) -> int:
    """Detect if URL uses a raw IP address instead of domain."""
    ip_pattern = re.compile(
        r"https?://(\d{1,3}\.){3}\d{1,3}"
    )
    return int(bool(ip_pattern.match(url)))


def _is_shortened(url: str) -> int:
    try:
        domain = urlparse(url).netloc.lower().lstrip("www.")
        return int(domain in SHORTENERS)
    except Exception:
        return 0


def _suspicious_word_count(url: str) -> int:
    url_lower = url.lower()
    return sum(1 for w in SUSPICIOUS_WORDS if w in url_lower)


def _subdomain_count(url: str) -> int:
    try:
        netloc = urlparse(url).netloc.lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]
        parts = netloc.split(":")[0].split(".")
        return max(0, len(parts) - 2)
    except Exception:
        return 0


def extract_features(url: str) -> dict:
    """Extract the 12 features expected by the URL model."""
    return {
        "url_length": len(url),
        "dot_count": url.count("."),
        "hyphen_count": url.count("-"),
        "slash_count": url.count("/"),
        "question_count": url.count("?"),
        "equal_count": url.count("="),
        "at_count": url.count("@"),
        "https": int(url.startswith("https://")),
        "has_ip": _has_ip(url),
        "shortened_url": _is_shortened(url),
        "suspicious_word_count": _suspicious_word_count(url),
        "subdomain_count": _subdomain_count(url),
    }


def extract_domain_info(url: str) -> dict:
    """Extract structured domain, host, protocol, and TLD breakdown."""
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()
        host = netloc.split(":")[0]
        port = parsed.port

        # Check if host is raw IP
        is_ip = False
        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            is_ip = False

        # Extract root domain & TLD
        parts = host.split(".")
        if is_ip or len(parts) < 2:
            root_domain = host
            tld = ""
            subdomain = ""
        else:
            # Simple TLD parsing
            tld = parts[-1]
            if len(parts) >= 2:
                root_domain = f"{parts[-2]}.{parts[-1]}"
                subdomain = ".".join(parts[:-2])
            else:
                root_domain = host
                subdomain = ""

        suspicious_tld = tld in SUSPICIOUS_TLDS

        return {
            "host": host,
            "port": port,
            "protocol": parsed.scheme or "http",
            "root_domain": root_domain,
            "tld": tld,
            "subdomain": subdomain,
            "is_ip": is_ip,
            "path": parsed.path or "/",
            "query": parsed.query or "",
            "suspicious_tld": suspicious_tld,
        }
    except Exception:
        return {
            "host": "",
            "port": None,
            "protocol": "http",
            "root_domain": "",
            "tld": "",
            "subdomain": "",
            "is_ip": False,
            "path": "/",
            "query": "",
            "suspicious_tld": False,
        }


def _resolve_ip(host: str) -> Optional[str]:
    """Resolve a hostname or IP to an IPv4 string with a short timeout."""
    if not host:
        return None
    try:
        # If already an IP address
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    try:
        # Set quick socket timeout for DNS
        orig_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(2.0)
        try:
            return socket.gethostbyname(host)
        finally:
            socket.setdefaulttimeout(orig_timeout)
    except Exception:
        return None


def _is_private_ip(ip_str: str) -> bool:
    """Check whether an IP is private, loopback, or reserved (RFC 1918 / Bogon)."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_reserved
            or ip_obj.is_link_local
            or ip_obj.is_multicast
        )
    except Exception:
        return False


def get_geolocation(host: str) -> dict:
    """
    Resolve and geolocate host/IP address.
    Uses in-memory cache, handles private/reserved IPs instantly,
    and queries public geolocation API with resilience.
    """
    if not host:
        return {
            "status": "fail",
            "resolved_ip": None,
            "country": "Unknown",
            "country_code": "UNK",
            "region": "Unknown",
            "city": "Unknown",
            "isp": "Unknown",
            "org": "Unknown",
            "asn": "N/A",
            "latitude": 0.0,
            "longitude": 0.0,
            "is_private": False,
            "note": "No host provided",
        }

    with _geo_lock:
        if host in _geo_cache:
            return _geo_cache[host]

    resolved_ip = _resolve_ip(host)
    if not resolved_ip:
        res = {
            "status": "fail",
            "resolved_ip": None,
            "host": host,
            "country": "Unresolvable Host",
            "country_code": "UNK",
            "region": "DNS Resolution Failed",
            "city": "Unknown",
            "isp": "N/A (Host Unreachable)",
            "org": "N/A",
            "asn": "N/A",
            "latitude": 0.0,
            "longitude": 0.0,
            "is_private": False,
            "note": "DNS query failed to resolve host IP",
        }
        with _geo_lock:
            _geo_cache[host] = res
        return res

    # Check for private or loopback IP
    if _is_private_ip(resolved_ip):
        res = {
            "status": "success",
            "resolved_ip": resolved_ip,
            "host": host,
            "country": "Local / Private Network",
            "country_code": "LAN",
            "region": "Internal Network (RFC 1918 / Loopback)",
            "city": "Private Subnet",
            "isp": "Local Area Network",
            "org": "Private Infrastructure",
            "asn": "N/A (Private)",
            "latitude": 0.0,
            "longitude": 0.0,
            "is_private": True,
            "note": "IP belongs to reserved private address space (RFC 1918 / Bogon)",
        }
        with _geo_lock:
            _geo_cache[host] = res
            _geo_cache[resolved_ip] = res
        return res

    # Lookup public IP geolocation via free, resilient API
    try:
        api_url = f"http://ip-api.com/json/{resolved_ip}?fields=status,message,country,countryCode,regionName,city,isp,org,as,lat,lon,query"
        req = urllib.request.Request(api_url, headers={"User-Agent": "SatyaAI-ThreatIntel/3.0"})
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        if data.get("status") == "success":
            res = {
                "status": "success",
                "resolved_ip": resolved_ip,
                "host": host,
                "country": data.get("country") or "Unknown",
                "country_code": data.get("countryCode") or "UNK",
                "region": data.get("regionName") or "Unknown",
                "city": data.get("city") or "Unknown",
                "isp": data.get("isp") or "Unknown ISP",
                "org": data.get("org") or data.get("isp") or "Unknown Org",
                "asn": data.get("as") or "N/A",
                "latitude": float(data.get("lat") or 0.0),
                "longitude": float(data.get("lon") or 0.0),
                "is_private": False,
                "note": "Public geolocation resolved",
            }
        else:
            res = {
                "status": "partial",
                "resolved_ip": resolved_ip,
                "host": host,
                "country": "External Host",
                "country_code": "EXT",
                "region": "Public IP Range",
                "city": "Unknown",
                "isp": "Public Internet Host",
                "org": "Unknown",
                "asn": "N/A",
                "latitude": 0.0,
                "longitude": 0.0,
                "is_private": False,
                "note": data.get("message", "Lookup returned no data"),
            }
    except Exception as exc:
        res = {
            "status": "partial",
            "resolved_ip": resolved_ip,
            "host": host,
            "country": "Public Host (Geo Offline)",
            "country_code": "UNK",
            "region": "Resolved IP Online",
            "city": "Unknown",
            "isp": "Public Network",
            "org": "Public Network",
            "asn": "N/A",
            "latitude": 0.0,
            "longitude": 0.0,
            "is_private": False,
            "note": f"Geolocation service offline: {exc}",
        }

    with _geo_lock:
        _geo_cache[host] = res
        _geo_cache[resolved_ip] = res
    return res


def _extract_indicators(url: str, features: dict, domain_info: dict, geo_info: dict) -> list[str]:
    indicators = []
    if features.get("has_ip"):
        indicators.append("IP address used instead of domain name")
    if features.get("shortened_url"):
        indicators.append("URL shortening service detected")
    if not features.get("https"):
        indicators.append("No HTTPS — insecure unencrypted connection")
    if features.get("suspicious_word_count", 0) >= 2:
        indicators.append(f"Suspicious keywords in URL ({features['suspicious_word_count']} found)")
    if features.get("subdomain_count", 0) >= 2:
        indicators.append(f"Excessive subdomains ({features['subdomain_count']}) — possible brand spoofing")
    if features.get("hyphen_count", 0) >= 3:
        indicators.append("Excessive hyphens — common phishing evasion pattern")
    if features.get("url_length", 0) > 100:
        indicators.append("Abnormally long URL string")
    if features.get("at_count", 0) > 0:
        indicators.append("@ symbol in URL — credential redirection pattern")

    # Domain & Geolocation indicators
    if domain_info.get("suspicious_tld"):
        tld_val = domain_info.get("tld", "")
        indicators.append(f"High-risk TLD (.{tld_val}) frequently used in phishing campaigns")

    if geo_info.get("is_private") and not url.startswith("http://localhost") and not url.startswith("http://127.0.0.1"):
        indicators.append("Private/LAN IP address (RFC 1918) in public URL — evasion/reconnaissance pattern")

    if geo_info.get("country") and geo_info.get("country") not in ("Unknown", "Local / Private Network", "Public Host (Geo Offline)", "Unresolvable Host"):
        # If URL mentions major domestic brands but is hosted in foreign jurisdiction
        country_name = geo_info.get("country")
        isp_name = geo_info.get("isp", "")
        if any(w in url.lower() for w in ["sbi", "hdfc", "icici", "axis", "punjab", "rbi", "paytm"]) and geo_info.get("country_code") != "IN":
            indicators.append(f"Impersonated Indian financial brand hosted offshore in {country_name} ({isp_name})")

    return indicators


def _risk_level(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


def analyze_url(url: str) -> dict:
    """
    Analyze a URL for phishing indicators with RandomForestClassifier and Geolocation intelligence.

    Returns:
        {
            "url": str,
            "prediction": "PHISHING" | "SAFE",
            "probability": 0–100,
            "risk_level": str,
            "indicators": [...],
            "explanation": str,
            "features": {...},
            "domain_info": {...},
            "geolocation": {...},
            "model_used": str,
            "error": None,
        }
    """
    if not url or not url.strip():
        empty_domain = extract_domain_info("")
        empty_geo = get_geolocation("")
        return {
            "url": url or "",
            "prediction": "SAFE",
            "probability": 0,
            "risk_level": "LOW",
            "indicators": [],
            "explanation": "No URL provided.",
            "features": {},
            "domain_info": empty_domain,
            "geolocation": empty_geo,
            "threat_origin": {
                "status": "unavailable",
                "markers": [],
                "message": "No URL provided.",
            },
            "model_used": MODEL_PATH.name if MODEL_PATH.exists() else "none",
            "error": None,
        }

    url = url.strip()
    # Normalise — add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        import numpy as np
        model, feature_names = _load_models()
        feats = extract_features(url)
        domain_info = extract_domain_info(url)
        geo_info = get_geolocation(domain_info.get("host", ""))

        # Build feature vector in exact training order
        vec = np.array([[feats[fn] for fn in feature_names]], dtype=float)

        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            proba = float(model.predict_proba(vec)[0][1])
            label_int = int(model.predict(vec)[0])
        score = round(proba * 100)
        prediction = "PHISHING" if label_int == 1 else "SAFE"

        indicators = _extract_indicators(url, feats, domain_info, geo_info)

        # Heuristic boost for identified deception markers
        if indicators and score < 40:
            boost = min(12 * len(indicators), 40)
            score = min(score + boost, 99)

        risk = _risk_level(score)

        geo_desc = ""
        if geo_info.get("country") and geo_info.get("country") != "Unknown":
            loc_parts = [geo_info.get("city"), geo_info.get("country")]
            loc_str = ", ".join([p for p in loc_parts if p and p != "Unknown"])
            if loc_str:
                geo_desc = f" Server hosted in {loc_str} ({geo_info.get('isp', 'N/A')})."

        explanation = (
            f"URL has a phishing probability of {score}/100.{geo_desc} "
            + (f"Detected: {'; '.join(indicators)}." if indicators else "No strong phishing signals found.")
        )

        from backend.services.geolocation_service import build_threat_origin_markers
        infra_items = [{
            "type": "domain",
            "domain": domain_info.get("host", ""),
            "label": domain_info.get("host", ""),
            "ip": geo_info.get("resolved_ip"),
            "risk_score": score,
            "threat_type": "Phishing URL" if prediction == "PHISHING" else "Legitimate URL",
            "source": "URL Analysis",
        }]
        threat_origin = build_threat_origin_markers(
            infra_items,
            default_threat_type="Phishing URL" if prediction == "PHISHING" else "Legitimate URL",
            default_risk_score=score,
            source="URL Analysis",
        )

        return {
            "url": url,
            "prediction": prediction,
            "probability": score,
            "risk_level": risk,
            "indicators": indicators,
            "explanation": explanation,
            "features": feats,
            "domain_info": domain_info,
            "geolocation": geo_info,
            "threat_origin": threat_origin,
            "model_used": MODEL_PATH.name,
            "error": None,
        }

    except Exception as exc:
        empty_domain = extract_domain_info(url)
        empty_geo = get_geolocation(empty_domain.get("host", ""))
        return {
            "url": url,
            "prediction": "UNKNOWN",
            "probability": 0,
            "risk_level": "UNKNOWN",
            "indicators": [],
            "explanation": "URL analysis failed.",
            "features": {},
            "domain_info": empty_domain,
            "geolocation": empty_geo,
            "threat_origin": {
                "status": "unavailable",
                "markers": [],
                "message": f"URL analysis failed: {exc}",
            },
            "model_used": MODEL_PATH.name if MODEL_PATH.exists() else "none",
            "error": str(exc),
        }
