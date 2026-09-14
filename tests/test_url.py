"""Tests for url_service.py"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.services.url_service import analyze_url, extract_features, _has_ip, _is_shortened


def test_phishing_url_ip():
    url = "http://192.168.1.105/paypal-login?token=xyz"
    result = analyze_url(url)
    assert result["prediction"] in ("PHISHING", "SAFE", "UNKNOWN")
    assert 0 <= result["probability"] <= 100
    assert "IP address used instead of domain name" in result["indicators"]


def test_shortened_url():
    url = "http://bit.ly/3xAbc12"
    result = analyze_url(url)
    assert "URL shortening service detected" in result["indicators"]


def test_safe_https_url():
    url = "https://www.google.com"
    result = analyze_url(url)
    assert result["prediction"] in ("PHISHING", "SAFE")
    assert result["probability"] < 60  # Should be relatively low risk


def test_empty_url():
    result = analyze_url("")
    assert result["probability"] == 0
    assert result["risk_level"] == "LOW"


def test_url_without_scheme():
    result = analyze_url("example.com/page")
    assert result["url"].startswith("http://")


def test_result_keys():
    result = analyze_url("https://google.com")
    assert "url" in result
    assert "prediction" in result
    assert "probability" in result
    assert "risk_level" in result
    assert "indicators" in result
    assert "explanation" in result
    assert "domain_info" in result
    assert "geolocation" in result
    assert "model_used" in result
    assert result["model_used"] in ("url_phishing_model.pkl", "url_model.pkl")


def test_domain_and_geolocation():
    from backend.services.url_service import extract_domain_info, get_geolocation

    dom = extract_domain_info("https://www.google.com/search?q=test")
    assert dom["host"] == "www.google.com"
    assert dom["root_domain"] == "google.com"
    assert dom["tld"] == "com"
    assert dom["subdomain"] == "www"
    assert dom["protocol"] == "https"

    # Private IP geolocation handling
    geo_priv = get_geolocation("192.168.1.1")
    assert geo_priv["is_private"] is True
    assert geo_priv["country_code"] == "LAN"
    assert geo_priv["resolved_ip"] == "192.168.1.1"

    # Public domain geolocation handling
    geo_pub = get_geolocation("google.com")
    assert geo_pub["resolved_ip"] is not None
    assert geo_pub["is_private"] is False


def test_feature_extraction():
    url = "http://192.168.1.1/login?session=1&redirect=2"
    feats = extract_features(url)
    assert len(feats) == 12
    assert feats["https"] == 0
    assert feats["has_ip"] == 1


def test_has_ip_detection():
    assert _has_ip("http://10.0.0.1/page") == 1
    assert _has_ip("https://google.com") == 0


def test_shortener_detection():
    assert _is_shortened("http://bit.ly/abc") == 1
    assert _is_shortened("https://github.com/user") == 0


def test_suspicious_keywords():
    url = "http://example.com/paypal-login-verify-account"
    feats = extract_features(url)
    assert feats["suspicious_word_count"] >= 2


def test_risk_level_assignment():
    result = analyze_url("http://bit.ly/3xAbc12")
    assert result["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

