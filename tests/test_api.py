"""Tests for FastAPI endpoints using TestClient."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


# ── Status endpoints ─────────────────────────────────────────────────────────

def test_root():
    resp = client.get("/")
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "SatyaAI 3.0"
    assert "endpoints" in data


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"


# ── Message endpoint ─────────────────────────────────────────────────────────

def test_analyze_message_scam():
    resp = client.post("/api/analyze/message", json={
        "text": "URGENT: Your bank account is suspended. Click here to verify KYC now or lose access permanently."
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["modality"] == "message"
    assert "analysis" in data
    assert "risk_assessment" in data
    assert 0 <= data["risk_assessment"]["final_score"] <= 100


def test_analyze_message_safe():
    resp = client.post("/api/analyze/message", json={
        "text": "Can we schedule a meeting next Tuesday at 10am?"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_assessment"]["final_score"] < 70


def test_analyze_message_empty():
    resp = client.post("/api/analyze/message", json={"text": ""})
    assert resp.status_code == 422  # Validation error


def test_analyze_message_missing_field():
    resp = client.post("/api/analyze/message", json={})
    assert resp.status_code == 422


# ── URL endpoint ─────────────────────────────────────────────────────────────

def test_analyze_url_phishing():
    resp = client.post("/api/analyze/url", json={
        "url": "http://192.168.1.1/paypal-login-verify?session=xyz"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["modality"] == "url"
    assert "indicators" in data["analysis"]


def test_analyze_url_safe():
    resp = client.post("/api/analyze/url", json={"url": "https://www.google.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert 0 <= data["risk_assessment"]["final_score"] <= 100


def test_analyze_url_empty():
    resp = client.post("/api/analyze/url", json={"url": ""})
    assert resp.status_code == 422


# ── Image endpoint ───────────────────────────────────────────────────────────

def _make_test_png() -> bytes:
    """Create minimal PNG bytes with text (using PIL)."""
    try:
        import io
        from PIL import Image, ImageDraw
        img = Image.new("RGB", (300, 100), (255, 255, 255))
        draw = ImageDraw.Draw(img)
        draw.text((10, 40), "URGENT verify account now http://scam.com", fill=(0, 0, 0))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except Exception:
        return b""


def test_analyze_image_upload():
    png_bytes = _make_test_png()
    if not png_bytes:
        return  # PIL not available
    resp = client.post(
        "/api/analyze/image",
        files={"file": ("test_scam.png", png_bytes, "image/png")}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["modality"] == "image"
    assert "analysis" in data


def test_analyze_image_wrong_type():
    resp = client.post(
        "/api/analyze/image",
        files={"file": ("test.txt", b"hello", "text/plain")}
    )
    assert resp.status_code == 400


# ── Video endpoint ───────────────────────────────────────────────────────────

def test_analyze_video_upload():
    test_video = os.path.join(os.path.dirname(__file__), "..", "backend", "uploads", "test.mp4")
    if not os.path.exists(test_video):
        return  # Skip if test video not present

    with open(test_video, "rb") as f:
        resp = client.post(
            "/api/analyze/video",
            files={"file": ("test.mp4", f, "video/mp4")}
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["modality"] == "video"
    assert "analysis" in data


def test_analyze_video_wrong_type():
    resp = client.post(
        "/api/analyze/video",
        files={"file": ("test.txt", b"hello", "text/plain")}
    )
    assert resp.status_code == 400


# ── Risk engine integration ───────────────────────────────────────────────────

def test_risk_assessment_structure():
    resp = client.post("/api/analyze/message", json={
        "text": "You have won a lottery prize of $500000! Wire transfer fee required."
    })
    assert resp.status_code == 200
    risk = resp.json()["risk_assessment"]
    assert "final_score" in risk
    assert "risk_level" in risk
    assert "evidence" in risk
    assert "recommendation" in risk
    assert risk["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def test_processing_time_returned():
    resp = client.post("/api/analyze/message", json={"text": "Test message"})
    assert resp.status_code == 200
    assert "processing_time_ms" in resp.json()
