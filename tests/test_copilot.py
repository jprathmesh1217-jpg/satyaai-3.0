"""
Tests for SATYA AI Fraud Investigation Copilot:
RAG retrieval, intent detection, evidence memory, and /api/chat endpoints.
"""

import sys
import os

os.environ["TOKENIZERS_PARALLELISM"] = "false"
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient
from backend.main import app
from backend.services.chat_service import detect_intent
from backend.services.rag_service import get_rag_service

client = TestClient(app)


def test_intent_detection():
    assert detect_intent("Why is this a scam?") == "WHY"
    assert detect_intent("What type of scam is this?") == "SCAM_TYPE"
    assert detect_intent("What is suspicious about this URL?") == "URL_ANALYSIS"
    assert detect_intent("What should I do now?") == "RECOMMENDATION"
    assert detect_intent("How can I report this to the police?") == "REPORTING"
    assert detect_intent("Does this video show signs of deepfake manipulation?") == "DEEPFAKE"
    assert detect_intent("What is a UPI collect request?") == "UPI"


def test_rag_retrieval():
    rag = get_rag_service()
    results = rag.query("How do KYC deactivation SMS scams work?", top_k=2)
    assert len(results) > 0
    assert any("kyc" in r["category"].lower() or "phishing" in r["category"].lower() for r in results)
    assert "source" in results[0]
    assert "header" in results[0]
    assert "text" in results[0]


def test_copilot_upload_text():
    resp = client.post(
        "/api/chat/upload",
        data={"text": "URGENT: Your SBI account has been suspended due to KYC non-compliance. Click http://bit.ly/sbi-verify to avoid closure."}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "analysis_id" in data
    assert data["analysis_id"].startswith("SATYA-")
    assert data["input_type"] == "text"
    assert data["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")
    assert data["risk_score"] > 50
    assert len(data["indicators"]) > 0


def test_copilot_upload_url():
    resp = client.post(
        "/api/chat/upload",
        data={"url": "http://192.168.1.105/banking-secure/login?session=verify-kyc"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "analysis_id" in data
    assert data["input_type"] == "url"
    assert data["risk_score"] > 0


def test_copilot_chat_with_analysis():
    # First upload text
    upload_resp = client.post(
        "/api/chat/upload",
        data={"text": "Your account has been suspended. Verify KYC immediately: http://bit.ly/sbi-kyc"}
    )
    assert upload_resp.status_code == 200
    analysis_id = upload_resp.json()["analysis_id"]

    # Ask questions referencing the analysis
    chat_resp = client.post(
        "/api/chat",
        json={"message": "Why is this suspicious?", "analysis_id": analysis_id}
    )
    assert chat_resp.status_code == 200
    data = chat_resp.json()
    assert data["analysis_id"] == analysis_id
    assert data["intent"] == "WHY"
    assert "What I found" in data["answer"]
    assert "Why this is suspicious" in data["answer"]
    assert "Recommended action" in data["answer"]
    assert data["risk_score"] > 0
    assert len(data["sources"]) > 0


def test_copilot_chat_general_query_no_evidence():
    chat_resp = client.post(
        "/api/chat",
        json={"message": "What is digital arrest in courier scams?"}
    )
    assert chat_resp.status_code == 200
    data = chat_resp.json()
    assert "answer" in data
    assert "courier_scams.md" in str(data["sources"]) or "courier" in data["answer"].lower() or "arrest" in data["answer"].lower()


def test_copilot_get_context():
    upload_resp = client.post(
        "/api/chat/upload",
        data={"text": "Hello, this is a test message for context testing."}
    )
    analysis_id = upload_resp.json()["analysis_id"]

    ctx_resp = client.get(f"/api/chat/context/{analysis_id}")
    assert ctx_resp.status_code == 200
    ctx_data = ctx_resp.json()
    assert ctx_data["analysis_id"] == analysis_id
    assert ctx_data["extracted_text"] == "Hello, this is a test message for context testing."
