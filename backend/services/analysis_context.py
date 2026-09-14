"""
SatyaAI 3.0 — Uploaded Evidence Context Memory
Maintains thread-safe in-memory records of uploaded evidence,
extracted features, ML detection scores, and conversation turns.
"""

import time
import uuid
import threading
from typing import Optional, Dict, Any, List


class AnalysisContextStore:
    """Thread-safe store for evidence analysis contexts."""

    def __init__(self, max_entries: int = 1000):
        self._store: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._max_entries = max_entries

    def _generate_id(self) -> str:
        """Generate human-readable analysis identifier e.g. SATYA-ABC123."""
        suffix = uuid.uuid4().hex[:6].upper()
        return f"SATYA-{suffix}"

    def create_context(
        self,
        *,
        input_type: str,
        original_filename: Optional[str] = None,
        extracted_text: Optional[str] = None,
        detected_urls: Optional[List[str]] = None,
        ml_predictions: Optional[Dict[str, Any]] = None,
        risk_level: str = "LOW",
        risk_score: int = 0,
        indicators: Optional[List[str]] = None,
        recommendation: Optional[str] = None,
        deepfake_status: Optional[str] = None,
        raw_analysis: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Create and store a new analysis context, returning its unique analysis_id."""
        with self._lock:
            # Simple LRU-style eviction if max_entries reached
            if len(self._store) >= self._max_entries:
                oldest_key = min(self._store.keys(), key=lambda k: self._store[k]["timestamp"])
                del self._store[oldest_key]

            analysis_id = self._generate_id()
            self._store[analysis_id] = {
                "analysis_id": analysis_id,
                "timestamp": time.time(),
                "input_type": input_type,
                "original_filename": original_filename,
                "extracted_text": extracted_text or "",
                "detected_urls": detected_urls or [],
                "ml_predictions": ml_predictions or {},
                "risk_level": risk_level,
                "risk_score": risk_score,
                "indicators": indicators or [],
                "recommendation": recommendation or "",
                "deepfake_status": deepfake_status or ("analyzed" if input_type == "video" else "NOT_APPLICABLE"),
                "raw_analysis": raw_analysis or {},
                "chat_history": [],
            }
            return analysis_id

    def get_context(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve analysis context by ID."""
        with self._lock:
            return self._store.get(analysis_id)

    def append_message(
        self,
        analysis_id: str,
        role: str,
        content: str,
        intent: Optional[str] = None,
    ) -> None:
        """Append a user or assistant message to the analysis conversation thread."""
        with self._lock:
            ctx = self._store.get(analysis_id)
            if ctx is not None:
                ctx["chat_history"].append({
                    "role": role,
                    "content": content,
                    "intent": intent,
                    "timestamp": time.time(),
                })

    def get_latest_context(self) -> Optional[Dict[str, Any]]:
        """Return the most recently created analysis context if available."""
        with self._lock:
            if not self._store:
                return None
            latest_key = max(self._store.keys(), key=lambda k: self._store[k]["timestamp"])
            return self._store[latest_key]


# Global singleton instance
_context_store_instance = AnalysisContextStore()


def get_context_store() -> AnalysisContextStore:
    return _context_store_instance
