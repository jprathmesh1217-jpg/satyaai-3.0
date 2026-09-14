"""
SatyaAI 3.0 — Chat & NLP Orchestration Service
Analyzes user query intents, resolves co-references against active analysis_id,
queries the RAG knowledge base, and orchestrates grounded LLM reasoning.
"""

import re
from typing import Dict, Any, List, Optional, Tuple

from backend.services.analysis_context import get_context_store
from backend.services.rag_service import get_rag_service
from backend.services.llm_service import get_llm_service


# ── Intent Detection Patterns ────────────────────────────────────────────────

INTENT_RULES = [
    ("WHY", [r"\bwhy\b", r"reason", r"how come", r"cause"]),
    ("SCAM_TYPE", [r"what type", r"which scam", r"what kind", r"what scam", r"pattern"]),
    ("WHAT_FOUND", [r"what is this", r"what did you find", r"what found", r"findings", r"overview"]),
    ("URL_ANALYSIS", [r"\burl\b", r"link", r"domain", r"website", r"http", r"https"]),
    ("RED_FLAGS", [r"red flag", r"indicators", r"signals", r"suspicious about"]),
    ("ATTACKER_GOAL", [r"steal", r"attacker want", r"trying to get", r"trying to take", r"objective", r"aim"]),
    ("RECOMMENDATION", [r"what should i do", r"how to act", r"next step", r"advice", r"recommend"]),
    ("REPORTING", [r"how can i report", r"where to report", r"police", r"cybercrime portal", r"1930", r"helpline"]),
    ("PREVENTION", [r"protect myself", r"prevent", r"tell my parents", r"avoid", r"safety tips"]),
    ("DEEPFAKE", [r"deepfake", r"face swap", r"synthetic", r"manipulated video", r"altered video"]),
    ("VOICE_SCAM", [r"voice", r"audio call", r"recording", r"voice clone", r"vishing"]),
    ("PHISHING", [r"phishing", r"credential harvesting", r"fake login"]),
    ("UPI", [r"\bupi\b", r"qr code", r"gpay", r"phonepe", r"paytm"]),
    ("BANKING", [r"bank", r"account", r"sbi", r"hdfc", r"icici", r"debit"]),
    ("KYC", [r"kyc", r"pan", r"aadhaar", r"verify account"]),
    ("OTP", [r"\botp\b", r"pin", r"one-time password", r"2fa"]),
    ("RISK", [r"risk", r"score", r"danger", r"severity", r"probability"]),
    ("EXPLAIN", [r"explain", r"simple language", r"simplify", r"details"]),
    ("GENERAL_SCAM_KNOWLEDGE", [r"what is", r"how does", r"tell me about"]),
]


def detect_intent(query: str) -> str:
    """Classify user query into canonical NLP intent category."""
    q_clean = query.lower().strip()
    for intent, patterns in INTENT_RULES:
        for pat in patterns:
            if re.search(pat, q_clean):
                return intent
    return "EXPLAIN"


def resolve_context_query(query: str, ctx: Optional[Dict[str, Any]]) -> Tuple[str, Optional[str]]:
    """
    Resolve co-references such as 'this', 'it', 'the link' using active evidence context.
    Returns (augmented_query_for_rag, category_hint).
    """
    augmented = query
    category_hint = None

    if ctx:
        input_type = ctx.get("input_type", "").lower()
        extracted = ctx.get("extracted_text", "")
        detected_urls = ctx.get("detected_urls", [])

        # Categorize context
        if input_type == "video" or ctx.get("deepfake_status") == "analyzed":
            category_hint = "deepfake_scams"
        elif input_type == "audio":
            category_hint = "voice_scams"
        elif input_type == "url" or detected_urls:
            category_hint = "malicious_urls"
        elif "kyc" in extracted.lower():
            category_hint = "kyc_scams"
        elif "upi" in extracted.lower():
            category_hint = "upi_scams"
        elif "bank" in extracted.lower() or "sbi" in extracted.lower() or "hdfc" in extracted.lower():
            category_hint = "banking_scams"
        elif "otp" in extracted.lower():
            category_hint = "otp_scams"

        # Expand pronouns for RAG search
        co_ref_terms = [r"\bthis\b", r"\bit\b", r"the message", r"the link", r"the recording", r"the video"]
        has_coref = any(re.search(term, query.lower()) for term in co_ref_terms)
        if has_coref and extracted:
            sample_snippet = extracted[:150].strip()
            augmented = f"{query} | Context Evidence: {sample_snippet}"

    return augmented, category_hint


class ChatService:
    """Orchestrates RAG, NLP understanding, and LLM reasoning."""

    def __init__(self):
        self.context_store = get_context_store()
        self.rag_service = get_rag_service()
        self.llm_service = get_llm_service()

    def process_chat(
        self,
        *,
        message: str,
        analysis_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Process a user question against an optional analysis_id.
        Returns structured response with intent, answer, sources, and evidence.
        """
        user_query = message.strip()
        if not user_query:
            return {
                "answer": "Please provide a question regarding cyber fraud, scams, or your uploaded evidence.",
                "intent": "OTHER",
                "analysis_id": analysis_id,
                "sources": [],
                "evidence": [],
                "risk_score": 0,
                "risk_level": "LOW",
            }

        # 1. Resolve analysis context
        ctx = None
        if analysis_id:
            ctx = self.context_store.get_context(analysis_id)
        if not ctx:
            # Check if there is an active session context
            ctx = self.context_store.get_latest_context()
            if ctx:
                analysis_id = ctx["analysis_id"]

        # 2. NLP Intent Detection
        intent = detect_intent(user_query)

        # 3. Co-reference resolution & RAG retrieval
        rag_query, category_hint = resolve_context_query(user_query, ctx)
        rag_chunks = self.rag_service.query(rag_query, top_k=3, category_filter=category_hint)
        if not rag_chunks and category_hint:
            # Fallback query without category filter
            rag_chunks = self.rag_service.query(rag_query, top_k=3)

        # 4. Generate structured answer
        answer = self.llm_service.generate_response(
            query=user_query,
            intent=intent,
            evidence_context=ctx,
            rag_chunks=rag_chunks,
            chat_history=ctx.get("chat_history", []) if ctx else None,
        )

        # 5. Record message in context history
        if ctx and analysis_id:
            self.context_store.append_message(analysis_id, "user", user_query, intent)
            self.context_store.append_message(analysis_id, "assistant", answer, intent)

        # 6. Build structured response
        sources = [c["source"] for c in rag_chunks] if rag_chunks else []
        evidence = ctx.get("indicators", []) if ctx else []
        risk_score = ctx.get("risk_score", 0) if ctx else 0
        risk_level = ctx.get("risk_level", "LOW") if ctx else "LOW"

        return {
            "answer": answer,
            "intent": intent,
            "analysis_id": analysis_id,
            "sources": sources,
            "evidence": evidence,
            "risk_score": risk_score,
            "risk_level": risk_level,
        }


# Global singleton instance
_chat_service_instance = ChatService()


def get_chat_service() -> ChatService:
    return _chat_service_instance
