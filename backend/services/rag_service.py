"""
SatyaAI 3.0 — RAG Knowledge Retrieval Service
Loads markdown threat intelligence documents, chunks text semantically,
builds an in-memory FAISS vector index, and executes similarity search.
"""

import os
import re
import threading
from pathlib import Path
from typing import List, Dict, Any, Optional

import numpy as np
import faiss

from backend.services.embedding_service import get_embedding_service

KNOWLEDGE_BASE_DIR = Path(__file__).resolve().parent.parent / "knowledge_base"


class RAGService:
    """Manages document chunking, indexing, and semantic retrieval."""

    def __init__(self, kb_dir: Optional[Path] = None):
        self.kb_dir = kb_dir or KNOWLEDGE_BASE_DIR
        self.embedder = get_embedding_service()
        self.chunks: List[Dict[str, Any]] = []
        self.index: Optional[faiss.IndexFlatIP] = None
        self._lock = threading.Lock()
        self._build_index()

    def _chunk_document(self, file_path: Path) -> List[Dict[str, Any]]:
        """Parse markdown file and split into semantic section chunks."""
        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception:
            return []

        doc_name = file_path.stem.replace("_", " ").title()
        category = file_path.stem

        # Split by markdown headings (H2 or H3)
        sections = re.split(r"\n(?=##?\s+)", content)
        chunks = []

        for sec in sections:
            sec = sec.strip()
            if not sec or len(sec) < 50:
                continue

            # Extract title of section
            lines = sec.split("\n")
            header = lines[0].lstrip("#").strip() if lines else doc_name
            body = "\n".join(lines[1:]).strip() if len(lines) > 1 else sec

            # Clean markdown artifacts for clean embedding
            clean_text = re.sub(r"[*_`#]", "", sec).strip()

            chunks.append({
                "source": file_path.name,
                "category": category,
                "doc_name": doc_name,
                "header": header,
                "text": clean_text,
                "raw_section": sec,
            })

        return chunks

    def _build_index(self) -> None:
        """Scan knowledge base, extract chunks, compute embeddings, and build FAISS index."""
        with self._lock:
            all_chunks = []
            if self.kb_dir.exists():
                for md_file in sorted(self.kb_dir.glob("*.md")):
                    doc_chunks = self._chunk_document(md_file)
                    all_chunks.extend(doc_chunks)

            self.chunks = all_chunks
            if not self.chunks:
                self.index = None
                return

            texts = [c["text"] for c in self.chunks]
            embeddings = self.embedder.encode(texts)

            dimension = embeddings.shape[1]
            # IndexFlatIP calculates inner product (cosine similarity since vectors are normalized)
            self.index = faiss.IndexFlatIP(dimension)
            self.index.add(embeddings)

    def query(
        self,
        query_text: str,
        top_k: int = 3,
        category_filter: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Query knowledge base for top_k most relevant chunks.
        Returns list of chunks with similarity scores.
        """
        if not self.chunks or self.index is None:
            return []

        query_vec = self.embedder.encode(query_text)
        k = min(top_k * 2 if category_filter else top_k, len(self.chunks))

        scores, indices = self.index.search(query_vec, k)
        results = []

        for score, idx in zip(scores[0], indices[0]):
            if idx < 0 or idx >= len(self.chunks):
                continue
            chunk = self.chunks[idx].copy()
            chunk["score"] = float(score)

            if category_filter and chunk["category"] != category_filter:
                continue

            results.append(chunk)
            if len(results) >= top_k:
                break

        return results


# Singleton instance
_rag_service_instance = None
_rag_lock = threading.Lock()


def get_rag_service() -> RAGService:
    global _rag_service_instance
    if _rag_service_instance is not None:
        return _rag_service_instance

    with _rag_lock:
        if _rag_service_instance is not None:
            return _rag_service_instance
        _rag_service_instance = RAGService()
    return _rag_service_instance
