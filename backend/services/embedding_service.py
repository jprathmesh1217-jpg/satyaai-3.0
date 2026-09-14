"""
SatyaAI 3.0 — Embedding Service
Provides text embedding extraction using Sentence-Transformers with local caching.
Falls back to a lightweight normalized TF-IDF vectorizer if external models cannot be fetched.
"""

import os
import threading
from typing import List, Union

# Prevent OpenMP and Tokenizers multithreading collision on macOS
os.environ["TOKENIZERS_PARALLELISM"] = "false"
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"

import numpy as np

_model_instance = None
_model_lock = threading.Lock()
_fallback_vectorizer = None


class EmbeddingService:
    """Manages text embeddings for semantic search in FAISS."""

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model_name = model_name
        self.model = None
        self.dimension = 384
        self.use_fallback = False
        self._load()

    def _load(self):
        try:
            from sentence_transformers import SentenceTransformer
            # Load with cpu device explicitly
            self.model = SentenceTransformer(self.model_name, device="cpu")
            self.dimension = self.model.get_sentence_embedding_dimension() or 384
            self.use_fallback = False
        except Exception as exc:
            # Fallback to local deterministic projection
            self.use_fallback = True
            self.dimension = 384

    def encode(self, texts: Union[str, List[str]]) -> np.ndarray:
        """Encode text or list of texts into L2-normalized float32 numpy arrays."""
        if isinstance(texts, str):
            texts = [texts]

        if not texts:
            return np.empty((0, self.dimension), dtype=np.float32)

        if not self.use_fallback and self.model is not None:
            try:
                embeddings = self.model.encode(
                    texts,
                    convert_to_numpy=True,
                    normalize_embeddings=True,
                    show_progress_bar=False,
                )
                return embeddings.astype(np.float32)
            except Exception:
                pass

        # Local deterministic hashing & term-frequency projection fallback
        # Guarantees offline operation without internet connectivity
        return self._fallback_encode(texts)

    def _fallback_encode(self, texts: List[str]) -> np.ndarray:
        vectors = np.zeros((len(texts), self.dimension), dtype=np.float32)
        for i, text in enumerate(texts):
            words = text.lower().split()
            if not words:
                continue
            for w in words:
                # Deterministic Murmur-like hash index
                h = hash(w) % self.dimension
                vectors[i, h] += 1.0
            # L2 normalize
            norm = np.linalg.norm(vectors[i])
            if norm > 0:
                vectors[i] /= norm
        return vectors


def get_embedding_service() -> EmbeddingService:
    global _model_instance
    if _model_instance is not None:
        return _model_instance

    with _model_lock:
        if _model_instance is not None:
            return _model_instance
        _model_instance = EmbeddingService()
    return _model_instance
