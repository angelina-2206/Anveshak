"""
Local embedding service using sentence-transformers with deterministic serverless fallback.
Runs BAAI/bge-small-en-v1.5 on CPU — no external API key required.
"""
import logging
import hashlib
from typing import List

logger = logging.getLogger("uvicorn.error")

_model = None
_dimension = None


def _get_model():
    """Lazy-load the sentence-transformer model on first call with fallback."""
    global _model, _dimension
    if _model is None:
        try:
            from sentence_transformers import SentenceTransformer
            from app.core.config import settings

            model_name = settings.EMBEDDING_MODEL
            logger.info(f"[EmbeddingService] Loading model '{model_name}' (CPU)...")
            _model = SentenceTransformer(model_name, device="cpu")

            if hasattr(_model, "get_embedding_dimension"):
                _dimension = _model.get_embedding_dimension()
            else:
                _dimension = _model.get_sentence_embedding_dimension()
            logger.info(f"[EmbeddingService] Model loaded. Dimension: {_dimension}")
        except Exception as e:
            logger.warning(f"[EmbeddingService] Could not load sentence-transformers ({e}). Using deterministic fallback.")
            _model = "FALLBACK"
            _dimension = 384
    return _model


def get_dimension() -> int:
    """Return the vector dimension of the loaded model."""
    global _dimension
    if _dimension is None:
        _get_model()
    return _dimension or 384


def _deterministic_vector(text: str, dim: int = 384) -> List[float]:
    """Generate a deterministic normalized float vector from text hash."""
    seed = hashlib.sha256(text.encode("utf-8")).digest()
    vals = []
    for i in range(dim):
        byte_val = seed[i % len(seed)]
        float_val = (byte_val / 255.0) * 2.0 - 1.0
        vals.append(float_val)
    # Normalize
    norm = sum(x * x for x in vals) ** 0.5 or 1.0
    return [x / norm for x in vals]


def embed_text(text: str) -> List[float]:
    """Embed a single text string into a vector."""
    model = _get_model()
    if model == "FALLBACK":
        return _deterministic_vector(text, get_dimension())
    vector = model.encode(text, normalize_embeddings=True)
    return vector.tolist()


def embed_documents(documents: List[str], batch_size: int = 32) -> List[List[float]]:
    """Embed a list of text strings into vectors using batched processing."""
    model = _get_model()
    if model == "FALLBACK":
        return [_deterministic_vector(doc, get_dimension()) for doc in documents]
    vectors = model.encode(documents, batch_size=batch_size, normalize_embeddings=True, show_progress_bar=False)
    return [v.tolist() for v in vectors]
