"""
Qdrant vector database service.
Abstracts all Qdrant implementation details from the rest of the application.
Connects to local Docker Qdrant — no API key required.
"""
import logging
from typing import List, Dict, Any, Optional

from qdrant_client import QdrantClient
from qdrant_client.http import models as qmodels

from app.core.config import settings
from app.services.embedding_service import get_dimension

logger = logging.getLogger("uvicorn.error")

# Module-level client singleton
_client: Optional[QdrantClient] = None


def _get_client() -> QdrantClient:
    """Get or create the Qdrant client singleton."""
    global _client
    if _client is None:
        url = settings.QDRANT_URL
        api_key = settings.QDRANT_API_KEY or None
        logger.info(f"[QdrantService] Connecting to Qdrant at {url}")
        _client = QdrantClient(url=url, api_key=api_key, timeout=10.0, check_compatibility=False)
    return _client


def is_connected() -> bool:
    """Check if Qdrant is reachable."""
    try:
        client = _get_client()
        client.get_collections()
        return True
    except Exception as e:
        logger.warning(f"[QdrantService] Connection check failed: {e}")
        return False


def collection_exists(name: Optional[str] = None) -> bool:
    """Check if the target collection exists."""
    name = name or settings.RAG_COLLECTION_NAME
    try:
        client = _get_client()
        collections = client.get_collections().collections
        return any(c.name == name for c in collections)
    except Exception:
        return False


def create_collection(name: Optional[str] = None) -> bool:
    """Create the collection if it doesn't exist. Returns True if created."""
    name = name or settings.RAG_COLLECTION_NAME
    if collection_exists(name):
        logger.info(f"[QdrantService] Collection '{name}' already exists.")
        return False

    dimension = get_dimension()
    client = _get_client()
    client.create_collection(
        collection_name=name,
        vectors_config=qmodels.VectorParams(
            size=dimension,
            distance=qmodels.Distance.COSINE
        )
    )
    logger.info(f"[QdrantService] Created collection '{name}' (dim={dimension}, cosine).")
    return True


def delete_collection(name: Optional[str] = None) -> bool:
    """Delete a collection. Returns True if deleted."""
    name = name or settings.RAG_COLLECTION_NAME
    try:
        client = _get_client()
        client.delete_collection(collection_name=name)
        logger.info(f"[QdrantService] Deleted collection '{name}'.")
        return True
    except Exception as e:
        logger.warning(f"[QdrantService] Delete failed: {e}")
        return False


def get_collection_info(name: Optional[str] = None) -> Dict[str, Any]:
    """Return collection statistics."""
    name = name or settings.RAG_COLLECTION_NAME
    try:
        client = _get_client()
        info = client.get_collection(collection_name=name)
        return {
            "name": name,
            "vectors_count": info.indexed_vectors_count,
            "points_count": info.points_count,
            "status": str(info.status),
        }
    except Exception as e:
        return {"name": name, "error": str(e)}


def upsert_documents(points: List[Dict[str, Any]], name: Optional[str] = None, batch_size: int = 100) -> int:
    """
    Upsert document chunks as points into Qdrant.
    Each point dict must contain: id, vector, payload.
    Uses deterministic IDs so re-ingestion is idempotent.
    Returns the number of points upserted.
    """
    name = name or settings.RAG_COLLECTION_NAME
    client = _get_client()
    total = 0

    for i in range(0, len(points), batch_size):
        batch = points[i:i + batch_size]
        qdrant_points = [
            qmodels.PointStruct(
                id=p["id"],
                vector=p["vector"],
                payload=p["payload"]
            )
            for p in batch
        ]
        client.upsert(collection_name=name, points=qdrant_points)
        total += len(qdrant_points)

    logger.info(f"[QdrantService] Upserted {total} points into '{name}'.")
    return total


def search(vector: List[float], top_k: int = 5, score_threshold: float = 0.3, name: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Search for similar vectors in the collection.
    Returns list of dicts with score and payload.
    """
    name = name or settings.RAG_COLLECTION_NAME
    try:
        client = _get_client()
        results = client.query_points(
            collection_name=name,
            query=vector,
            limit=top_k,
            score_threshold=score_threshold,
        )
        
        output = []
        for point in results.points:
            entry = {
                "score": round(point.score, 4),
                **point.payload
            }
            output.append(entry)
        return output
    except Exception as e:
        logger.error(f"[QdrantService] Search failed: {e}")
        return []
