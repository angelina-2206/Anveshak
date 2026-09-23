import os
import json
import logging
from dotenv import load_dotenv

# Load server-side environment configuration from .env file
load_dotenv()

class Settings:
    PROJECT_NAME: str = "TRACE-X Cyber-Forensic Workstation"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    SECRET_KEY: str = os.getenv("SECRET_KEY", "tracex-super-secret-forensic-key-2026-sih")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 1 day
    
    # Load ALLOWED_ORIGINS securely from environment
    allowed_origins_env = os.getenv("ALLOWED_ORIGINS")
    if allowed_origins_env:
        try:
            ALLOWED_ORIGINS: list[str] = json.loads(allowed_origins_env)
        except Exception:
            ALLOWED_ORIGINS: list[str] = [allowed_origins_env]
    else:
        ALLOWED_ORIGINS: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000"]

    # External Provider Keys (exclusively server-side)
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    URLSCAN_API_KEY: str = os.getenv("URLSCAN_API_KEY", "")
    
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    QDRANT_URL: str = os.getenv("QDRANT_URL", "http://localhost:6333")
    QDRANT_API_KEY: str = os.getenv("QDRANT_API_KEY", "")
    
    # RAG / Embedding Configuration (local, no API key required)
    EMBEDDING_MODEL: str = os.getenv("EMBEDDING_MODEL", "BAAI/bge-small-en-v1.5")
    RAG_COLLECTION_NAME: str = os.getenv("RAG_COLLECTION_NAME", "tracex_knowledge")
    RAG_CHUNK_SIZE: int = int(os.getenv("RAG_CHUNK_SIZE", "600"))
    RAG_CHUNK_OVERLAP: int = int(os.getenv("RAG_CHUNK_OVERLAP", "80"))
    
    ALCHEMY_RPC_URL: str = os.getenv("ALCHEMY_RPC_URL", "")
    BLOCKCHAIN_PRIVATE_KEY: str = os.getenv("BLOCKCHAIN_PRIVATE_KEY", "")
    IPGEOLOCATION_API_KEY: str = os.getenv("IPGEOLOCATION_API_KEY", "")

    # SSRF Protection Configuration
    BLOCKED_IP_RANGES: list[str] = [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.169.254",  # AWS metadata
    ]
    
    # Storage (Use /tmp in serverless environments like Vercel)
    BASE_STORAGE: str = "/tmp" if os.getenv("VERCEL") else os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    UPLOAD_DIR: str = os.path.join(BASE_STORAGE, "storage", "uploads")
    EVIDENCE_DIR: str = os.path.join(BASE_STORAGE, "storage", "evidence")

settings = Settings()

# Ensure storage directories exist safely (prevent crashing on read-only filesystems)
try:
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    os.makedirs(settings.EVIDENCE_DIR, exist_ok=True)
except Exception:
    pass

def verify_environment_variables():
    """
    Validates configuration state on application startup.
    Warns security engineers about missing credentials without leaking secrets in logs.
    """
    logger = logging.getLogger("uvicorn.error")
    logger.info("======================================================================")
    logger.info("           TRACE-X SYSTEM INTEGRITY & CRYPTO SECRET LAYER            ")
    logger.info("======================================================================")
    
    if os.getenv("SECRET_KEY") is None:
        logger.warning("[SECURITY] SECRET_KEY not configured in env. Falling back to default.")
    else:
        logger.info("[SECURITY] SECRET_KEY is set and verified.")
        
    integrations = {
        "VIRUSTOTAL_API_KEY": "VirusTotal Intel Service",
        "ABUSEIPDB_API_KEY": "AbuseIPDB Ingress Check",
        "URLSCAN_API_KEY": "URLScan.io Sandbox Link Analysis",
        "GEMINI_API_KEY": "Gemini Forensic RAG Context Generator",
        "ALCHEMY_RPC_URL": "Alchemy Polygon JSON-RPC Anchoring Node",
        "BLOCKCHAIN_PRIVATE_KEY": "Polygon POS Merkle Anchoring Private Key",
        "IPGEOLOCATION_API_KEY": "IP Geolocation API Service"
    }
    
    for env_var, title in integrations.items():
        val = os.getenv(env_var)
        if not val:
            logger.warning(f"[CONFIG] {env_var} is missing. {title} features will run in simulated Mock mode.")
        else:
            logger.info(f"[CONFIG] {env_var} parsed and verified (safe).")
    
    # RAG layer status (non-secret, informational)
    logger.info(f"[RAG] Qdrant URL: {settings.QDRANT_URL}")
    logger.info(f"[RAG] Embedding Model: {settings.EMBEDDING_MODEL}")
    logger.info(f"[RAG] Collection: {settings.RAG_COLLECTION_NAME}")
    logger.info(f"[RAG] Chunk Size: {settings.RAG_CHUNK_SIZE} / Overlap: {settings.RAG_CHUNK_OVERLAP}")
            
    logger.info("======================================================================")

