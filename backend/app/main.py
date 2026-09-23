from contextlib import asynccontextmanager
import logging
import traceback
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api.endpoints import cases, investigate, rag, extension

logger = logging.getLogger("uvicorn.error")

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        from app.core.config import verify_environment_variables
        verify_environment_variables()
    except Exception as e:
        logger.warning(f"Startup verification notice: {e}")
    yield

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="TRACE-X: Cyber-Forensic Intelligence Workstation API",
    lifespan=lifespan
)

# CORS middleware for React Vite Frontend, Vercel deployments, and Chrome Extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global exception handler to return structured JSON errors instead of 500 HTML crashes
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    error_msg = f"Unhandled Exception: {exc}"
    logger.error(f"{error_msg}\n{traceback.format_exc()}")
    return JSONResponse(
        status_code=500,
        content={
            "status": "ERROR",
            "detail": str(exc),
            "type": type(exc).__name__,
            "path": request.url.path
        }
    )

# Include API Routers with multi-prefix fallbacks for Vercel route proxies
app.include_router(cases.router, prefix=settings.API_V1_STR)
app.include_router(cases.router, prefix="/api")
app.include_router(cases.router, prefix="/v1")

app.include_router(extension.router, prefix=settings.API_V1_STR)
app.include_router(extension.router, prefix="/api")

app.include_router(investigate.router, prefix=settings.API_V1_STR)
app.include_router(investigate.router, prefix="/api")

app.include_router(rag.router, prefix=settings.API_V1_STR)
app.include_router(rag.router, prefix="/api")

@app.get("/")
@app.get("/api")
def root():
    return {
        "status": "ONLINE",
        "system": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "docs_url": "/docs"
    }

@app.get("/health")
@app.get("/api/health")
@app.get("/v1/health")
def health():
    return {"status": "HEALTHY", "engine": "FastAPI Forensic Core"}

@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD"])
def catch_all_fallback(full_path: str, request: Request):
    return {
        "status": "ONLINE",
        "system": settings.PROJECT_NAME,
        "matched_path": full_path,
        "raw_path": request.url.path
    }
