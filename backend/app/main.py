from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api.endpoints import cases, investigate, rag, extension

@asynccontextmanager
async def lifespan(app: FastAPI):
    from app.core.config import verify_environment_variables
    verify_environment_variables()
    yield

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="TRACE-X: An Interactive Cyber-Forensic Intelligence Workstation API for SIH 2026 Problem Statement 26106",
    lifespan=lifespan
)

# CORS middleware for React Vite Frontend and Chrome Extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_origin_regex=r"chrome-extension://.*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers
app.include_router(cases.router, prefix=settings.API_V1_STR)
app.include_router(extension.router, prefix=settings.API_V1_STR)
app.include_router(extension.router, prefix="/api")
app.include_router(investigate.router, prefix=settings.API_V1_STR)
app.include_router(investigate.router, prefix="/api")
app.include_router(rag.router, prefix="/api")

@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none';"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

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
def health():
    return {"status": "HEALTHY", "engine": "FastAPI Forensic Core"}
