import sys
import os

root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
backend_dir = os.path.join(root_dir, "backend")

if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

try:
    from app.main import app
except Exception as e:
    import traceback
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse

    error_trace = traceback.format_exc()
    error_str = str(e)

    app = FastAPI(title="TRACE-X Diagnostic App")

    @app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"])
    def debug_error_handler(full_path: str = ""):
        return JSONResponse(
            status_code=200,
            content={
                "status": "SERVERLESS_IMPORT_ERROR",
                "error": error_str,
                "traceback": error_trace.split("\n"),
                "path": full_path
            }
        )

__all__ = ["app"]
