import sys
import os

# Ensure root of backend is on sys.path for Vercel execution
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.main import app

__all__ = ["app"]
