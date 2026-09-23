import sys
import os

# Root directory of repository on Vercel (/var/task)
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
backend_dir = os.path.join(root_dir, "backend")

# Ensure both backend and root are in sys.path
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from app.main import app

__all__ = ["app"]
