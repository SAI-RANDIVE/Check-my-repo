"""Netlify Functions entrypoint for the CodeSentinel FastAPI application."""

import sys
from pathlib import Path

from mangum import Mangum

# Netlify executes a function from its bundled directory rather than relying
# on the repository root being the current working directory.
project_root = Path(__file__).resolve().parents[2]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from app.main import app

handler = Mangum(app, lifespan="auto")
