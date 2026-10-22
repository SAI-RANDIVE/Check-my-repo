"""``python -m codesentinel`` entry package (the implementation lives in ``app/`` and ``cli.py``)."""

from app.config import APP_VERSION as __version__

__all__ = ["__version__"]
